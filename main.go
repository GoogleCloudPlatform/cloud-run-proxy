// Copyright 2021 the Cloud Run Proxy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main is the entrypoint for cloud-run-proxy. It starts the proxy
// server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type contextKey string

const contextKeyError = contextKey("error")

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

const Version = "0.1.0"
const OSArch = runtime.GOOS + "/" + runtime.GOARCH
const UserAgent = "cloud-run-proxy/" + Version + " (" + OSArch + ")"

var (
	flagHost             = flag.String("host", "", "Cloud Run host for which to proxy")
	flagBind             = flag.String("bind", "127.0.0.1:8080", "local host:port on which to listen")
	flagToken            = flag.String("token", "", "override OIDC token")
	flagPrependUserAgent = flag.Bool("prepend-user-agent", true, "prepend a custom User-Agent header to requests")
)

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func realMain() error {
	// Parse flags.
	flag.Parse()
	if *flagHost == "" {
		return fmt.Errorf("missing -host")
	}
	if *flagBind == "" {
		return fmt.Errorf("missing -bind")
	}

	// Get the best token source.
	tokenSource, err := findTokenSource(*flagToken)
	if err != nil {
		return fmt.Errorf("failed to find token source: %w", err)
	}

	// Build the remote host URL.
	host, err := smartBuildHost(*flagHost)
	if err != nil {
		return fmt.Errorf("failed to parse host URL: %w", err)
	}

	// Build the local bind URL.
	bindHost, bindPort, err := net.SplitHostPort(*flagBind)
	if err != nil {
		return fmt.Errorf("failed to parse bind address: %w", err)
	}
	bind := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(bindHost, bindPort),
	}

	// Construct the proxy.
	proxy := buildProxy(host, bind, tokenSource)

	// Create server.
	server := &http.Server{
		Addr:    bind.Host,
		Handler: proxy,
	}

	// Start server in background.
	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "%s proxies to %s\n", bind, host)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	// Signal on stop.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Wait for error or signal.
	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-stop:
		fmt.Fprint(os.Stderr, "\nserver is shutting down...\n")
	}

	// Attempt graceful shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}
	return nil
}

// buildProxy builds the reverse proxy server, forwarding requests on bind to
// the provided host.
func buildProxy(host, bind *url.URL, tokenSource oauth2.TokenSource) *httputil.ReverseProxy {
	// Build and configure the proxy.
	proxy := httputil.NewSingleHostReverseProxy(host)

	// Configure the director.
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		// Call the original director, which configures most of the URL bits for us.
		originalDirector(r)

		// Override host - this is not done by the default director, but Cloud Run
		// requires it.
		r.Header.Set("Host", host.Host)
		r.Host = host.Host

		ctx := r.Context()

		// Get the oauth token.
		token, err := tokenSource.Token()
		if err != nil {
			*r = *r.WithContext(context.WithValue(ctx, contextKeyError,
				fmt.Errorf("failed to get token: %w", err)))
			return
		}

		// Get the id_token from the oauth token.
		idTokenRaw := token.Extra("id_token")
		if idTokenRaw == nil {
			*r = *r.WithContext(context.WithValue(ctx, contextKeyError,
				fmt.Errorf("missing id_token")))
			return
		}
		idToken, ok := idTokenRaw.(string)
		if !ok {
			*r = *r.WithContext(context.WithValue(ctx, contextKeyError,
				fmt.Errorf("id_token is not a string: %T", idTokenRaw)))
			return
		}

		// Set a custom user-agent header.
		if *flagPrependUserAgent {
			ua := r.Header.Get("User-Agent")
			if ua == "" {
				ua = UserAgent
			} else {
				ua = UserAgent + " " + ua
			}

			r.Header.Set("User-Agent", ua)
		}

		// Set the bearer token to be the id token
		r.Header.Set("Authorization", "Bearer "+idToken)
	}

	// Configure error handling.
	proxy.ModifyResponse = func(r *http.Response) error {
		// In case of redirection, make sure the local address is still used for
		// host. If it has location header && the location url host is the proxied
		// host, change it to local address with http.
		location := r.Header.Get("Location")
		if location != "" {
			locationURL, err := url.Parse(location)
			if err == nil && locationURL.Host == host.Host {
				locationURL.Scheme = bind.Scheme
				locationURL.Host = bind.Host
				r.Header.Set("Location", locationURL.String())
			}
		}

		ctx := r.Request.Context()
		if err, ok := ctx.Value(contextKeyError).(error); ok && err != nil {
			return fmt.Errorf("[PROXY ERROR] %w", err)
		}

		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return proxy
}

// findTokenSource fetches the reusable/cached oauth2 token source. If t is
// provided, that token is used as a static value. Othwerise, this attempts to
// get the renewable token from the environment (including via Application
// Default Credentials).
func findTokenSource(t string) (oauth2.TokenSource, error) {
	// Prefer supplied value, usually from the flag.
	if t != "" {
		token := new(oauth2.Token).WithExtra(map[string]interface{}{
			"id_token": t,
		})
		return oauth2.StaticTokenSource(token), nil
	}

	// Try and find the default token from ADC.
	ctx := context.Background()
	tokenSource, err := google.DefaultTokenSource(ctx, cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get default token source: %w", err)
	}
	return oauth2.ReuseTokenSource(nil, tokenSource), nil
}

// smartBuildHost parses the URL, handling the case where it's a real URL
// (https://foo.bar) or just a host (foo.bar). If it's just a host, the URL is
// assumed to be TLS.
func smartBuildHost(host string) (*url.URL, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	if u.Scheme == "" {
		u.Scheme = "https"

		parts := strings.SplitN(u.Path, "/", 2)
		switch len(parts) {
		case 0:
			u.Host = ""
			u.Path = ""
		case 1:
			u.Host = parts[0]
			u.Path = ""
		case 2:
			u.Host = parts[0]
			u.Path = parts[1]
		}
	}

	u.Host = strings.TrimSpace(u.Host)
	if u.Host == "" {
		return nil, fmt.Errorf("invalid url %q (missing host)", host)
	}

	u.Path = strings.TrimSpace(u.Path)
	if u.Path == "/" {
		u.RawPath = ""
		u.Path = ""
	}

	return u, nil
}
