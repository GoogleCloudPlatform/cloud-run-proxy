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
	"syscall"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

type contextKey string

const contextKeyError = contextKey("error")

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

const Version = "0.1.0"
const OSArch = runtime.GOOS + "/" + runtime.GOARCH
const UserAgent = "cloud-run-proxy/" + Version + " (" + OSArch + ")"

const ADCHintMessage = "If you're trying to authenticate using gcloud, try running `gcloud auth login --update-adc` first then restart the proxy."

var (
	flagHost             = flag.String("host", "", "Cloud Run host for which to proxy")
	flagBind             = flag.String("bind", "127.0.0.1:8080", "local host:port on which to listen")
	flagAudience         = flag.String("audience", "", "override JWT audience value (aud)")
	flagToken            = flag.String("token", "", "override OIDC token")
	flagPrependUserAgent = flag.Bool("prepend-user-agent", true, "prepend a custom User-Agent header to requests")
	flagServerUpTime     = flag.String("server-up-time", "", "Time duration the proxy server will run. For example, 1h, 1m30s. Empty means forever")
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := realMain(ctx); err != nil {
		cancel()

		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func realMain(ctx context.Context) error {
	// Parse flags.
	flag.Parse()
	if *flagHost == "" {
		return errors.New("missing -host")
	}
	if *flagBind == "" {
		return errors.New("missing -bind")
	}
	var d time.Duration
	if *flagServerUpTime != "" {
		var err error
		d, err = time.ParseDuration(*flagServerUpTime)
		if err != nil {
			return fmt.Errorf("error parsing -server-up-time: %w", err)
		}
	}

	// Build the remote host URL.
	host, err := smartBuildHost(*flagHost)
	if err != nil {
		return fmt.Errorf("failed to parse host URL: %w", err)
	}

	// Compute the audience, default to the host. However, there might be cases
	// where you want to specify a custom aud (such as when accessing through a
	// load balancer).
	audience := *flagAudience
	if audience == "" {
		audience = host.String()
	}

	// Get the best token source. Cloud Run expects the audience parameter to be
	// the URL of the service.
	tokenSource, err := findTokenSource(ctx, *flagToken, audience)
	if err != nil {
		return fmt.Errorf("failed to find token source: %w", err)
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

	// Wait for stop
	if *flagServerUpTime != "" {
		select {
		case err := <-errCh:
			return fmt.Errorf("server error: %w", err)
		case <-time.After(d):
		case <-ctx.Done():
			fmt.Fprint(os.Stderr, "\nserver is shutting down...\n")
		}
	} else {
		select {
		case err := <-errCh:
			return fmt.Errorf("server error: %w", err)
		case <-ctx.Done():
			fmt.Fprint(os.Stderr, "\nserver is shutting down...\n")
		}
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
				fmt.Errorf("failed to get token: %w\n\n%s", err, ADCHintMessage)))
			return
		}

		// Get the id_token.
		idToken := token.AccessToken
		if idToken == "" {
			*r = *r.WithContext(context.WithValue(ctx, contextKeyError,
				errors.New("missing id_token")))
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

// findTokenSource fetches the reusable/cached oauth2 token source. If rawToken
// is provided, that token is used as a static value and the audience parameter
// is ignored. Othwerise, this attempts to get the renewable token from the
// environment (via Application Default Credentials).
func findTokenSource(ctx context.Context, rawToken, audience string) (oauth2.TokenSource, error) {
	// Prefer supplied value, usually from the flag.
	if rawToken != "" {
		token := &oauth2.Token{AccessToken: rawToken}
		return oauth2.StaticTokenSource(token), nil
	}

	// Try to use the idtoken package, which will use the metadata service.
	// However, the idtoken package does not work with gcloud's ADC, so we need to
	// handle that case by falling back to default ADC search. However, the
	// default ADC has a token at a different path, so we construct a custom token
	// source for this edge case.
	tokenSource, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		// Return any unexpected error.
		if !strings.Contains(err.Error(), "credential must be service_account") {
			return nil, fmt.Errorf("failed to get idtoken source: %w", err)
		}

		// If we got this far, it means that we found ADC, but the ADC was supplied
		// by a gcloud "authorized_user" instead of a service account. Thus we
		// fallback to the default ADC search.
		tokenSource, err = google.DefaultTokenSource(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get default token source: %w", err)
		}
		tokenSource = &idTokenFromDefaultTokenSource{TokenSource: tokenSource}
	}
	return oauth2.ReuseTokenSource(nil, tokenSource), nil
}

type idTokenFromDefaultTokenSource struct {
	TokenSource oauth2.TokenSource
}

// Token extracts the id_token field from ADC from a default token source and
// puts the value into the AccessToken field.
func (s *idTokenFromDefaultTokenSource) Token() (*oauth2.Token, error) {
	token, err := s.TokenSource.Token()
	if err != nil {
		return nil, err
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("missing id_token")
	}

	return &oauth2.Token{
		AccessToken: idToken,
		Expiry:      token.Expiry,
	}, nil
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
