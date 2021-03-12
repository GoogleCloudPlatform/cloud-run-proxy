// Copyright Seth Vargo
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

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type contextKey string

const contextKeyError = contextKey("error")

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

var (
	flagHost  = flag.String("host", "", "host to proxy to")
	flagBind  = flag.String("bind", "127.0.0.1:8080", "local host:port on which to listen")
	flagToken = flag.String("token", "", "override OIDC token")
)

func main() {
	if err := realMain(); err != nil {
		fmt.Fprint(os.Stderr, err.Error(), "\n")
		os.Exit(1)
	}
}

func realMain() error {
	ctx := context.Background()

	// Parse flags.
	flag.Parse()
	if *flagHost == "" {
		return fmt.Errorf("missing -host")
	}
	if *flagBind == "" {
		return fmt.Errorf("missing -addr")
	}

	// Get the token source. If a static token is supplied, create a static token
	// source. Otherwise attempt to find credentials via ADC.
	var tokenSource oauth2.TokenSource
	if providedToken := *flagToken; providedToken != "" {
		token := &oauth2.Token{}
		token = token.WithExtra(map[string]interface{}{"id_token": providedToken})
		tokenSource = oauth2.StaticTokenSource(token)
	} else {
		// Create token source. Since this proxy is designed to run on a local laptop,
		// this is probably going to come from gcloud.
		var err error
		tokenSource, err = google.DefaultTokenSource(ctx, cloudPlatformScope)
		if err != nil {
			return fmt.Errorf("failed to get default token source: %w", err)
		}
	}

	// Create re-usable token source.
	tokenSource = oauth2.ReuseTokenSource(nil, tokenSource)

	// Parse the URL, handling the case where it's a real URL (https://foo.bar) or
	// just a host (foo.bar). If it's just a host, TLS is assumed.
	u, err := url.Parse(*flagHost)
	if err != nil {
		return fmt.Errorf("failed to parse url: %w", err)
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

	// Build and configure the proxy.
	proxy := httputil.NewSingleHostReverseProxy(u)

	// Configure the director.
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		// Call the original director, which configures most of the URL bits for us.
		originalDirector(r)

		// Override host - this is not done by the default director, but Cloud Run
		// requires it.
		r.Header.Set("Host", u.Host)
		r.Host = u.Host

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

		// Set the bearer token to be the id token
		r.Header.Set("Authorization", "Bearer "+idToken)
	}

	// Configure error handling.
	proxy.ModifyResponse = func(r *http.Response) error {
		// In case of redirection, make sure the local address is still used for host.
		location := r.Header.Get("Location")
		if location != "" {
			locationUrl, err := url.Parse(location)
			// If location is not a valid url, ignore it.
			if err == nil && locationUrl.Host == u.Host {
				// If it has location header && the location url host is the proxied host,
				// change it to local address with http.
				locationUrl.Scheme = "http"
				locationUrl.Host = *flagBind
				r.Header.Set("Location", locationUrl.String())
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

	// Create server.
	server := &http.Server{
		Addr:    *flagBind,
		Handler: proxy,
	}

	// Start server in background.
	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "%s proxies to %s\n", *flagBind, u)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}
	return nil
}
