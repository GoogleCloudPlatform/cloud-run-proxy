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

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func testRandomPort(tb testing.TB) int {
	tb.Helper()

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		tb.Fatalf("failed to resolve tcp addr: %s", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		tb.Fatalf("failed to listen on addr: %s", err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}

func TestBuildProxy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	mux := http.NewServeMux()
	called := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer mytoken"; got != want {
			t.Errorf("invalid authorization header: expected %q to be %q", got, want)
		}
		called = true
	})

	srv := httptest.NewServer(mux)

	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	bind := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", testRandomPort(t)),
	}

	src, err := findTokenSource(ctx, "mytoken", "aud")
	if err != nil {
		t.Fatal(err)
	}

	proxy := buildProxy(srvURL, bind, src, false, nil)

	t.Run("root", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		proxy.ServeHTTP(w, r)
		if !called{
			t.Errorf("handler not called")
		}
	})
}

func TestFindTokenSource(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("static", func(t *testing.T) {
		t.Parallel()

		src, err := findTokenSource(ctx, "mytoken", "aud")
		if err != nil {
			t.Fatal(err)
		}

		token, err := src.Token()
		if err != nil {
			t.Fatal(err)
		}

		if got, want := token.AccessToken, "mytoken"; got != want {
			t.Errorf("expected %q to be %q", got, want)
		}
	})
}

func TestSmartBuildHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		exp  string
		err  bool
	}{
		{
			name: "full_http",
			in:   "http://my.run.app",
			exp:  "http://my.run.app",
			err:  false,
		},
		{
			name: "full_https",
			in:   "https://my.run.app",
			exp:  "https://my.run.app",
			err:  false,
		},
		{
			name: "partial",
			in:   "my.run.app",
			exp:  "https://my.run.app",
			err:  false,
		},
		{
			name: "trailing_slash",
			in:   "my.run.app/",
			exp:  "https://my.run.app",
			err:  false,
		},
		{
			name: "empty",
			in:   "",
			exp:  "",
			err:  true,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u, err := smartBuildHost(tc.in)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if u != nil {
				if got, want := u.String(), tc.exp; got != want {
					t.Errorf("expected %q to be %q", got, want)
				}
			}
		})
	}
}

func TestHttp2(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mux := http.NewServeMux()
	called := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer mytoken"; got != want {
			t.Errorf("invalid authorization header: expected %q to be %q", got, want)
		}
		called = true
	})


	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()

	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	bind := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", testRandomPort(t)),
	}

	src, err := findTokenSource(ctx, "mytoken", "aud")
	if err != nil {
		t.Fatal(err)
	}

	proxy := buildProxy(srvURL, bind, src, true, srv.Certificate())

	t.Run("root", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		proxy.ServeHTTP(w, r)

		if !called{
			t.Errorf("handler not called")
		}
		defer srv.Close()
	})

}
