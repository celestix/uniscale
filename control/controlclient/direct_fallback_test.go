// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

// keyServer is a fake control server that serves /key and counts the
// requests it gets. If down, it drops every connection without a
// response, as a network that blocks the server does.
type keyServer struct {
	*httptest.Server
	keys tailcfg.OverTLSPublicKeyResponse
	hits atomic.Int32
}

func newKeyServer(t *testing.T, status int, down bool) *keyServer {
	t.Helper()
	ks := &keyServer{keys: tailcfg.OverTLSPublicKeyResponse{
		LegacyPublicKey: key.NewMachine().Public(),
		PublicKey:       key.NewMachine().Public(),
	}}
	ks.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks.hits.Add(1)
		if down {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		if r.URL.Path != "/key" {
			http.NotFound(w, r)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "nope", status)
			return
		}
		json.NewEncoder(w).Encode(ks.keys)
	}))
	t.Cleanup(ks.Close)
	return ks
}

func newFallbackTestDirect(t *testing.T, serverURL string) *Direct {
	t.Helper()
	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	k := key.NewMachine()
	c, err := NewDirect(Options{
		ServerURL:            serverURL,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) { return k, nil },
		Dialer:               dialer,
		Bus:                  bus,
		Logf:                 t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestFetchServerPubKeysFallback(t *testing.T) {
	tests := []struct {
		name          string
		primaryStatus int  // HTTP status of the primary's /key
		primaryDown   bool // the primary drops connections
		fallbackDown  bool // the fallback drops connections
		noFallback    bool // no fallback is configured for the primary
		cancel        bool // the context is canceled before the fetch
		wantFallback  bool // the keys and the server URL are the fallback's
		wantErr       string
		wantFbHits    int32
	}{
		{name: "primary reachable", primaryStatus: 200},
		{name: "primary unreachable", primaryDown: true, wantFallback: true, wantFbHits: 1},
		{name: "primary http error", primaryStatus: 500, wantErr: "500"},
		{name: "no fallback for url", primaryDown: true, noFallback: true, wantErr: "fetch control key"},
		{name: "fallback unreachable too", primaryDown: true, fallbackDown: true, wantErr: "fallback", wantFbHits: 1},
		{name: "canceled", primaryDown: true, cancel: true, wantErr: "context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newKeyServer(t, tt.primaryStatus, tt.primaryDown)
			fallback := newKeyServer(t, http.StatusOK, tt.fallbackDown)
			fallbacks := map[string]string{primary.URL: fallback.URL}
			if tt.noFallback {
				fallbacks = nil
			}
			tstest.Replace(t, &controlURLFallbacks, fallbacks)
			c := newFallbackTestDirect(t, primary.URL)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			keys, err := c.fetchServerPubKeys(ctx)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("fetchServerPubKeys error = %v, want one containing %q", err, tt.wantErr)
				}
				if tt.name == "fallback unreachable too" && (!strings.Contains(err.Error(), primary.URL) || !strings.Contains(err.Error(), fallback.URL)) {
					t.Errorf("error %q does not name both %s and %s", err, primary.URL, fallback.URL)
				}
				if tt.wantFbHits == 0 && strings.Contains(err.Error(), "fallback") {
					t.Errorf("error %q mentions the fallback, which must not be tried", err)
				}
			} else if err != nil {
				t.Fatalf("fetchServerPubKeys: %v", err)
			}

			wantURL, wantKeys := primary.URL, primary.keys
			if tt.wantFallback {
				wantURL, wantKeys = fallback.URL, fallback.keys
			}
			if got := c.serverURL.Load(); got != wantURL {
				t.Errorf("server URL = %q, want %q", got, wantURL)
			}
			if err == nil && *keys != wantKeys {
				t.Errorf("keys = %+v, want %+v", *keys, wantKeys)
			}
			if got := fallback.hits.Load(); got != tt.wantFbHits {
				t.Errorf("fallback got %d requests, want %d", got, tt.wantFbHits)
			}
		})
	}
}

// TestFetchServerPubKeysFallbackSticky checks that once the fallback is in
// use, later fetches go to it directly instead of waiting on the primary
// again.
func TestFetchServerPubKeysFallbackSticky(t *testing.T) {
	primary := newKeyServer(t, http.StatusOK, true)
	fallback := newKeyServer(t, http.StatusOK, false)
	tstest.Replace(t, &controlURLFallbacks, map[string]string{primary.URL: fallback.URL})
	c := newFallbackTestDirect(t, primary.URL)

	for range 2 {
		if _, err := c.fetchServerPubKeys(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := primary.hits.Load(); got != 1 {
		t.Errorf("primary got %d requests, want 1", got)
	}
	if got := fallback.hits.Load(); got != 2 {
		t.Errorf("fallback got %d requests, want 2", got)
	}
}

// TestTryLoginUsesControlFallback checks that login fetches the server keys
// through the fallback when the primary is unreachable, so the rest of the
// session (Noise, register, map) uses the fallback's URL and keys.
func TestTryLoginUsesControlFallback(t *testing.T) {
	primary := newKeyServer(t, http.StatusOK, true)
	fallback := newKeyServer(t, http.StatusOK, false)
	tstest.Replace(t, &controlURLFallbacks, map[string]string{primary.URL: fallback.URL})
	c := newFallbackTestDirect(t, primary.URL)

	// The fake fallback serves no Noise, so login fails after the key fetch.
	if _, err := c.TryLogin(context.Background(), 0); err == nil {
		t.Fatal("TryLogin succeeded against a fake control server")
	}
	if got := c.serverURL.Load(); got != fallback.URL {
		t.Errorf("server URL = %q, want the fallback %q", got, fallback.URL)
	}
	c.mu.Lock()
	noiseKey := c.serverNoiseKey
	c.mu.Unlock()
	if noiseKey != fallback.keys.PublicKey {
		t.Errorf("server Noise key = %v, want the fallback's %v", noiseKey, fallback.keys.PublicKey)
	}
}

func TestDefaultControlURLFallback(t *testing.T) {
	if got, want := controlURLFallbacks["https://controlplane.tailscale.com"], "https://login.tailscale.com"; got != want {
		t.Errorf("fallback for the default control URL = %q, want %q", got, want)
	}
	if len(controlURLFallbacks) != 1 {
		t.Errorf("controlURLFallbacks = %v, want only the default control URL", controlURLFallbacks)
	}
}

// TestFetchServerPubKeysFallbackOnCertError checks that a primary whose TLS
// certificate the client rejects, as on a network that intercepts it, is
// treated as unreachable.
func TestFetchServerPubKeysFallbackOnCertError(t *testing.T) {
	primary := httptest.NewTLSServer(http.NotFoundHandler()) // untrusted certificate
	t.Cleanup(primary.Close)
	fallback := newKeyServer(t, http.StatusOK, false)
	tstest.Replace(t, &controlURLFallbacks, map[string]string{primary.URL: fallback.URL})
	c := newFallbackTestDirect(t, primary.URL)

	keys, err := c.fetchServerPubKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *keys != fallback.keys {
		t.Errorf("keys = %+v, want the fallback's %+v", *keys, fallback.keys)
	}
	if got := c.serverURL.Load(); got != fallback.URL {
		t.Errorf("server URL = %q, want the fallback %q", got, fallback.URL)
	}
}

// TestFetchServerPubKeysNoFallbackOnBadBody checks that a primary that
// answers, but with keys the client cannot parse, is not treated as
// unreachable.
func TestFetchServerPubKeysNoFallbackOnBadBody(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not keys"))
	}))
	t.Cleanup(primary.Close)
	fallback := newKeyServer(t, http.StatusOK, false)
	tstest.Replace(t, &controlURLFallbacks, map[string]string{primary.URL: fallback.URL})
	c := newFallbackTestDirect(t, primary.URL)

	if _, err := c.fetchServerPubKeys(context.Background()); err == nil {
		t.Fatal("fetchServerPubKeys succeeded with a bad key body")
	}
	if got := fallback.hits.Load(); got != 0 {
		t.Errorf("fallback got %d requests, want 0", got)
	}
	if got := c.serverURL.Load(); got != primary.URL {
		t.Errorf("server URL = %q, want the primary %q", got, primary.URL)
	}
}
