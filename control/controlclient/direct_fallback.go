// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"tailscale.com/tailcfg"
)

// controlURLFallbacks maps a control server URL to another URL of the same
// control server, which a client uses when the first is unreachable.
//
// Some networks block https://controlplane.tailscale.com (by the name in
// its TLS handshake, for instance) but not https://login.tailscale.com,
// which serves the same control plane under a certificate of the same
// domain, so falling back to it trusts no one new.
var controlURLFallbacks = map[string]string{
	"https://controlplane.tailscale.com": "https://login.tailscale.com",
}

// fetchServerPubKeys fetches the control server's public keys from c's
// server URL. If that fails because the server cannot be reached, and the
// URL has a fallback in [controlURLFallbacks], it fetches them from the
// fallback instead, and c uses the fallback's URL from then on: for the
// Noise connection, registration and map requests. A server that answers
// with an error, or a canceled ctx, leaves the URL alone.
//
// A TLS certificate the client rejects also counts as unreachable. That is
// deliberate and trusts no one new: the fallback's certificate is verified
// the same way, and the Noise handshake pins the server key fetched from it.
func (c *Direct) fetchServerPubKeys(ctx context.Context) (*tailcfg.OverTLSPublicKeyResponse, error) {
	serverURL := c.serverURL.Load()
	keys, err := loadServerPubKeys(ctx, c.httpc, serverURL)
	if err == nil {
		return keys, nil
	}
	fallback, ok := controlURLFallbacks[serverURL]
	var uerr *url.Error
	if !ok || ctx.Err() != nil || !errors.As(err, &uerr) {
		return nil, err
	}
	keys, ferr := loadServerPubKeys(ctx, c.httpc, fallback)
	if ferr != nil {
		return nil, fmt.Errorf("%w; fallback %s: %w", err, fallback, ferr)
	}
	c.logf("control server %s unreachable (%v); using %s", serverURL, err, fallback)
	c.serverURL.Store(fallback)
	return keys, nil
}
