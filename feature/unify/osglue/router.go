// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osglue

import (
	"errors"
	"sync"

	"tailscale.com/wgengine/router"
)

var errRouterClosed = errors.New("osglue: router closed")

// Router is a router.Router for one stack. It records the last
// configuration the stack's engine sets instead of changing the OS. It is
// safe for concurrent use.
type Router struct {
	notify func()

	mu     sync.Mutex
	cfg    *router.Config // nil before the first Set, after Set(nil) and after Close
	closed bool
}

var _ router.Router = (*Router)(nil)

// NewRouter returns a Router. If notify is not nil, it is called after
// every recorded change. The engine sets its router with the stack's
// LocalBackend lock held, so notify must not block or call into the
// stack.
func NewRouter(notify func()) *Router {
	return &Router{notify: notify}
}

// Up implements router.Router. It does nothing.
func (r *Router) Up() error { return nil }

// Set implements router.Router. It records a copy of cfg; nil means no
// configuration. It fails after Close.
func (r *Router) Set(cfg *router.Config) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errRouterClosed
	}
	r.cfg = cfg.Clone()
	r.mu.Unlock()
	r.changed()
	return nil
}

// Close implements router.Router. It forgets the configuration.
func (r *Router) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.cfg = nil
	r.mu.Unlock()
	r.changed()
	return nil
}

// Config returns a copy of the last configuration set, or nil if there is
// none.
func (r *Router) Config() *router.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.Clone()
}

func (r *Router) changed() {
	if r.notify != nil {
		r.notify()
	}
}
