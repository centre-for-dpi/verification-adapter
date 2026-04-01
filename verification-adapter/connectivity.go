// connectivity.go — Per-backend health probes.
//
// The connectivity checker periodically probes every registered backend's
// health endpoint and tracks per-backend availability. The adapter uses
// this to decide whether to route to a backend (online) or verify locally
// (offline). Unlike the original Node.js adapter, this implementation is
// backend-agnostic — it discovers health endpoints from the registry.
package main

import (
	"log"
	"net/http"
	"sync"
	"time"
)

// ConnectivityChecker probes registered backends and exposes per-backend
// and aggregate online/offline status.
type ConnectivityChecker struct {
	registry  *BackendRegistry
	timeout   time.Duration
	interval  time.Duration
	status    map[string]bool // backend name → reachable
	lastCheck time.Time
	mu        sync.RWMutex
	stop      chan struct{}
}

// NewConnectivityChecker creates a checker. Call Start() to begin probing.
func NewConnectivityChecker(registry *BackendRegistry, timeout, interval time.Duration) *ConnectivityChecker {
	return &ConnectivityChecker{
		registry: registry,
		timeout:  timeout,
		interval: interval,
		status:   make(map[string]bool),
		stop:     make(chan struct{}),
	}
}

// IsOnline returns true if at least one backend that can handle the given
// DID method is reachable.
func (c *ConnectivityChecker) IsOnline(didMethod string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, b := range c.registry.All() {
		if b.CanVerify(didMethod) {
			if c.status[b.Name()] {
				return true
			}
		}
	}
	return false
}

// IsAnyOnline returns true if any registered backend is reachable.
func (c *ConnectivityChecker) IsAnyOnline() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, v := range c.status {
		if v {
			return true
		}
	}
	return false
}

// LastCheck returns the time of the most recent probe cycle.
func (c *ConnectivityChecker) LastCheck() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastCheck
}

// Status returns the per-backend reachability map (for the /health endpoint).
func (c *ConnectivityChecker) Status() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]bool, len(c.status))
	for k, v := range c.status {
		out[k] = v
	}
	return out
}

// Start begins periodic health checks in the background.
func (c *ConnectivityChecker) Start() {
	c.check() // immediate first check
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.check()
		case <-c.stop:
			return
		}
	}
}

// Stop halts periodic checks.
func (c *ConnectivityChecker) Stop() {
	select {
	case c.stop <- struct{}{}:
	default:
	}
}

func (c *ConnectivityChecker) check() {
	client := &http.Client{Timeout: c.timeout}
	backends := c.registry.All()

	newStatus := make(map[string]bool, len(backends))
	for _, b := range backends {
		endpoint := b.HealthEndpoint()
		ok := ping(client, endpoint)
		newStatus[b.Name()] = ok
		if !ok {
			log.Printf("[CONNECTIVITY] %s unreachable (%s)", b.Name(), endpoint)
		}
	}

	c.mu.Lock()
	for name, ok := range newStatus {
		prev, existed := c.status[name]
		if existed && prev != ok {
			if ok {
				log.Printf("[CONNECTIVITY] %s: OFFLINE → ONLINE", name)
			} else {
				log.Printf("[CONNECTIVITY] %s: ONLINE → OFFLINE", name)
			}
		}
	}
	c.status = newStatus
	c.lastCheck = time.Now()
	c.mu.Unlock()
}

func ping(client *http.Client, url string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}
