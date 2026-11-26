// Package pipeline — netscan.go: the network discovery module (README §8).
// Iterates the CIDR ranges from scope.ips, probes common TCP ports on each
// host through the policy engine's DialTCP, and records live hosts, open
// ports, and service banners as first-class assets. Hosts are probed
// concurrently — the engine's rate limiter civilizes the global pace while
// TCP timeouts run in parallel.
package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agenticrecon/internal/policy"
	"agenticrecon/internal/store"
)

// discoveryPorts are the ports probed to determine if a host is alive.
var discoveryPorts = []int{22, 80, 443, 445, 3389}

// netScanTimeout is the TCP connect timeout for LAN discovery — short
// because unreachable hosts are common and 1s is plenty on a local network.
const netScanTimeout = 1 * time.Second

// hostResult carries what one host probe found.
type hostResult struct {
	host      string
	live      bool
	openPorts []int
	banners   map[int]string
}

// Netscan discovers live hosts on the CIDR ranges in scope.ips.
// Every probe flows through the policy engine (scope → pace → dial → log).
// Hosts are probed concurrently: the rate limiter controls the request rate
// while TCP timeouts happen in parallel. Live hosts become ip assets; open
// ports are recorded as observations with service names and banners.
func Netscan(ctx context.Context, scope *policy.Scope, eng *policy.Engine, st *store.Store, campaignID int64) error {
	hosts := scope.CIDRHosts(256)
	if len(hosts) == 0 {
		return fmt.Errorf("netscan: no CIDR ranges in scope.ips — add e.g. ips: [10.50.77.0/24]")
	}

	// Probe all hosts concurrently; the engine's rate limiter paces the
	// actual requests while TCP timeouts run in parallel.
	results := make(chan hostResult, len(hosts))
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			res := hostResult{host: h, banners: make(map[int]string)}
			for _, port := range discoveryPorts {
				r, _, err := eng.DialTCP(ctx, &policy.TCPRequest{
					Actor:   "module:netscan",
					Tool:    "netscan",
					Reason:  fmt.Sprintf("host discovery on %s:%d", h, port),
					Risk:    policy.RiskLowImpact,
					Host:    h,
					Port:    port,
					Timeout: netScanTimeout,
				})
				if err != nil {
					continue // individual probe failures don't abort the scan
				}
				if r != nil && r.Open {
					res.live = true
					res.openPorts = append(res.openPorts, port)
					if r.Banner != "" {
						res.banners[port] = r.Banner
					}
				}
			}
			results <- res
		}(host)
	}

	go func() { wg.Wait(); close(results) }()

	// Collect results and store live hosts.
	liveCount := 0
	for r := range results {
		if !r.live {
			continue
		}
		liveCount++

		attrs := map[string]any{
			"live":       true,
			"open_ports": r.openPorts,
		}
		ip, err := st.UpsertAsset(ctx, campaignID, store.KindIP, r.host, "netscan", false, attrs)
		if err != nil {
			return err
		}

		for _, port := range r.openPorts {
			serviceName := policy.PortName(port)
			if serviceName == "" {
				serviceName = fmt.Sprintf("port-%d", port)
			}
			obsAttrs := map[string]any{
				"port":    port,
				"proto":   "tcp",
				"service": serviceName,
			}
			if banner, ok := r.banners[port]; ok {
				obsAttrs["banner"] = banner
			}
			if _, err := st.AddObservation(ctx, campaignID, ip.ID, "netscan", obsAttrs); err != nil {
				return err
			}

			// Web-capable ports create web_service assets for the HTTP pipeline.
			if isWebPort(port) {
				wsAttrs := map[string]any{"port": port, "service": serviceName}
				if banner, ok := r.banners[port]; ok {
					wsAttrs["banner"] = banner
				}
				ws, err := st.UpsertAsset(ctx, campaignID, store.KindWebService, r.host, "netscan", false, wsAttrs)
				if err != nil {
					return err
				}
				if err := st.LinkAssets(ctx, ip.ID, ws.ID, "hosts"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func isWebPort(port int) bool {
	switch port {
	case 80, 443, 8080, 8443:
		return true
	}
	return false
}
