package policy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCIDRHostsIteratesRange(t *testing.T) {
	doc := `
authorization:
  reference: "ROE-TEST-001"
  window: {start: "2000-01-01T00:00:00Z", end: "2999-01-01T00:00:00Z"}
scope:
  domains: [example.com]
  ips: [10.50.77.0/24]
  sources: [crt.sh]
policy:
  risk_levels: [PASSIVE, LOW_IMPACT]
budgets:
  agent_max_steps_per_hypothesis: 8
  campaign_max_tokens: 1000000
`
	s := mustParse(t, doc)
	hosts := s.CIDRHosts(300)
	// A /24 has 254 usable hosts (excluding .0 and .255)
	if len(hosts) != 254 {
		t.Fatalf("hosts = %d, want 254", len(hosts))
	}
	if hosts[0] != "10.50.77.1" || hosts[len(hosts)-1] != "10.50.77.254" {
		t.Fatalf("range = %s…%s", hosts[0], hosts[len(hosts)-1])
	}
}

func TestCIDRHostsRespectsMax(t *testing.T) {
	doc := strings.Replace(defaultScopeYAML, "ips: [203.0.113.0/24]", "ips: [10.50.77.0/24]", 1)
	s := mustParse(t, doc)
	hosts := s.CIDRHosts(10)
	if len(hosts) != 10 {
		t.Fatalf("hosts = %d, want 10 (capped)", len(hosts))
	}
}

func TestDialTCPAgainstRealListener(t *testing.T) {
	// Start a real TCP listener on loopback — the engine's DialTCP
	// connects to it, proving the full path works (scope→pace→dial→log).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Send a banner like SSH would.
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
			_ = conn.Close()
		}
	}()

	doc := strings.Replace(defaultScopeYAML,
		"ips: [203.0.113.0/24]", "ips: [127.0.0.1]", 1)
	sink := &MemSink{}
	eng, err := NewEngine(EngineConfig{
		Scope:    mustParse(t, doc),
		Sink:     sink,
		Now:      func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}

	port := ln.Addr().(*net.TCPAddr).Port
	result, v, err := eng.DialTCP(context.Background(), &TCPRequest{
		Actor: "module:netscan", Tool: "netscan",
		Reason: "unit test probe",
		Risk:   RiskLowImpact,
		Host:   "127.0.0.1",
		Port:   port,
	})
	if err != nil || !v.Allowed {
		t.Fatalf("verdict = %+v err = %v", v, err)
	}
	if result == nil || !result.Open {
		t.Fatalf("result = %+v (expected open)", result)
	}
	if !strings.Contains(result.Banner, "SSH-2.0-OpenSSH_9.0") {
		t.Fatalf("banner = %q", result.Banner)
	}

	// Evidence logged.
	if sink.Len() != 1 {
		t.Fatalf("entries = %d, want 1", sink.Len())
	}
	e := sink.Entries[0]
	if !e.Allowed || !strings.Contains(e.Result, "open") || !strings.Contains(e.Target, "tcp://") {
		t.Fatalf("entry = %+v", e)
	}
}

func TestDialTCPDeniedOutOfScope(t *testing.T) {
	sink := &MemSink{}
	eng, err := NewEngine(EngineConfig{
		Scope:    mustParse(t, defaultScopeYAML),
		Sink:     sink,
		Now:      func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}

	_, v, err := eng.DialTCP(context.Background(), &TCPRequest{
		Actor: "module:netscan", Tool: "netscan",
		Risk: RiskLowImpact,
		Host: "192.168.1.1", // not in scope
		Port: 22,
	})
	if err == nil || v.Allowed {
		t.Fatalf("verdict = %+v err = %v", v, err)
	}
	if len(strings.Split(v.Reason, " ")) == 0 {
		t.Fatalf("reason = %q", v.Reason)
	}
	// Denied attempts are logged too.
	if sink.Len() != 1 || sink.Entries[0].Allowed {
		t.Fatalf("entry = %+v", sink.Entries[0])
	}
}

func TestDialTCPClosedPortIsNotError(t *testing.T) {
	sink := &MemSink{}
	doc := strings.Replace(defaultScopeYAML, "ips: [203.0.113.0/24]", "ips: [127.0.0.1]", 1)
	eng, err := NewEngine(EngineConfig{
		Scope:    mustParse(t, doc),
		Sink:     sink,
		Now:      func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		JitterFn: func() time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Probe a port with no listener — should return open=false, not an error.
	result, v, err := eng.DialTCP(context.Background(), &TCPRequest{
		Actor: "module:netscan", Tool: "netscan",
		Risk: RiskLowImpact,
		Host: "127.0.0.1",
		Port: 59999, // nothing listens here
	})
	if err != nil || !v.Allowed {
		t.Fatalf("verdict = %+v err = %v", v, err)
	}
	if result == nil || result.Open {
		t.Fatalf("result = %+v (expected closed)", result)
	}
	if sink.Entries[0].Result != "closed" {
		t.Fatalf("result = %q", sink.Entries[0].Result)
	}
}

func TestPortName(t *testing.T) {
	if PortName(22) != "ssh" || PortName(443) != "https" || PortName(3389) != "rdp" {
		t.Fatal("port names must map correctly")
	}
	if PortName(12345) != "" {
		t.Fatal("unknown port must return empty")
	}
}
