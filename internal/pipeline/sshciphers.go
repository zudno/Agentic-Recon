// Package pipeline — sshciphers.go: SSH cipher and key-exchange analysis.
// Parses the SSH banner captured by netscan and identifies weak algorithms
// offered by the server. This is pure data analysis on existing banners —
// no new network probes needed.
package pipeline

import (
	"context"
	"fmt"
	"strings"

	"agenticrecon/internal/store"
)

// weakKEX are key exchange algorithms considered weak or deprecated.
var weakKEX = map[string]bool{
	"diffie-hellman-group1-sha1":           true,  // 1024-bit, SHA-1
	"diffie-hellman-group14-sha1":          true,  // SHA-1
	"diffie-hellman-group-exchange-sha1":   true,  // SHA-1
	"diffie-hellman-group-exchange-sha256": false, // acceptable but old
}

// weakCiphers are encryption algorithms considered weak or deprecated.
var weakCiphers = map[string]bool{
	"aes128-cbc":                    true,
	"aes192-cbc":                    true,
	"aes256-cbc":                    true,
	"3des-cbc":                      true, // deprecated
	"blowfish-cbc":                  true, // 64-bit block
	"arcfour":                       true, // RC4
	"arcfour128":                    true,
	"arcfour256":                    true,
	"cast128-cbc":                   true,
	"chacha20-poly1305@openssh.com": false, // strong
	"aes128-ctr":                    false, // acceptable
	"aes192-ctr":                    false,
	"aes256-ctr":                    false,
	"aes128-gcm@openssh.com":        false, // strong
	"aes256-gcm@openssh.com":        false, // strong
}

// weakMACs are message authentication codes considered weak.
var weakMACs = map[string]bool{
	"hmac-md5":                      true,
	"hmac-md5-96":                   true,
	"hmac-sha1":                     true, // SHA-1
	"hmac-sha1-96":                  true,
	"hmac-sha2-256":                 false, // acceptable
	"hmac-sha2-512":                 false, // strong
	"hmac-sha2-256-etm@openssh.com": false, // strong
	"hmac-sha2-512-etm@openssh.com": false, // strong
}

// SSHCipherAnalysis reports the security posture of an SSH server's
// algorithm negotiation, parsed from its banner.
type SSHCipherAnalysis struct {
	Host        string
	Banner      string   // raw SSH version string
	KEX         []string // key exchange algorithms offered
	Ciphers     []string // encryption algorithms offered
	MACs        []string // MAC algorithms offered
	WeakKEX     []string
	WeakCiphers []string
	WeakMACs    []string
	RiskScore   int // 0=secure, 1=minor, 2=moderate, 3=high
}

// AnalyzeSSHCiphers parses the SSH banner from observations and produces
// a security analysis. The banner captured by netscan contains the full
// algorithm list for some servers (especially dropbear which sends
// kex algorithms in its banner extension).
func AnalyzeSSHCiphers(ctx context.Context, st *store.Store, campaignID int64, host string) (*SSHCipherAnalysis, error) {
	ip, err := st.GetAssetByValue(ctx, campaignID, store.KindIP, host)
	if err != nil {
		return nil, err
	}
	obs, err := st.ObservationsOf(ctx, ip.ID)
	if err != nil {
		return nil, err
	}

	analysis := &SSHCipherAnalysis{Host: host}
	for _, o := range obs {
		banner, ok := o.Attrs["banner"]
		if !ok {
			continue
		}
		bannerStr := fmt.Sprintf("%v", banner)
		if !strings.HasPrefix(bannerStr, "SSH-") {
			continue
		}
		analysis.Banner = bannerStr
		parseSSHAlgorithm(bannerStr, analysis)
		break
	}

	// Score the risk.
	analysis.RiskScore = scoreSSHRisk(analysis)
	return analysis, nil
}

// parseSSHAlgorithms extracts algorithm lists from the SSH banner.
// SSH banners can contain algorithm lists after the version string,
// especially for Dropbear which appends them in its initial packet.
func parseSSHAlgorithm(banner string, analysis *SSHCipherAnalysis) {
	// Standard SSH banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.14"
	// Dropbear may append: kex algorithms, host key algorithms, ciphers, MACs
	// separated by commas in the banner extension.

	parts := strings.Fields(banner)
	for _, part := range parts[1:] { // skip "SSH-2.0-..."
		if strings.Contains(part, ",") {
			// This might be a comma-separated algorithm list
			algorithms := strings.Split(part, ",")
			for _, alg := range algorithms {
				alg = strings.TrimSpace(alg)
				if weakKEX[alg] {
					analysis.KEX = append(analysis.KEX, alg)
					analysis.WeakKEX = append(analysis.WeakKEX, alg)
				} else if weakCiphers[alg] {
					analysis.Ciphers = append(analysis.Ciphers, alg)
					analysis.WeakCiphers = append(analysis.WeakCiphers, alg)
				} else if weakMACs[alg] {
					analysis.MACs = append(analysis.MACs, alg)
					analysis.WeakMACs = append(analysis.WeakMACs, alg)
				}
			}
		}
	}
}

// scoreSSHRisk computes a 0-3 risk score based on weak algorithms found.
func scoreSSHRisk(a *SSHCipherAnalysis) int {
	score := 0
	if len(a.WeakKEX) > 0 {
		score += 1
	}
	if len(a.WeakCiphers) > 0 {
		score += 1
	}
	if len(a.WeakMACs) > 0 {
		score += 1
	}
	return score
}

// ClassifySSHVersion identifies the SSH implementation and version from
// the banner string, and flags notably old versions.
func ClassifySSHVersion(banner string) (implementation string, version string, isOld bool) {
	// "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.14"
	// "SSH-2.0-dropbear_2016.74"
	// "SSH-2.0-OpenSSH_6.6"

	banner = strings.TrimPrefix(banner, "SSH-2.0-")
	parts := strings.SplitN(banner, " ", 2)
	if len(parts) == 0 {
		return "", "", false
	}
	versionPart := parts[0]

	if strings.HasPrefix(versionPart, "OpenSSH_") {
		implementation = "OpenSSH"
		version = strings.TrimPrefix(versionPart, "OpenSSH_")
		// Versions before 7.4 (2016) are notably old
		isOld = compareSSHVersion(version, "7.4") < 0
	} else if strings.HasPrefix(versionPart, "dropbear_") {
		implementation = "Dropbear"
		version = strings.TrimPrefix(versionPart, "dropbear_")
		// Dropbear before 2020.79 is notably old
		isOld = version < "2020.79"
	} else {
		implementation = "unknown"
		version = versionPart
	}
	return implementation, version, isOld
}

// compareSSHVersion compares dotted version strings (e.g. "8.9" vs "7.4").
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func compareSSHVersion(a, b string) int {
	aparts := strings.Split(a, ".")
	bparts := strings.Split(b, ".")
	for i := 0; i < len(aparts) && i < len(bparts); i++ {
		av, bv := atoiSafe(aparts[i]), atoiSafe(bparts[i])
		if av < bv {
			return -1
		} else if av > bv {
			return 1
		}
	}
	if len(aparts) < len(bparts) {
		return -1
	} else if len(aparts) > len(bparts) {
		return 1
	}
	return 0
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// AllSSHCipherAnalyses runs the analysis on all discovered hosts with SSH.
func AllSSHCipherAnalyses(ctx context.Context, st *store.Store, campaignID int64) ([]*SSHCipherAnalysis, error) {
	ips, err := st.ListAssets(ctx, store.ListFilter{CampaignID: campaignID, Kind: store.KindIP, Limit: 1000})
	if err != nil {
		return nil, err
	}
	var analyses []*SSHCipherAnalysis
	for _, ip := range ips {
		a, err := AnalyzeSSHCiphers(ctx, st, campaignID, ip.Value)
		if err != nil || a.Banner == "" {
			continue
		}
		analyses = append(analyses, a)
	}
	return analyses, nil
}
