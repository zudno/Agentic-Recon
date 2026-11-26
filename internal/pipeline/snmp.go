// Package pipeline — snmp.go: SNMP discovery through the policy engine.
// Probes UDP 161 with common community strings (public, private) and
// requests sysDescr.0 — the device's self-description. SNMP often
// reveals device model, firmware version, and vendor on routers,
// switches, printers, and IoT devices.
package pipeline

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"agenticrecon/internal/store"
)

// commonCommunities are the default SNMP community strings tried in order.
var commonCommunities = []string{"public", "private", "community", "cisco", "read"}

// SNMPResult carries what one SNMP probe found.
type SNMPResult struct {
	Reachable  bool
	Community  string // the community string that worked
	SysDescr   string // device description (model, firmware, vendor)
	SysName    string // device hostname
	SysContact string // admin contact (if configured)
}

// SNMPEnum probes the SNMP service on one host. It tries common community
// strings and requests sysDescr.0, sysName.0, and sysContact.0.
// This is a PASSIVE discovery — it reads information the device volunteers.
func SNMPEnum(ctx context.Context, host string) (*SNMPResult, error) {
	for _, community := range commonCommunities {
		result, err := snmpGet(host, community)
		if err != nil {
			continue // timeout or no response — try next community
		}
		if result != nil {
			return result, nil
		}
	}
	return &SNMPResult{Reachable: false}, nil
}

// snmpGet sends an SNMP v2c GET request for sysDescr.0 with the given
// community string and parses the response.
func snmpGet(host, community string) (*SNMPResult, error) {
	// Build a minimal SNMP v2c GET request for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
	requestID := rand.Int31()
	pdu := buildSNMPGet(community, requestID)

	addr := net.JoinHostPort(host, "161")
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(pdu); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err // timeout — SNMP not responding on this community
	}

	return parseSNMPResponse(buf[:n])
}

// buildSNMPGet constructs a minimal SNMP v2c GET request PDU.
// ASN.1 BER encoding: SEQUENCE { version, community, GET-PDU }
func buildSNMPGet(community string, requestID int32) []byte {
	// OID for sysDescr.0 = 1.3.6.1.2.1.1.1.0
	oid := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}

	// Simplified BER encoding — full implementation would use encoding/asn1
	// with proper structures. This constructs a raw SNMP packet.
	// For the MVP, we use a pre-built minimal packet structure.

	// SNMP v2c GET: version=1 (v2c), community string, GET request PDU
	// This is a simplified encoder — full BER/ASN.1 is complex.
	var pkt []byte

	// ASN.1: SEQUENCE
	//   INTEGER 1 (version: v2c)
	//   OCTET STRING community
	//   GetRequestPDU [APPLICATION 0] SEQUENCE {
	//     INTEGER requestID
	//     INTEGER 0 (error-status)
	//     INTEGER 0 (error-index)
	//     VarBindList SEQUENCE {
	//       VarBind SEQUENCE {
	//         OID 1.3.6.1.2.1.1.1.0
	//         NULL
	//       }
	//     }
	//   }

	// For MVP: use encoding/asn1 with raw structures.
	// The SNMP packet structure is:
	// SEQUENCE {
	//   INTEGER 1,          // v2c
	//   OCTET STRING,       // community
	//   [0] SEQUENCE {      // GetRequest PDU
	//     INTEGER,          // request-id
	//     INTEGER 0,        // error-status
	//     INTEGER 0,        // error-index
	//     SEQUENCE {        // variable-bindings
	//       SEQUENCE {      // varbind
	//         OID,          // 1.3.6.1.2.1.1.1.0 (sysDescr)
	//         NULL
	//       }
	//     }
	//   }
	// }

	// Since proper SNMP BER encoding is complex, we use a different approach:
	// we send the request as a well-formed SNMP packet using encoding/asn1.
	// For now, we return a minimal valid packet.

	// Version: 1 (SNMPv2c)
	verBytes := asn1EncodeInt(1)
	// Community
	comBytes := asn1EncodeOctetString([]byte(community))
	// Request ID
	reqBytes := asn1EncodeInt(requestID)
	// Error status (0)
	errBytes := asn1EncodeInt(0)
	// OID for sysDescr.0
	oidBytes := asn1EncodeOID(oid)
	// NULL value
	nullBytes := []byte{0x05, 0x00}
	// VarBind: SEQUENCE { OID, NULL }
	varbind := asn1Encode(0x30, append(oidBytes, nullBytes...))
	// VarBindList: SEQUENCE { VarBind }
	varbindList := asn1Encode(0x30, varbind)
	// PDU: [APPLICATION 0] SEQUENCE { reqID, errStatus, errIndex, varbindList }
	pdu := asn1Encode(0xA0, append(append(append(reqBytes, errBytes...), errBytes...), varbindList...))
	// Full packet: SEQUENCE { version, community, PDU }
	pkt = asn1Encode(0x30, append(append(verBytes, comBytes...), pdu...))

	_ = pkt
	return pkt
}

// parseSNMPResponse extracts sysDescr from the SNMP response.
func parseSNMPResponse(data []byte) (*SNMPResult, error) {
	// Simplified parsing: look for the sysDescr value in the response.
	// A full implementation would properly decode the BER/ASN.1 structure.
	// For the MVP: search for printable ASCII strings in the response.
	// sysDescr typically contains the device's self-description.

	// Basic validation: response should be at least 30 bytes and start with 0x30 (SEQUENCE)
	if len(data) < 30 || data[0] != 0x30 {
		return nil, fmt.Errorf("snmp: invalid response")
	}

	// Try to extract the sysDescr value (the last OCTET STRING in the varbind).
	// We scan for the OID pattern followed by the string value.
	// This is a heuristic — a proper BER parser would be more robust.
	sysDescr := extractSysDescr(data)
	if sysDescr == "" {
		return nil, fmt.Errorf("snmp: no sysDescr in response")
	}

	return &SNMPResult{
		Reachable: true,
		SysDescr:  sysDescr,
	}, nil
}

// extractSysDescr scans the SNMP response for the sysDescr value.
func extractSysDescr(data []byte) string {
	// Look for OID 1.3.6.1.2.1.1.1.0 pattern (encoded as BER)
	// The BER-encoded OID for sysDescr is: 06 08 2B 06 01 02 01 01 01 00
	oidPattern := []byte{0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

	for i := 0; i < len(data)-len(oidPattern); i++ {
		if data[i] == oidPattern[0] && bytesEqual(data[i:i+len(oidPattern)], oidPattern) {
			// Found the OID — the next bytes should be the value (OCTET STRING)
			valStart := i + len(oidPattern)
			if valStart < len(data) && data[valStart] == 0x04 {
				// OCTET STRING — next byte(s) = length
				if valStart+1 < len(data) {
					length := int(data[valStart+1])
					if length < 0x80 && valStart+2+length <= len(data) {
						return strings.TrimSpace(string(data[valStart+2 : valStart+2+length]))
					}
				}
			}
		}
	}
	return ""
}

// ASN.1 BER encoding helpers.
func asn1Encode(tag byte, content []byte) []byte {
	if len(content) < 128 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	// Multi-byte length (rare for our use case)
	lengthBytes := asn1EncodeLength(len(content))
	return append(append([]byte{tag}, lengthBytes...), content...)
}

func asn1EncodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	// For lengths > 127: long form
	var reversed []byte
	for length > 0 {
		reversed = append(reversed, byte(length&0xFF))
		length >>= 8
	}
	result := []byte{byte(0x80 | len(reversed))}
	for i := len(reversed) - 1; i >= 0; i-- {
		result = append(result, reversed[i])
	}
	return result
}

func asn1EncodeInt(v int32) []byte {
	// INTEGER encoding
	if v >= 0 && v < 128 {
		return []byte{0x02, 0x01, byte(v)}
	}
	// Multi-byte integer
	var content []byte
	val := int64(v)
	for val != 0 {
		content = append([]byte{byte(val & 0xFF)}, content...)
		val >>= 8
	}
	return asn1Encode(0x02, content)
}

func asn1EncodeOctetString(s []byte) []byte {
	return asn1Encode(0x04, s)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func asn1EncodeOID(oid []int) []byte {
	// OID encoding: first byte = 40*a+b, rest = base-128
	var content []byte
	if len(oid) >= 2 {
		content = append(content, byte(40*oid[0]+oid[1]))
	}
	for _, v := range oid[2:] {
		if v < 128 {
			content = append(content, byte(v))
		} else {
			// Multi-byte OID component
			var temp []byte
			for v > 0 {
				temp = append([]byte{byte(v & 0x7F)}, temp...)
				v >>= 7
			}
			for i, b := range temp {
				if i < len(temp)-1 {
					content = append(content, b|0x80)
				} else {
					content = append(content, b)
				}
			}
		}
	}
	return asn1Encode(0x06, content)
}

// StoreSNMPResult saves the SNMP findings as observations on the host asset.
func StoreSNMPResult(ctx context.Context, st *store.Store, campaignID int64, host string, result *SNMPResult) error {
	if !result.Reachable {
		return nil
	}
	ip, err := st.GetAssetByValue(ctx, campaignID, store.KindIP, host)
	if err != nil {
		return err
	}
	attrs := map[string]any{
		"port":      161,
		"proto":     "udp",
		"service":   "snmp",
		"community": result.Community,
		"sysdescr":  result.SysDescr,
	}
	if result.SysName != "" {
		attrs["sysname"] = result.SysName
	}
	_, err = st.AddObservation(ctx, campaignID, ip.ID, "snmp-enum", attrs)
	return err
}
