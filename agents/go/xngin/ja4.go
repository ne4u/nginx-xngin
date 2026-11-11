// JA4 fingerprinting (FoxIO) from a raw TLS ClientHello handshake
// message — the bytes carried in the XNAP "ch-raw" field (full handshake
// message including its 4-byte header).
//
// The implementation intentionally mirrors ngx_http_xngin_ja4() in the
// nginx module, including its "000000000000" empty-list hash quirk, so an
// agent-computed JA4 matches the engine's own "ja4" NOTIFY field and
// $xngin_ja4 variable for the same ClientHello.
package xngin

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// errBadCH is returned when ch is not a parseable ClientHello message.
var errBadCH = errors.New("xngin: malformed client_hello")

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func sha12(b []byte) string {
	if len(b) == 0 {
		return "000000000000" // matches the module's empty-list hash
	}
	d := sha256.Sum256(b)
	return fmt.Sprintf("%x", d[:6])
}

func hex4list(vals []uint16) []byte {
	out := make([]byte, 0, len(vals)*5)
	for i, v := range vals {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, fmt.Sprintf("%04x", v)...)
	}
	return out
}

func ja4Version(ver uint16) string {
	switch ver {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

type chReader struct {
	b []byte
	p int
}

func (r *chReader) bytes(n int) ([]byte, error) {
	if n < 0 || r.p+n > len(r.b) {
		return nil, errBadCH
	}
	out := r.b[r.p : r.p+n]
	r.p += n
	return out, nil
}

func (r *chReader) u8() (int, error) {
	b, err := r.bytes(1)
	if err != nil {
		return 0, err
	}
	return int(b[0]), nil
}

func (r *chReader) u16() (uint16, error) {
	b, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ComputeJA4 computes the JA4 and JA4_r fingerprints of a raw TLS
// ClientHello handshake message (4-byte handshake header included).
//
//	ja4  = a_b_c           e.g. t13d1516h2_8daaf6152771_b1da8ab2d16f
//	ja4r = a_b-ciphers_c-exts_sigalgs (unhashed)
func ComputeJA4(ch []byte) (ja4 string, ja4r string, err error) {
	if len(ch) < 4 || ch[0] != 0x01 { // client_hello msg type
		return "", "", errBadCH
	}
	hlen := int(ch[1])<<16 | int(ch[2])<<8 | int(ch[3])
	if hlen+4 > len(ch) {
		return "", "", errBadCH
	}

	r := &chReader{b: ch[4 : 4+hlen]}

	verBytes, err := r.bytes(2)
	if err != nil {
		return "", "", err
	}
	highest := binary.BigEndian.Uint16(verBytes)

	if _, err = r.bytes(32); err != nil { // random
		return "", "", err
	}
	sidLen, err := r.u8()
	if err != nil {
		return "", "", err
	}
	if _, err = r.bytes(sidLen); err != nil { // session_id
		return "", "", err
	}

	csLen, err := r.u16()
	if err != nil {
		return "", "", err
	}
	csBytes, err := r.bytes(int(csLen))
	if err != nil {
		return "", "", err
	}
	var ciphers []uint16
	for i := 0; i+1 < len(csBytes); i += 2 {
		cs := binary.BigEndian.Uint16(csBytes[i:])
		if !isGREASE(cs) {
			ciphers = append(ciphers, cs)
		}
	}

	compLen, err := r.u8()
	if err != nil {
		return "", "", err
	}
	if _, err = r.bytes(compLen); err != nil { // compression methods
		return "", "", err
	}

	extLen, err := r.u16()
	if err != nil {
		return "", "", errBadCH
	}
	extBytes, err := r.bytes(int(extLen))
	if err != nil {
		return "", "", errBadCH
	}

	var (
		extTotal          int
		exts              []uint16 // for JA4_c (sorted, excl SNI/ALPN)
		sigAlgs           []uint16 // original order
		sniSeen           bool
		alpn              = [2]byte{'0', '0'}
		er                = &chReader{b: extBytes}
	)

	for er.p+4 <= len(er.b) {
		etype, _ := er.u16()
		dlen, _ := er.u16()
		data, derr := er.bytes(int(dlen))
		if derr != nil {
			return "", "", errBadCH
		}
		if isGREASE(etype) {
			continue
		}
		extTotal++

		switch etype {
		case 0x0000: // server_name
			if len(data) > 0 {
				sniSeen = true
			}
		case 0x0010: // ALPN — counts toward extTotal, excluded from JA4_c
			if len(data) >= 3 {
				listLen := int(data[0])<<8 | int(data[1])
				pos := 2
			alpnLoop:
				for pos < len(data) && pos < 2+listLen {
					pl := int(data[pos])
					pos++
					if pl > 0 && pos+pl <= len(data) {
						if pl == 2 && isGREASE(binary.BigEndian.Uint16(data[pos:])) {
							pos += pl
							continue
						}
						first, lastc := data[pos], data[pos+pl-1]
						if isAlnum(first) && isAlnum(lastc) {
							alpn[0], alpn[1] = first, lastc
						} else {
							alpn[0] = "0123456789abcdef"[first>>4]
							alpn[1] = "0123456789abcdef"[lastc&0x0f]
						}
						break alpnLoop
					}
					pos += pl
				}
			}
		case 0x002b: // supported_versions
			if len(data) >= 3 {
				listLen := int(data[0])
				var maxV uint16
				for i := 1; i+1 < len(data) && i < 1+listLen; i += 2 {
					v := binary.BigEndian.Uint16(data[i:])
					if !isGREASE(v) && v > maxV {
						maxV = v
					}
				}
				if maxV > 0 {
					highest = maxV
				}
			}
		case 0x000d: // signature_algorithms
			if len(data) >= 2 {
				listLen := int(data[0])<<8 | int(data[1])
				for i := 2; i+1 < len(data) && i < 2+listLen; i += 2 {
					sa := binary.BigEndian.Uint16(data[i:])
					if !isGREASE(sa) {
						sigAlgs = append(sigAlgs, sa)
					}
				}
			}
		}

		// SNI and ALPN count toward JA4_a but are excluded from JA4_c
		if etype != 0x0000 && etype != 0x0010 {
			exts = append(exts, etype)
		}
	}

	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })

	sniChar := byte('i')
	if sniSeen {
		sniChar = 'd'
	}
	cc, ec := len(ciphers), extTotal
	if cc > 99 {
		cc = 99
	}
	if ec > 99 {
		ec = 99
	}

	a := fmt.Sprintf("t%c%c%c%02d%02d%c%c",
		ja4Version(highest)[0], ja4Version(highest)[1], sniChar,
		cc, ec, alpn[0], alpn[1])

	bRaw := hex4list(ciphers)
	cRaw := hex4list(exts)
	if len(sigAlgs) > 0 {
		if len(cRaw) > 0 {
			cRaw = append(cRaw, '_')
		}
		cRaw = append(cRaw, hex4list(sigAlgs)...)
	}

	ja4 = fmt.Sprintf("%s_%s_%s", a, sha12(bRaw), sha12(cRaw))
	ja4r = fmt.Sprintf("%s_%s_%s", a, bRaw, cRaw)
	return ja4, ja4r, nil
}
