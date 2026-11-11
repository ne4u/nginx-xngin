// Package xngin implements the XNAP wire protocol (SPEC.md v1) used to
// build xngin agents: external traffic-decision services for nginx.
package xngin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const Version = 1

// Frame types.
const (
	FrameEngineHello = 0x01
	FrameAgentHello  = 0x02
	FrameDiscon      = 0x03
	FrameNotify      = 0x04
	FrameVerdict     = 0x05
	FrameBody        = 0x06
	FrameAbort       = 0x07
	FramePing        = 0x08
	FramePong        = 0x09
)

// Value types.
const (
	VTNull    = 0x00
	VTTrue    = 0x01
	VTFalse   = 0x02
	VTInt32   = 0x03
	VTInt64   = 0x04
	VTUint32  = 0x05
	VTUint64  = 0x06
	VTIPv4    = 0x07
	VTIPv6    = 0x08
	VTStr     = 0x09
	VTBin     = 0x0A
	VTKVL     = 0x0B
	VTStrList = 0x0C
)

// Stream lifecycle flags.
const (
	FlagFin   = 0x01
	FlagAbort = 0x02
)

// Frame-specific flags.
const (
	FlagNotifyHasBody = 1 << 8
	FlagNotifyAsync   = 1 << 9
	FlagBodyLast      = 1 << 8
	FlagBodyTruncated = 1 << 9
)

// Capability bits exchanged in HELLO.
const (
	CapBody   = 0x01
	CapAsync  = 0x02
	CapVCache = 0x04
	CapResp   = 0x08
)

// ErrProtocol is returned for malformed frames.
var ErrProtocol = errors.New("xngin: protocol error")

// Value is a decoded KV value. Go mapping:
//
//	NULL->nil, TRUE/FALSE->bool, INT->int64, UINT->uint64,
//	IPV4/IPV6->net.IP, STR->string, BIN->[]byte,
//	KVL->[]Pair, STRLIST->[]string
type Value = any

// Pair is one entry of a KV list (order preserved).
type Pair struct {
	Name  string
	Value Value
}

// ---------- varint ----------

func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendSvarint(dst []byte, v int64) []byte {
	return appendVarint(dst, uint64(v<<1)^uint64(v>>63))
}

// ---------- value encode ----------

func appendValue(dst []byte, v Value) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return append(dst, VTNull), nil
	case bool:
		if t {
			return append(dst, VTTrue), nil
		}
		return append(dst, VTFalse), nil
	case int:
		dst = append(dst, VTInt64)
		return appendSvarint(dst, int64(t)), nil
	case int32:
		dst = append(dst, VTInt32)
		return appendSvarint(dst, int64(t)), nil
	case int64:
		dst = append(dst, VTInt64)
		return appendSvarint(dst, t), nil
	case uint32:
		dst = append(dst, VTUint32)
		return appendVarint(dst, uint64(t)), nil
	case uint64:
		dst = append(dst, VTUint64)
		return appendVarint(dst, t), nil
	case net.IP:
		if v4 := t.To4(); v4 != nil {
			dst = append(dst, VTIPv4)
			return append(dst, v4...), nil
		}
		dst = append(dst, VTIPv6)
		return append(dst, t.To16()...), nil
	case string:
		dst = append(dst, VTStr)
		dst = appendVarint(dst, uint64(len(t)))
		return append(dst, t...), nil
	case []byte:
		dst = append(dst, VTBin)
		dst = appendVarint(dst, uint64(len(t)))
		return append(dst, t...), nil
	case []string:
		dst = append(dst, VTStrList)
		dst = appendVarint(dst, uint64(len(t)))
		for _, s := range t {
			dst = appendVarint(dst, uint64(len(s)))
			dst = append(dst, s...)
		}
		return dst, nil
	case []Pair:
		var inner []byte
		var err error
		for _, p := range t {
			inner, err = appendKV(inner, p.Name, p.Value)
			if err != nil {
				return nil, err
			}
		}
		dst = append(dst, VTKVL)
		dst = appendVarint(dst, uint64(len(inner)))
		return append(dst, inner...), nil
	default:
		return nil, fmt.Errorf("xngin: cannot encode %T", v)
	}
}

func appendKV(dst []byte, name string, v Value) ([]byte, error) {
	dst = appendVarint(dst, uint64(len(name)))
	dst = append(dst, name...)
	return appendValue(dst, v)
}

// KVPairs builds a KV payload from a map (order not preserved) or pairs.
func KVPairs(kv ...Pair) []byte {
	var out []byte
	for _, p := range kv {
		out, _ = appendKV(out, p.Name, p.Value)
	}
	return out
}

// KVMap is a convenience for building KVL values from a map.
func KVMap(m map[string]Value) []Pair {
	out := make([]Pair, 0, len(m))
	for k, v := range m {
		out = append(out, Pair{k, v})
	}
	return out
}

// ---------- decoding ----------

type decoder struct {
	buf []byte
	pos int
}

func (d *decoder) varint() (uint64, error) {
	var v uint64
	var shift uint
	for {
		if d.pos >= len(d.buf) {
			return 0, ErrProtocol
		}
		b := d.buf[d.pos]
		d.pos++
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, nil
		}
		shift += 7
		if shift >= 70 {
			return 0, ErrProtocol
		}
	}
}

func (d *decoder) svarint() (int64, error) {
	v, err := d.varint()
	if err != nil {
		return 0, err
	}
	return int64(v>>1) ^ -int64(v&1), nil
}

func (d *decoder) need(n int) error {
	if len(d.buf)-d.pos < n {
		return ErrProtocol
	}
	return nil
}

func (d *decoder) value() (Value, error) {
	if err := d.need(1); err != nil {
		return nil, err
	}
	t := d.buf[d.pos]
	d.pos++
	switch t {
	case VTNull:
		return nil, nil
	case VTTrue:
		return true, nil
	case VTFalse:
		return false, nil
	case VTInt32, VTInt64:
		return d.svarint()
	case VTUint32, VTUint64:
		return d.varint()
	case VTIPv4:
		if err := d.need(4); err != nil {
			return nil, err
		}
		ip := net.IP(d.buf[d.pos : d.pos+4])
		d.pos += 4
		return ip, nil
	case VTIPv6:
		if err := d.need(16); err != nil {
			return nil, err
		}
		ip := net.IP(d.buf[d.pos : d.pos+16])
		d.pos += 16
		return ip, nil
	case VTStr, VTBin:
		n, err := d.varint()
		if err != nil || d.need(int(n)) != nil {
			return nil, ErrProtocol
		}
		b := d.buf[d.pos : d.pos+int(n)]
		d.pos += int(n)
		if t == VTStr {
			return string(b), nil
		}
		out := make([]byte, len(b))
		copy(out, b)
		return out, nil
	case VTKVL:
		n, err := d.varint()
		if err != nil || d.need(int(n)) != nil {
			return nil, ErrProtocol
		}
		sub := &decoder{buf: d.buf[d.pos : d.pos+int(n)]}
		d.pos += int(n)
		var pairs []Pair
		for {
			name, v, err := sub.kv()
			if err != nil {
				return nil, err
			}
			if name == "" {
				break
			}
			pairs = append(pairs, Pair{name, v})
		}
		return pairs, nil
	case VTStrList:
		n, err := d.varint()
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, n)
		for i := uint64(0); i < n; i++ {
			ln, err := d.varint()
			if err != nil || d.need(int(ln)) != nil {
				return nil, ErrProtocol
			}
			out = append(out, string(d.buf[d.pos:d.pos+int(ln)]))
			d.pos += int(ln)
		}
		return out, nil
	}
	return nil, ErrProtocol
}

// kv returns the next (name, value); name=="" signals end of list.
func (d *decoder) kv() (string, Value, error) {
	if d.pos >= len(d.buf) {
		return "", nil, nil
	}
	n, err := d.varint()
	if err != nil || d.need(int(n)) != nil {
		return "", nil, ErrProtocol
	}
	name := string(d.buf[d.pos : d.pos+int(n)])
	d.pos += int(n)
	v, err := d.value()
	return name, v, err
}

// ParseKV decodes a KV payload into ordered pairs.
func ParseKV(payload []byte) ([]Pair, error) {
	d := &decoder{buf: payload}
	var out []Pair
	for {
		name, v, err := d.kv()
		if err != nil {
			return nil, err
		}
		if name == "" {
			return out, nil
		}
		out = append(out, Pair{name, v})
	}
}

// PairsGet returns the first value for name from a pair list.
func PairsGet(ps []Pair, name string) (Value, bool) {
	for _, p := range ps {
		if p.Name == name {
			return p.Value, true
		}
	}
	return nil, false
}

// ---------- frames ----------

// Frame is one XNAP frame.
type Frame struct {
	Type    byte
	Flags   uint32
	SID     uint64
	FID     uint64
	Payload []byte
}

// Marshal encodes the frame to wire bytes.
func (f *Frame) Marshal() []byte {
	out := make([]byte, 0, len(f.Payload)+16)
	body := make([]byte, 0, len(f.Payload)+16)
	body = append(body, f.Type)
	var fb [4]byte
	binary.BigEndian.PutUint32(fb[:], f.Flags)
	body = append(body, fb[:]...)
	body = appendVarint(body, f.SID)
	body = appendVarint(body, f.FID)
	body = append(body, f.Payload...)
	out = appendVarint(out, uint64(len(body)))
	return append(out, body...)
}

// ReadFrame reads one frame; returns nil,nil when more bytes are needed.
// Call feed-style: append read bytes to buf, call ParseFrames.
func ParseFrames(buf []byte) ([]Frame, []byte, error) {
	var frames []Frame
	for {
		d := &decoder{buf: buf}
		start := 0
		flen, err := d.varint()
		if err != nil {
			return frames, buf[start:], nil // need more
		}
		if flen < 6 {
			return nil, nil, ErrProtocol
		}
		if len(buf)-d.pos < int(flen) {
			return frames, buf[start:], nil
		}
		fend := d.pos + int(flen)
		ftype := buf[d.pos]
		d.pos++
		if err := d.need(4); err != nil {
			return nil, nil, ErrProtocol
		}
		flags := binary.BigEndian.Uint32(buf[d.pos:])
		d.pos += 4
		sid, err := d.varint()
		if err != nil {
			return nil, nil, ErrProtocol
		}
		fid, err := d.varint()
		if err != nil {
			return nil, nil, ErrProtocol
		}
		payload := buf[d.pos:fend]
		frames = append(frames, Frame{
			Type: ftype, Flags: flags, SID: sid, FID: fid,
			Payload: append([]byte(nil), payload...),
		})
		buf = buf[fend:]
	}
}
