package xngin

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

// Request is one offload decision request delivered to a Handler.
type Request struct {
	// Msg is the NOTIFY message name ("http-request").
	Msg string
	// Fields are the flat KV fields of the NOTIFY message.
	Fields map[string]Value
	// Header multi-map (lowercased names -> values).
	Header map[string][]string
	// Body chunks accumulated so far (nil unless HAS_BODY).
	Body []byte
	// Async is true when the engine flagged NOTIFY ASYNC.
	Async bool
	// BodyTruncated reports the engine could not capture the full body.
	BodyTruncated bool
}

// Get returns a string field or "".
func (r *Request) Get(name string) string {
	if s, ok := r.Fields[name].(string); ok {
		return s
	}
	return ""
}

// GetIP returns an IP field as net.IP or nil.
func (r *Request) GetIP(name string) net.IP {
	ip, _ := r.Fields[name].(net.IP)
	return ip
}

// Verdict is the agent's decision for one stream.
type Verdict struct {
	Action      string            // "allow" | "deny" | "redirect" (required)
	Status      int               // deny status (0 -> engine default 403)
	Body        []byte            // optional deny body
	ContentType string            // for Body
	Location    string            // for redirect
	SetHeaders  map[string]string // applied to upstream request
	UnsetHeader []string
	// ReqBody replaces the request body forwarded upstream (non-nil to
	// send; requires the engine captured the body).
	ReqBody []byte
	// ResHeaders are applied to the client-bound response headers.
	ResHeaders map[string]string
	// ResUnsetHeaders removes client-bound response headers.
	ResUnsetHeaders []string
	// ResBody replaces the response body (non-nil to send).
	ResBody       []byte
	Vars          map[string]string // exposed as $xngin_<name>
	CacheTTL      uint32            // >0 lets engine cache this verdict
	Reason        string
	Score         int64
}

// Allow is a shorthand allow verdict.
func Allow() *Verdict { return &Verdict{Action: "allow"} }

// Deny is a shorthand deny verdict.
func Deny(status int, reason string) *Verdict {
	return &Verdict{Action: "deny", Status: status, Reason: reason}
}

func (v *Verdict) marshal() ([]byte, error) {
	var out []byte
	var err error
	put := func(name string, val Value) {
		if err == nil {
			out, err = appendKV(out, name, val)
		}
	}
	put("action", v.Action)
	if v.Status != 0 {
		put("status", int32(v.Status))
	}
	if len(v.Body) > 0 {
		put("body", v.Body)
	}
	if v.ContentType != "" {
		put("content-type", v.ContentType)
	}
	if v.Location != "" {
		put("location", v.Location)
	}
	if len(v.SetHeaders) > 0 {
		put("hdr-set", KVMap(anyMap(v.SetHeaders)))
	}
	if len(v.UnsetHeader) > 0 {
		put("hdr-unset", v.UnsetHeader)
	}
	if v.ReqBody != nil {
		put("req-body", v.ReqBody)
	}
	if len(v.ResHeaders) > 0 {
		put("res-hdr-set", KVMap(anyMap(v.ResHeaders)))
	}
	if len(v.ResUnsetHeaders) > 0 {
		put("res-hdr-unset", v.ResUnsetHeaders)
	}
	if v.ResBody != nil {
		put("res-body", v.ResBody)
	}
	if len(v.Vars) > 0 {
		put("vars", KVMap(anyMap(v.Vars)))
	}
	if v.CacheTTL > 0 {
		put("cache-ttl", v.CacheTTL)
	}
	if v.Reason != "" {
		put("reason", v.Reason)
	}
	if v.Score != 0 {
		put("score", v.Score)
	}
	return out, err
}

func anyMap(m map[string]string) map[string]Value {
	out := make(map[string]Value, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Handler decides one request. It must be safe for concurrent use;
// each stream is handled in its own goroutine.
type Handler interface {
	Handle(ctx context.Context, req *Request) (*Verdict, error)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, req *Request) (*Verdict, error)

func (f HandlerFunc) Handle(ctx context.Context, r *Request) (*Verdict, error) {
	return f(ctx, r)
}

// Server is an XNAP agent server.
type Server struct {
	Handler    Handler
	AgentID    string
	MaxStreams uint32
	MaxFrame   uint32
	Logger     *log.Logger // nil -> silent
}

// Serve accepts XNAP connections on l until it is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(c)
	}
}

// ListenAndServe is a convenience for "unix:/path", "tcp:port" or
// "tcp:host:port" listen addresses.
func (s *Server) ListenAndServe(addr string) error {
	var (
		l   net.Listener
		err error
	)
	switch {
	case strings.HasPrefix(addr, "unix:"):
		l, err = net.Listen("unix", addr[5:])
	case strings.HasPrefix(addr, "tcp:"):
		l, err = net.Listen("tcp", addr[4:])
	default:
		l, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}
	return s.Serve(l)
}

type streamState struct {
	req *Request
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil && s.Logger != nil {
			s.Logger.Printf("xngin: connection %v: panic: %v",
				c.RemoteAddr(), r)
		}
	}()

	maxStreams := s.MaxStreams
	if maxStreams == 0 {
		maxStreams = 256
	}
	maxFrame := s.MaxFrame
	if maxFrame == 0 {
		maxFrame = 16384
	}
	agentID := s.AgentID
	if agentID == "" {
		agentID = "xngin-go/1"
	}

	var (
		buf     []byte
		streams = map[uint64]*streamState{}
		mu      sync.Mutex
		wg      sync.WaitGroup
		writeMu sync.Mutex
	)

	writeFrame := func(f *Frame) {
		writeMu.Lock()
		defer writeMu.Unlock()
		c.Write(f.Marshal())
	}

	defer wg.Wait()

	tmp := make([]byte, 64*1024)
	for {
		n, err := c.Read(tmp)
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
		buf = append(buf, tmp[:n]...)

		var frames []Frame
		frames, buf, err = ParseFramesMax(buf, maxFrame)
		if err != nil {
			return
		}

		for _, fr := range frames {
			switch fr.Type {

			case FrameEngineHello:
				hello := KVPairs(
					Pair{"version", uint32(Version)},
					Pair{"max-frame-size", maxFrame},
					Pair{"max-streams", maxStreams},
					Pair{"capabilities",
						uint32(CapBody | CapAsync | CapVCache | CapResp)},
					Pair{"agent-id", agentID},
				)
				writeFrame(&Frame{Type: FrameAgentHello, Payload: hello})

			case FramePing:
				writeFrame(&Frame{Type: FramePong, SID: fr.SID,
					FID: fr.FID, Payload: fr.Payload})

			case FrameAbort:
				mu.Lock()
				delete(streams, fr.SID)
				mu.Unlock()

			case FrameBody:
				mu.Lock()
				st := streams[fr.SID]
				mu.Unlock()
				if st == nil {
					break
				}
				st.req.Body = append(st.req.Body, fr.Payload...)
				if fr.Flags&FlagBodyLast != 0 {
					if fr.Flags&FlagBodyTruncated != 0 {
						st.req.BodyTruncated = true
					}
					wg.Add(1)
					go s.handleStream(c, st, fr.SID, writeFrame, &wg, &mu, streams)
				}

			case FrameNotify:
				msg, fields, hdrs, trunc := parseNotify(fr.Payload)
				st := &streamState{req: &Request{
					Msg: msg, Fields: fields, Header: hdrs,
					Async:         fr.Flags&FlagNotifyAsync != 0,
					BodyTruncated: trunc,
				}}
				mu.Lock()
				streams[fr.SID] = st
				mu.Unlock()
				if fr.Flags&FlagNotifyHasBody == 0 {
					wg.Add(1)
					go s.handleStream(c, st, fr.SID, writeFrame, &wg, &mu, streams)
				}

			case FrameDiscon:
				return
			}
		}
	}
}

func (s *Server) handleStream(c net.Conn, st *streamState, sid uint64,
	writeFrame func(*Frame), wg *sync.WaitGroup,
	mu *sync.Mutex, streams map[uint64]*streamState) {
	defer wg.Done()
	defer func() {
		mu.Lock()
		delete(streams, sid)
		mu.Unlock()
	}()

	v, err := s.Handler.Handle(context.Background(), st.req)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Printf("xngin: handler error: %v", err)
		}
		v = Deny(500, "agent error")
	}
	if v == nil {
		v = Allow()
	}
	payload, err := v.marshal()
	if err != nil {
		payload = KVPairs(Pair{"action", "deny"}, Pair{"status", int32(500)})
	}
	writeFrame(&Frame{Type: FrameVerdict, Flags: FlagFin,
		SID: sid, Payload: payload})
}

func parseNotify(payload []byte) (string, map[string]Value,
	map[string][]string, bool) {
	d := &decoder{buf: payload}
	msg := ""
	if b, err := d.lenBytes(); err == nil {
		msg = string(b)
	}
	fields := map[string]Value{}
	hdrs := map[string][]string{}
	trunc := false
	for {
		name, v, err := d.kv()
		if err != nil || name == "" {
			break
		}
		if name == "headers" {
			if pairs, ok := v.([]Pair); ok {
				for _, p := range pairs {
					if s, ok := p.Value.(string); ok {
						hdrs[p.Name] = append(hdrs[p.Name], s)
					}
				}
			}
			continue
		}
		if name == "body-truncated" {
			if b, ok := v.(bool); ok {
				trunc = b
			}
			continue
		}
		fields[name] = v
	}
	return msg, fields, hdrs, trunc
}
