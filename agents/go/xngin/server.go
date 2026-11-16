package xngin

import (
	"context"
	"crypto/tls"
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
	ResBody  []byte
	Vars     map[string]string // exposed as $xngin_<name>
	CacheTTL uint32            // >0 lets engine cache this verdict
	Reason   string
	Score    int64
}

// Allow is a shorthand allow verdict.
func Allow() *Verdict { return &Verdict{Action: "allow"} }

// Deny is a shorthand deny verdict.
func Deny(status int, reason string) *Verdict {
	return &Verdict{Action: "deny", Status: status, Reason: reason}
}

func (v *Verdict) marshal() ([]byte, error) {
	return v.marshalInto(nil)
}

// marshalInto encodes the verdict KV payload onto dst, for callers
// supplying a pooled buffer.
func (v *Verdict) marshalInto(out []byte) ([]byte, error) {
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

// EarlyHandler is an optional interface a Handler may implement to
// answer a stream before its request body finishes uploading
// (SPEC §4.2). It is called once per NOTIFY that carries HAS_BODY, on
// the stream's own goroutine — a slow EarlyVerdict cannot stall the
// connection's read loop. A non-nil verdict is sent immediately and the
// stream is closed (the engine stops sending BODY); nil keeps
// accumulating BODY frames and calls Handle at LAST, as today.
// req.Body is always empty at this point.
type EarlyHandler interface {
	EarlyVerdict(ctx context.Context, req *Request) (*Verdict, error)
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
	// TLSConfig enables TLS (optionally mutual) on the listener — the
	// engine connects as the TLS client. Build it with TLSConfig().
	TLSConfig *tls.Config
	Logger    *log.Logger // nil -> silent
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
	req      *Request
	ctx      context.Context
	cancel   context.CancelFunc
	body     []byte // raw accumulation; lands in req.Body at LAST
	trunc    bool
	bodyDone bool          // LAST seen: body is now read-only
	done     chan struct{} // closed at LAST; wakes the stream task
	decided  bool          // early verdict sent; BODY is ignored
}

// marshalPool recycles VERDICT/PONG/HELLO wire buffers: the writer
// goroutine returns each buffer after it hits the socket.
var marshalPool = sync.Pool{New: func() any {
	return make([]byte, 0, 512)
}}

// marshalBuf encodes f into a pooled buffer; callers hand the buffer to
// wq.enqueue (or return it to the pool themselves).
func marshalBuf(f *Frame) []byte {
	return appendFrame(marshalPool.Get().([]byte)[:0], f)
}

// writeQueue owns the conn's write side. The `writing` flag is a
// single-writer claim taken atomically under mu: an uncontended
// producer writes its frame inline (no scheduler hop), while a
// producer that finds a write in flight or queued work appends to the
// queue for the writer goroutine to batch into one net.Buffers writev.
type writeQueue struct {
	c        net.Conn
	mu       sync.Mutex
	queue    [][]byte
	wake     chan struct{}
	stop     chan struct{}
	finished chan struct{}
	closed   bool
	writing  bool
}

func newWriteQueue(c net.Conn) *writeQueue {
	q := &writeQueue{
		c:        c,
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	go q.run()
	return q
}

func (q *writeQueue) enqueue(b []byte) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		marshalPool.Put(b[:0])
		return
	}
	if len(q.queue) == 0 && !q.writing {
		// fast path: take the claim and write inline — the frame is
		// ordered first because the queue is empty.
		q.writing = true
		q.mu.Unlock()

		_, err := q.c.Write(b)
		marshalPool.Put(b[:0])

		q.mu.Lock()
		q.writing = false
		if len(q.queue) > 0 {
			// run() may have skipped a wake while we held the claim
			select {
			case q.wake <- struct{}{}:
			default:
			}
		}
		q.mu.Unlock()
		if err != nil {
			q.c.Close() // unblock the reader so serveConn returns
		}
		return
	}
	q.queue = append(q.queue, b)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *writeQueue) run() {
	defer close(q.finished)
	for {
		select {
		case <-q.stop:
			return
		case <-q.wake:
		}
		q.mu.Lock()
		if q.writing || len(q.queue) == 0 {
			// someone holds the claim; when it is released it
			// re-signals wake if work is pending
			q.mu.Unlock()
			continue
		}
		q.writing = true
		batch := q.queue
		q.queue = nil
		q.mu.Unlock()

		var err error
		if len(batch) == 1 {
			_, err = q.c.Write(batch[0])
		} else {
			// WriteTo consumes the slice it is given; pass a copy so
			// the originals stay whole for the pool return below.
			v := make(net.Buffers, len(batch))
			copy(v, batch)
			_, err = v.WriteTo(q.c)
		}
		for _, b := range batch {
			marshalPool.Put(b[:0])
		}

		q.mu.Lock()
		q.writing = false
		q.mu.Unlock()
		if err != nil {
			q.c.Close() // unblock the reader so serveConn returns
			return
		}
	}
}

func (q *writeQueue) close() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		for _, b := range q.queue {
			marshalPool.Put(b[:0])
		}
		q.queue = nil
		close(q.stop)
	}
	q.mu.Unlock()
	<-q.finished
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil && s.Logger != nil {
			s.Logger.Printf("xngin: connection %v: panic: %v",
				c.RemoteAddr(), r)
		}
	}()

	if s.TLSConfig != nil {
		c = tls.Server(c, s.TLSConfig)
	}

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

	early, _ := s.Handler.(EarlyHandler)

	connCtx, connCancel := context.WithCancel(context.Background())

	var (
		streams = map[uint64]*streamState{}
		mu      sync.Mutex
		wg      sync.WaitGroup
	)
	wq := newWriteQueue(c)

	// teardown order (LIFO): cancel handlers -> stop writer -> wait for
	// stream goroutines -> close the socket.
	defer connCancel()
	defer wq.close()
	defer wg.Wait()

	buf := make([]byte, 0, 64*1024)
	for {
		if len(buf) == cap(buf) {
			nb := make([]byte, len(buf), cap(buf)*2)
			copy(nb, buf)
			buf = nb
		}
		n, err := c.Read(buf[len(buf):cap(buf)])
		if err != nil {
			return
		}
		buf = buf[:len(buf)+n]

		spans, consumed, err := scanFrames(buf, maxFrame)
		if err != nil {
			return
		}

		for _, fr := range spans {
			switch fr.typ {

			case FrameEngineHello:
				hello := KVPairs(
					Pair{"version", uint32(Version)},
					Pair{"max-frame-size", maxFrame},
					Pair{"max-streams", maxStreams},
					Pair{"capabilities",
						uint32(CapBody | CapAsync | CapVCache | CapResp)},
					Pair{"agent-id", agentID},
				)
				wq.enqueue(marshalBuf(&Frame{Type: FrameAgentHello,
					Payload: hello}))

			case FramePing:
				wq.enqueue(marshalBuf(&Frame{Type: FramePong,
					SID: fr.sid, FID: fr.fid, Payload: fr.payload}))

			case FrameAbort:
				mu.Lock()
				if st := streams[fr.sid]; st != nil {
					delete(streams, fr.sid)
					st.cancel()
				}
				mu.Unlock()

			case FrameBody:
				mu.Lock()
				st := streams[fr.sid]
				if st != nil && !st.decided && !st.bodyDone {
					st.body = append(st.body, fr.payload...)
					if fr.flags&FlagBodyLast != 0 {
						st.bodyDone = true
						st.trunc = st.trunc ||
							fr.flags&FlagBodyTruncated != 0
						close(st.done)
					}
				}
				mu.Unlock()

			case FrameNotify:
				msg, fields, hdrs, trunc := parseNotify(fr.payload)
				ctx, cancel := context.WithCancel(connCtx)
				st := &streamState{
					req: &Request{
						Msg: msg, Fields: fields, Header: hdrs,
						Async:         fr.flags&FlagNotifyAsync != 0,
						BodyTruncated: trunc,
					},
					ctx:    ctx,
					cancel: cancel,
					done:   make(chan struct{}),
				}
				mu.Lock()
				streams[fr.sid] = st
				mu.Unlock()
				wg.Add(1)
				go s.streamTask(st, fr.sid,
					fr.flags&FlagNotifyHasBody != 0, early,
					wq, &wg, &mu, streams)

			case FrameDiscon:
				return
			}
		}

		if consumed > 0 {
			copy(buf, buf[consumed:])
			buf = buf[:len(buf)-consumed]
		}
	}
}

// streamTask runs one stream to a verdict: the optional early callback
// first, then (when the request has a body) the wait for LAST, then
// Handle — all off the read loop so a slow handler stalls only its own
// stream.
func (s *Server) streamTask(st *streamState, sid uint64, hasBody bool,
	early EarlyHandler, wq *writeQueue, wg *sync.WaitGroup,
	mu *sync.Mutex, streams map[uint64]*streamState) {
	defer wg.Done()

	if hasBody {
		if early != nil {
			v, err := early.EarlyVerdict(st.ctx, st.req)
			if err != nil {
				if s.Logger != nil {
					s.Logger.Printf("xngin: early handler error: %v", err)
				}
				v = Deny(500, "agent error")
			}
			if v != nil {
				mu.Lock()
				st.decided = true
				delete(streams, sid)
				mu.Unlock()
				s.sendVerdict(wq, sid, v)
				return
			}
		}
		select {
		case <-st.done:
		case <-st.ctx.Done():
			mu.Lock()
			delete(streams, sid)
			mu.Unlock()
			return
		}
		mu.Lock()
		st.req.Body = st.body
		st.req.BodyTruncated = st.req.BodyTruncated || st.trunc
		mu.Unlock()
	}
	s.handleStream(st, sid, wq, mu, streams)
}

func (s *Server) handleStream(st *streamState, sid uint64,
	wq *writeQueue, mu *sync.Mutex, streams map[uint64]*streamState) {
	mu.Lock()
	delete(streams, sid)
	mu.Unlock()

	v, err := s.Handler.Handle(st.ctx, st.req)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Printf("xngin: handler error: %v", err)
		}
		v = Deny(500, "agent error")
	}
	if v == nil {
		v = Allow()
	}
	s.sendVerdict(wq, sid, v)
}

func (s *Server) sendVerdict(wq *writeQueue, sid uint64, v *Verdict) {
	payload, err := v.marshalInto(marshalPool.Get().([]byte)[:0])
	if err != nil {
		payload = append(payload[:0],
			KVPairs(Pair{"action", "deny"},
				Pair{"status", int32(500)})...)
	}
	buf := marshalBuf(&Frame{Type: FrameVerdict, Flags: FlagFin,
		SID: sid, Payload: payload})
	marshalPool.Put(payload[:0])
	wq.enqueue(buf)
}

func parseNotify(payload []byte) (string, map[string]Value,
	map[string][]string, bool) {
	d := &decoder{buf: payload}
	msg := ""
	if b, err := d.lenBytes(); err == nil {
		msg = string(b)
	}
	fields := make(map[string]Value, 16)
	hdrs := make(map[string][]string, 8)
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
