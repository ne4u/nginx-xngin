// ja4-fp is an example xngin agent: TLS client fingerprinting. For every
// request arriving over a connection whose ClientHello the engine captured
// (xngin_tls_inspect), it computes JA4 + JA4_r from the raw ClientHello
// ("ch-raw" NOTIFY field) itself and surfaces them three ways:
//
//   - upstream request headers:  x-ja4, x-ja4-raw        (hdr-set)
//   - client response headers:   x-ja4, x-ja4-raw        (res-hdr-set)
//   - nginx vars:                $xngin_agent_ja4, $xngin_agent_ja4_r
//                                $xngin_ja4_match        (vars)
//
// Plain HTTP requests (no ch-raw) pass through with a plain allow.
//
// Flags:
//
//	-listen unix:/tmp/xngin-ja4.sock   (or tcp:127.0.0.1:7778)
package main

import (
	"context"
	"flag"
	"log"

	"github.com/xngin/xngin-go/xngin"
)

type fp struct{}

func (fp) Handle(_ context.Context, r *xngin.Request) (*xngin.Verdict, error) {
	raw, ok := r.Fields["ch-raw"].([]byte)
	if !ok || len(raw) == 0 {
		return xngin.Allow(), nil
	}

	ja4, ja4r, err := xngin.ComputeJA4(raw)
	if err != nil {
		return &xngin.Verdict{
			Action: "allow",
			Vars:   map[string]string{"ja4_match": "err"},
		}, nil
	}

	v := xngin.Allow()
	v.Vars = map[string]string{
		"agent_ja4":   ja4,
		"agent_ja4_r": ja4r,
	}
	if engine := r.Get("ja4"); engine != "" {
		if engine == ja4 {
			v.Vars["ja4_match"] = "1"
		} else {
			v.Vars["ja4_match"] = "0"
		}
	}
	v.SetHeaders = map[string]string{
		"x-ja4":     ja4,
		"x-ja4-raw": ja4r,
	}
	v.ResHeaders = map[string]string{
		"x-ja4":     ja4,
		"x-ja4-raw": ja4r,
	}
	return v, nil
}

func main() {
	listen := flag.String("listen", "unix:/tmp/xngin-ja4.sock",
		"unix:/path or tcp:host:port")
	flag.Parse()

	srv := &xngin.Server{
		Handler: fp{},
		AgentID: "ja4-fp/1.0",
		Logger:  log.Default(),
	}
	log.Printf("ja4-fp listening on %s", *listen)
	log.Fatal(srv.ListenAndServe(*listen))
}
