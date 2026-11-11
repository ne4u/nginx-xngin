// Go codec fuzz: go test -fuzz=FuzzFrames -fuzztime=30s ./xngin
package xngin

import "testing"

func FuzzFrames(f *testing.F) {
	f.Add([]byte{0x0a, 0x08, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		frames, _, err := ParseFrames(data)
		if err != nil {
			return
		}
		for _, fr := range frames {
			_, _ = ParseKV(fr.Payload)
			// decoded frames must re-marshal without panic
			_ = fr.Marshal()
		}
	})
}
