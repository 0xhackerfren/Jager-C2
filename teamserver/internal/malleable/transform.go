package malleable

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// ApplyOutbound transforms implant-bound data per malleable profile step.
func ApplyOutbound(data []byte, steps []string) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	for _, step := range steps {
		switch {
		case step == "base64":
			enc := base64.StdEncoding.EncodeToString(out)
			out = []byte(enc)
		case strings.HasPrefix(step, "prepend "):
			out = append([]byte(strings.TrimPrefix(step, "prepend ")), out...)
		case strings.HasPrefix(step, "append "):
			out = append(out, []byte(strings.TrimPrefix(step, "append "))...)
		case strings.HasPrefix(step, "mask "):
			k := parseMaskKey(strings.TrimPrefix(step, "mask "))
			if k != 0 {
				for i := range out {
					out[i] ^= k
				}
			}
		}
	}
	return out
}

// ApplyInbound reverses inbound transforms.
func ApplyInbound(data []byte, steps []string) ([]byte, error) {
	out := data
	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		switch {
		case step == "base64":
			dec, err := base64.StdEncoding.DecodeString(string(out))
			if err != nil {
				return nil, err
			}
			out = dec
		case strings.HasPrefix(step, "prepend "):
			prefix := []byte(strings.TrimPrefix(step, "prepend "))
			if len(out) >= len(prefix) {
				out = out[len(prefix):]
			}
		case strings.HasPrefix(step, "append "):
			suffix := []byte(strings.TrimPrefix(step, "append "))
			if len(out) >= len(suffix) {
				out = out[:len(out)-len(suffix)]
			}
		case strings.HasPrefix(step, "mask "):
			k := parseMaskKey(strings.TrimPrefix(step, "mask "))
			if k != 0 {
				for j := range out {
					out[j] ^= k
				}
			}
		}
	}
	return out, nil
}

// parseMaskKey extracts the XOR byte from a mask step value.
// Accepts decimal integer format ("211") or single-char legacy format ("A").
func parseMaskKey(s string) byte {
	if v, err := strconv.Atoi(s); err == nil && v > 0 && v < 256 {
		return byte(v)
	}
	if len(s) > 0 {
		return s[0]
	}
	return 0
}

// maskStep returns a mask pipeline step keyed by integer value.
// Uses decimal format to avoid UTF-8 multi-byte corruption when key >= 128.
func maskStep(key int) string {
	if key > 0 && key < 256 {
		return fmt.Sprintf("mask %d", key)
	}
	return "mask 65"
}

// BodyTransformSteps converts profile body transform to pipeline steps.
// Order must match implant's malleable_encode_outbound: mask -> base64 -> prepend -> append.
// ApplyInbound reverses this list, so inbound decode is: strip append -> strip prepend -> base64 decode -> unmask.
func BodyTransformSteps(bt BodyTransform) []string {
	var steps []string
	if bt.Mask {
		steps = append(steps, maskStep(bt.MaskKey))
	}
	if bt.Base64 {
		steps = append(steps, "base64")
	}
	if bt.Prepend != "" {
		steps = append(steps, "prepend "+bt.Prepend)
	}
	if bt.Append != "" {
		steps = append(steps, "append "+bt.Append)
	}
	return steps
}

// ServerTransformSteps converts server output transform to pipeline steps.
// Order matches implant's malleable_decode_inbound expectations: mask -> base64 -> prepend -> append.
func ServerTransformSteps(st ServerTransform) []string {
	var steps []string
	if st.Mask {
		steps = append(steps, maskStep(st.MaskKey))
	}
	if st.Base64 {
		steps = append(steps, "base64")
	}
	if st.Prepend != "" {
		steps = append(steps, "prepend "+st.Prepend)
	}
	if st.Append != "" {
		steps = append(steps, "append "+st.Append)
	}
	return steps
}
