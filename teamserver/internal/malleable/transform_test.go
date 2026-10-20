package malleable

import (
	"bytes"
	"testing"
)

func TestApplyOutboundBase64(t *testing.T) {
	input := []byte("hello world")
	result := ApplyOutbound(input, []string{"base64"})
	if string(result) != "aGVsbG8gd29ybGQ=" {
		t.Fatalf("unexpected base64: %s", result)
	}
}

func TestApplyOutboundPrepend(t *testing.T) {
	input := []byte("data")
	result := ApplyOutbound(input, []string{"prepend PREFIX_"})
	if string(result) != "PREFIX_data" {
		t.Fatalf("unexpected prepend: %s", result)
	}
}

func TestApplyOutboundAppend(t *testing.T) {
	input := []byte("data")
	result := ApplyOutbound(input, []string{"append _SUFFIX"})
	if string(result) != "data_SUFFIX" {
		t.Fatalf("unexpected append: %s", result)
	}
}

func TestApplyOutboundMask(t *testing.T) {
	input := []byte("AAAA")
	result := ApplyOutbound(input, []string{"mask 66"})
	// XOR 'A'(65) with 66 = 0x03
	for _, b := range result {
		if b != 0x03 {
			t.Fatalf("expected 0x03, got 0x%02x", b)
		}
	}
}

func TestApplyOutboundMaskLegacyChar(t *testing.T) {
	input := []byte("AAAA")
	result := ApplyOutbound(input, []string{"mask B"})
	for _, b := range result {
		if b != 0x03 {
			t.Fatalf("expected 0x03, got 0x%02x", b)
		}
	}
}

func TestApplyOutboundChain(t *testing.T) {
	input := []byte("secret")
	steps := []string{"prepend [", "append ]", "base64"}
	result := ApplyOutbound(input, steps)
	// Should be base64 of "[secret]"
	if string(result) != "W3NlY3JldF0=" {
		t.Fatalf("unexpected chain result: %s", result)
	}
}

func TestRoundTrip(t *testing.T) {
	original := []byte("round trip test data 12345")
	steps := []string{"prepend HEADER:", "mask X", "base64", "append .END"}

	encoded := ApplyOutbound(original, steps)
	decoded, err := ApplyInbound(encoded, steps)
	if err != nil {
		t.Fatalf("ApplyInbound: %v", err)
	}

	if !bytes.Equal(original, decoded) {
		t.Fatalf("round trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestRoundTripBase64Only(t *testing.T) {
	original := []byte("\x00\x01\x02\xff\xfe")
	steps := []string{"base64"}

	encoded := ApplyOutbound(original, steps)
	decoded, err := ApplyInbound(encoded, steps)
	if err != nil {
		t.Fatalf("ApplyInbound: %v", err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatalf("base64 round trip failed")
	}
}

func TestRoundTripMaskOnly(t *testing.T) {
	original := []byte("mask test 123")
	steps := []string{"mask 90"}

	encoded := ApplyOutbound(original, steps)
	decoded, err := ApplyInbound(encoded, steps)
	if err != nil {
		t.Fatalf("ApplyInbound: %v", err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatalf("mask round trip failed")
	}
}

func TestRoundTripMaskLegacyChar(t *testing.T) {
	original := []byte("mask test 123")
	steps := []string{"mask Z"}

	encoded := ApplyOutbound(original, steps)
	decoded, err := ApplyInbound(encoded, steps)
	if err != nil {
		t.Fatalf("ApplyInbound: %v", err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatalf("legacy char mask round trip failed")
	}
}

func TestApplyInboundBadBase64(t *testing.T) {
	_, err := ApplyInbound([]byte("not-valid-b64!!!"), []string{"base64"})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestBodyTransformSteps(t *testing.T) {
	bt := BodyTransform{
		Prepend: "START",
		Base64:  true,
		Mask:    true,
		MaskKey: 42,
		Append:  "END",
	}

	steps := BodyTransformSteps(bt)
	if len(steps) != 4 {
		t.Fatalf("expected 4 steps, got %d: %v", len(steps), steps)
	}
	if steps[0] != "mask 42" {
		t.Fatalf("first step should be mask 42, got %s", steps[0])
	}
	if steps[3] != "append END" {
		t.Fatalf("last step should be append, got %s", steps[3])
	}
}

func TestServerTransformSteps(t *testing.T) {
	st := ServerTransform{
		Base64: true,
	}
	steps := ServerTransformSteps(st)
	if len(steps) != 1 || steps[0] != "base64" {
		t.Fatalf("expected [base64], got %v", steps)
	}
}

func TestMaskStepDefault(t *testing.T) {
	step := maskStep(0)
	if step != "mask 65" {
		t.Fatalf("expected 'mask 65', got '%s'", step)
	}
}

func TestMaskStepCustom(t *testing.T) {
	step := maskStep(66)
	if step != "mask 66" {
		t.Fatalf("expected 'mask 66', got '%s'", step)
	}
}

func TestMaskStepHighKey(t *testing.T) {
	step := maskStep(211)
	if step != "mask 211" {
		t.Fatalf("expected 'mask 211', got '%s'", step)
	}
}

func TestRoundTripHighMaskKey(t *testing.T) {
	original := []byte(`{"build_id":"abc123","hostname":"web01","os":"linux"}`)
	bt := BodyTransform{
		Mask:    true,
		MaskKey: 211,
		Base64:  true,
		Prepend: "<!-- ",
		Append:  "\"}",
	}
	steps := BodyTransformSteps(bt)
	encoded := ApplyOutbound(original, steps)
	decoded, err := ApplyInbound(encoded, steps)
	if err != nil {
		t.Fatalf("ApplyInbound with mask_key=211: %v", err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatalf("round trip with mask_key=211 failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEmptySteps(t *testing.T) {
	input := []byte("unchanged")
	result := ApplyOutbound(input, nil)
	if !bytes.Equal(input, result) {
		t.Fatal("nil steps should return input unchanged")
	}

	decoded, err := ApplyInbound(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, decoded) {
		t.Fatal("nil steps inbound should return input unchanged")
	}
}
