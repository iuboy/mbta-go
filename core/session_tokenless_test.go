package core

import "testing"

// TestNegotiateAuthTokenless 覆盖 CapAuthTokenless 的协商逻辑。
func TestNegotiateAuthTokenless(t *testing.T) {
	t.Run("policy enabled and offered -> selected", func(t *testing.T) {
		res := Negotiate(
			[]string{CapCodecJSON, CapHMACSHA256, CapAuthTokenless},
			Policy{EnableHMACSHA256: true, EnableAuthTokenless: true},
		)
		if !res.IsCapabilitySelected(CapAuthTokenless) {
			t.Error("expected CapAuthTokenless to be selected")
		}
	})

	t.Run("policy disabled -> not selected", func(t *testing.T) {
		res := Negotiate(
			[]string{CapCodecJSON, CapAuthTokenless},
			Policy{EnableAuthTokenless: false},
		)
		if res.IsCapabilitySelected(CapAuthTokenless) {
			t.Error("CapAuthTokenless must not be selected when policy disabled")
		}
	})

	t.Run("not offered -> not selected", func(t *testing.T) {
		res := Negotiate(
			[]string{CapCodecJSON},
			Policy{EnableAuthTokenless: true},
		)
		if res.IsCapabilitySelected(CapAuthTokenless) {
			t.Error("CapAuthTokenless must not be selected when not offered")
		}
	})
}

// TestNegotiateResultIsCapabilitySelected 覆盖能力查询辅助的三态。
func TestNegotiateResultIsCapabilitySelected(t *testing.T) {
	t.Run("selected capability", func(t *testing.T) {
		r := &NegotiateResult{SelectedCapabilities: []string{CapCodecJSON, CapAuthTokenless}}
		if !r.IsCapabilitySelected(CapAuthTokenless) {
			t.Error("expected true for selected cap")
		}
	})
	t.Run("unselected capability", func(t *testing.T) {
		r := &NegotiateResult{SelectedCapabilities: []string{CapCodecJSON}}
		if r.IsCapabilitySelected(CapAuthTokenless) {
			t.Error("expected false for unselected cap")
		}
	})
	t.Run("nil receiver safe", func(t *testing.T) {
		var r *NegotiateResult
		if r.IsCapabilitySelected(CapAuthTokenless) {
			t.Error("expected false on nil receiver")
		}
	})
}
