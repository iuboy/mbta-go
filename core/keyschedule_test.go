package core

import (
	"bytes"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestSessionKeysWipe 验证 Wipe 清零全部密钥材料（AEAD/握手/DualMAC 密钥与
// nonce 前缀），且 nil 接收者安全。密钥擦除是 best-effort 纵深防御（见 Wipe
// 注释），本测试锁定「确实清零」这一契约本身。
func TestSessionKeysWipe(t *testing.T) {
	priv, pub, err := GenerateEphemeral(corepb.Profile_PROFILE_INTL)
	if err != nil {
		t.Fatalf("generate eph: %v", err)
	}
	zz, err := DeriveZZ(corepb.Profile_PROFILE_INTL, priv, pub)
	if err != nil {
		t.Fatalf("derive zz: %v", err)
	}
	th := make([]byte, 32)
	proof := make([]byte, 32)
	keys, err := DeriveSessionKeysWithCaps(corepb.Profile_PROFILE_INTL, zz, th, proof,
		[]string{CapDualIntegrity})
	if err != nil {
		t.Fatalf("derive session keys: %v", err)
	}
	if len(keys.DualMACKey) == 0 {
		t.Fatal("dual_integrity negotiated but DualMACKey empty — test premise broken")
	}

	// 擦除前快照非零（防「本来就零」的空断言）。
	for name, b := range map[string][]byte{
		"C2SKey":       keys.C2SKey,
		"S2CKey":       keys.S2CKey,
		"HandshakeKey": keys.HandshakeKey,
		"DualMACKey":   keys.DualMACKey,
	} {
		if bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("%s all-zero before Wipe — derived-key premise broken", name)
		}
	}

	pc, ps := keys.NoncePrefixC, keys.NoncePrefixS
	keys.Wipe()

	for name, b := range map[string][]byte{
		"C2SKey":       keys.C2SKey,
		"S2CKey":       keys.S2CKey,
		"HandshakeKey": keys.HandshakeKey,
		"DualMACKey":   keys.DualMACKey,
	} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s not zeroed after Wipe", name)
		}
	}
	if keys.NoncePrefixC != [4]byte{} || keys.NoncePrefixC == pc && pc != [4]byte{} {
		t.Error("NoncePrefixC not zeroed after Wipe")
	}
	if keys.NoncePrefixS != [4]byte{} || keys.NoncePrefixS == ps && ps != [4]byte{} {
		t.Error("NoncePrefixS not zeroed after Wipe")
	}

	// nil 接收者不 panic。
	var nilKeys *SessionKeys
	nilKeys.Wipe()
}
