package core

import (
	"fmt"
	"testing"
)

func BenchmarkBuild(b *testing.B) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	params := Params{
		SessionID:   "bench-session",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoNone,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := Build(params, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildGzip(b *testing.B) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	params := Params{
		SessionID:   "bench-session",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionGzip,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoNone,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := Build(params, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildHMAC(b *testing.B) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	hmacKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i)
	}
	params := Params{
		SessionID:   "bench-session",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoSHA256,
		HMACKey:     hmacKey,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := Build(params, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	params := Params{
		SessionID:   "bench-session",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoNone,
	}
	env, err := Build(params, payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := Open(env)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenGzip(b *testing.B) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	params := Params{
		SessionID:   "bench-session",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionGzip,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoNone,
	}
	env, err := Build(params, payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := Open(env)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyHMACSHA256(b *testing.B) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	hmacKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i)
	}
	params := Params{
		SessionID:   "bench-session",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoSHA256,
		HMACKey:     hmacKey,
	}
	env, err := Build(params, payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if !VerifyHMACSHA256(hmacKey, env) {
			b.Fatal("HMAC verification failed")
		}
	}
}

// BenchmarkBuildGzip_PayloadSize：gzip+HMAC 在不同 payload 规模下的吞吐与分配。
// 验证 sync.Pool 复用后，分配是否随 payload 线性增长（理想：仅随输出大小，非内部表）。
func BenchmarkBuildGzip_PayloadSize(b *testing.B) {
	hmacKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i)
	}
	for _, sz := range []int{4 * 1024, 64 * 1024, 1024 * 1024} {
		b.Run(byteSize(sz), func(b *testing.B) {
			payload := make([]byte, sz)
			for i := range payload {
				payload[i] = byte(i)
			}
			params := Params{
				SessionID:   "bench-session",
				KeyID:       "key-1",
				Seq:         1,
				ChunkID:     "chunk-1",
				Codec:       CodecJSON,
				Compression: CompressionGzip,
				Encryption:  EncryptionNone,
				HMACAlgo:    HMACAlgoSHA256,
				HMACKey:     hmacKey,
			}
			b.SetBytes(int64(sz))
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Build(params, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func byteSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
