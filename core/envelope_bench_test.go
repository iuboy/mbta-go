package core

import (
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
