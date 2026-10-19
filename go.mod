module github.com/iuboy/mbta-go

// go 1.26.9：stdlib 安全基线——GO-2026-6617（net/http HPACK 竞态）等 8 条
// govulncheck stdlib 漏洞在 go1.26.9 修复；CI 以 go-version-file 取该版本，
// 升级本指令即升级 CI 的 stdlib 扫描基线。与 pollux-go（go.work）保持一致。
go 1.26.9

require (
	github.com/emmansun/gmsm v0.45.0
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/iuboy/pollux-go v0.5.2
	github.com/klauspost/compress v1.20.3
	github.com/oklog/ulid/v2 v2.1.2
	github.com/pierrec/lz4/v4 v4.1.33
	github.com/prometheus/client_golang v1.25.0
	github.com/prometheus/client_model v0.6.3
	github.com/quic-go/quic-go v0.64.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sync v0.24.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/common v0.72.1 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
