//go:build integration

// perf_export_test.go 提供性能基准测试的结构化 JSON 报告导出。
//
// perf test（TestPerf_*）跑完调用 writePerfReport，把各环节延迟/吞吐 + 环境信息
// 写入 test/results/perf-<timestamp>.json。CI 可归档、跨 commit 对比、绘图。
// 自包含，不依赖 benchstat 等外部工具。

package mbta_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// PerfReport 是性能基准报告的顶层结构，序列化为 JSON。
type PerfReport struct {
	Timestamp  string         `json:"timestamp"`  // RFC3339，报告生成时刻
	GoVersion  string         `json:"go_version"` // runtime.Version()
	GOOS       string         `json:"goos"`
	GOARCH     string         `json:"goarch"`
	NumCPU     int            `json:"num_cpu"`
	E2E        E2EMetrics     `json:"e2e"`                   // 端到端各环节延迟分解
	Stages     []StageMetric  `json:"stages"`                // 核心环节级延迟（cipher/envelope/negotiate）
	LargeBatch *LargeBatchRow `json:"large_batch,omitempty"` // 大 batch 吞吐（可选）
}

// E2EMetrics 是端到端各环节的延迟与吞吐。
type E2EMetrics struct {
	HandshakeMs     float64 `json:"handshake_ms"`      // 握手（NewClient+Connect）
	ColdSendMs      float64 `json:"cold_send_ms"`      // 首次 SendBatch（冷启动）
	SteadySendUs    float64 `json:"steady_send_us"`    // 稳态 SendBatch 平均（含 ACK 往返）
	CloseMs         float64 `json:"close_ms"`          // Close（drain）
	BatchPerSec     float64 `json:"batch_per_sec"`     // 稳态 batch 吞吐
	PayloadBytesPS  float64 `json:"payload_bytes_ps"`  // 稳态 payload 吞吐（bytes/s）
	PayloadPerBatch int     `json:"payload_per_batch"` // 每 batch payload 字节数
}

// StageMetric 是单个核心环节的延迟度量（如 HMAC-INTL、EnvelopeBuild-GM-4KB）。
type StageMetric struct {
	Name        string  `json:"name"`                    // 环节名（如 "EnvelopeBuild/INTL_4KB"）
	NsPerOp     float64 `json:"ns_per_op"`               // 每次操作纳秒
	MBPerSec    float64 `json:"mb_per_sec"`              // 吞吐（0 = 该环节不适用 bytes/sec）
	AllocsPerOp float64 `json:"allocs_per_op,omitempty"` // 每次 op 分配数（可选）
}

// LargeBatchRow 是大 batch 端到端吞吐的度量。
type LargeBatchRow struct {
	EventsPerBatch int     `json:"events_per_batch"`
	BodyBytes      int     `json:"body_bytes"`
	NBatches       int     `json:"n_batches"`
	ThroughputMBps float64 `json:"throughput_mb_ps"` // MB/s
	BatchPerSec    float64 `json:"batch_per_sec"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}

// writePerfReport 把报告写入 test/results/perf-<timestamp>.json。
// 文件名带毫秒时间戳避免覆盖；返回写入路径（供 t.Logf 输出）。
func writePerfReport(r PerfReport) (string, error) {
	r.Timestamp = time.Now().Format(time.RFC3339)
	r.GoVersion = runtime.Version()
	r.GOOS = runtime.GOOS
	r.GOARCH = runtime.GOARCH
	r.NumCPU = runtime.NumCPU()

	resultsDir := filepath.Join("results")
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir results: %w", err)
	}
	// 文件名用可排序的紧凑时间戳（20060102-150405）。
	name := fmt.Sprintf("perf-%s.json", time.Now().Format("20060102-150405"))
	path := filepath.Join(resultsDir, name)

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}
