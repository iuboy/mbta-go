package v1

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// Spool Put 规模压测：验证增量计数后，Put 的尾部延迟与已存 record 数无关（O(1)）。
// 用 buffered 模式（flushInterval 长）隔离掉刷盘 IO，只测内存 Put + curSize 增量路径。
// 优化前（旧 estimatedSize 每次 O(n) 全表遍历），ns/op 会随 records 线性增长。

func BenchmarkSpool_PutScale(b *testing.B) {
	for _, n := range []int{10_000, 100_000, 500_000} {
		b.Run(scaleName(n), func(b *testing.B) {
			dir := b.TempDir()
			s, err := New(dir, WithFlushInterval(time.Hour), WithMaxSize(0)) // buffered + 禁用大小上限，避免 bench 累计写入触发拒绝
			if err != nil {
				b.Fatal(err)
			}
			// 预填充 n 条，建立规模基线。
			for i := 0; i < n; i++ {
				if err := s.Put(Record{RecordID: strconv.Itoa(i), AgentID: "a"}); err != nil {
					b.Fatal(err)
				}
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := s.Put(Record{RecordID: fmt.Sprintf("n%d", i), AgentID: "a"}); err != nil {
					b.Fatal(err)
				}
			}

			b.StopTimer()
			// Close 会全量 flush；不计入压测计时。
			_ = s.Close()
		})
	}
}

func scaleName(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%dM", n/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%dk", n/1_000)
	default:
		return strconv.Itoa(n)
	}
}
