// Package main demonstrates a minimal MBTA server that accepts agent connections
// and delivers event batches to a registered BatchHandler.
package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"
)

// demoHandler 打印收到的 signal 到控制台（core.BatchHandler 注册式投递面）。
// accepted-only 模式下 done 无 wire 效果，但仍按契约调用以保持幂等语义。
func demoHandler(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
	if ev.Decoded != nil {
		for _, sig := range ev.Decoded.Signals {
			fmt.Printf("[agent=%s] signal_type=%s body=%v\n", ev.Agent, sig.SignalType, sig.Body)
		}
	}
	done(core.Outcome{Level: core.OutcomeAccepted})
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	server, err := mbtago.NewServer(
		// SinkOptions{} 默认逐事件解码供给（Decoded 非 nil）；需要原始字节供给时
		// 置 Raw=true，需要持久化确认时置 Durable=true（配合 policy ack_mode=durable）。
		mbtago.WithSink(core.SinkOptions{}, demoHandler),
		mbtago.WithAuth(core.NewStaticTokenValidator(map[string]string{
			"my-secret-token": "example-agent",
		})),
		mbtago.WithV1(v1.QUICServerConfig{
			Address: "0.0.0.0:7400",
			Credentials: &v1.ServerCredentials{
				CertFile: "../../test/data/certificates/server.crt",
				KeyFile:  "../../test/data/certificates/server.key",
			},
		}),
	)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}
	defer server.Close()

	fmt.Println("starting MBTA server on :7400...")
	if err := server.Start(ctx); err != nil {
		server.Close() // 确保 listener/goroutine 清理后再 Fatal（log.Fatalf 会 os.Exit 跳过 defer）
		log.Fatalf("server error: %v", err)
	}
}
