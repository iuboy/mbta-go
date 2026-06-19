// Package main demonstrates a minimal MBTA server that accepts agent connections
// and routes events through a custom EventSink.
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

// demoSink 是一个简单的 EventSink 实现，将接收到的信号打印到控制台。
type demoSink struct{}

func (d *demoSink) OnSignalBatch(_ context.Context, agentID string, batch *core.SignalBatch) error {
	for _, sig := range batch.Signals {
		fmt.Printf("[agent=%s] signal_type=%s body=%v\n", agentID, sig.SignalType, sig.Body)
	}
	return nil
}

func (d *demoSink) OnPressure(_ string) core.PressureState {
	return core.PressureNormal
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	sink := &demoSink{}

	server, err := mbtago.NewServer(
		mbtago.WithEventSink(sink),
		mbtago.WithAuth(core.NewStaticTokenValidator(map[string]string{
			"my-secret-token": "example-agent",
		})),
		mbtago.WithV1(v1.QUICServerConfig{
			Address:     "0.0.0.0:7400",
			Credentials: nil, // 生产环境应配置 TLS 证书
		}),
	)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}
	defer server.Close()

	fmt.Println("starting MBTA server on :7400...")
	if err := server.Start(ctx); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
