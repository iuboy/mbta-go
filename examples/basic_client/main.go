// Package main demonstrates a minimal MBTA client that connects to a server
// and sends a batch of signal events.
package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client, err := mbtago.NewClient(
		mbtago.WithServer("localhost:7400"),
		mbtago.WithAgent("example-agent", "localhost", "my-secret-token"),
		mbtago.WithV1Credentials(v1.ClientCredentials{
			InsecureSkipVerify: true, // 仅用于开发环境
		}),
	)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// 连接服务端
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}
	fmt.Println("connected to MBTA server")

	// 构造信号批次
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{
				SignalType:     "log",
				TimeUnixMs:     time.Now().UnixMilli(),
				SeverityText:   "INFO",
				SeverityNumber: 9,
				Body:           "hello from mbta-go client example",
				Attributes:     map[string]any{"service": "example"},
			},
		},
	}

	// 发送批次
	chunkID, err := client.SendBatch(ctx, batch, "example", "demo")
	if err != nil {
		log.Fatalf("send batch: %v", err)
	}
	fmt.Printf("batch sent, chunk_id=%s\n", chunkID)
}
