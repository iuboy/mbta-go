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
		mbtago.WithAgent("example-agent", "my-secret-token"),
		// 生产路径：加载服务端 CA 做证书校验（ServerName 与证书 SAN 匹配）。
		// CA 文件可用仓库内脚本生成：bash test/data/certificates/gen_certs.sh
		//（服务端需用同一 CA 签发的 server.crt/server.key）。
		// InsecureSkipVerify 仅限本地临时调试，绝不可用于生产。
		mbtago.WithV1Credentials(v1.ClientCredentials{
			CAFile:     "ca.crt",
			ServerName: "localhost",
		}),
	)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// 注册 RESULT 回调：seq 与 SendBatch 返回值对账（level=accepted/durable/...）。
	client.SetResultHandler(func(seq uint64, level string, code uint32, correlation string) {
		fmt.Printf("batch seq=%d result=%s code=%d\n", seq, level, code)
	})

	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}
	fmt.Println("connected to MBTA server")

	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{
				SignalType:     "log",
				TimeUnixNs:     time.Now().UnixNano(),
				SeverityText:   "INFO",
				SeverityNumber: 9,
				Body:           "hello from mbta-go client example",
				Attributes:     map[string]any{"service": "example"},
			},
		},
	}

	seq, err := client.SendBatch(ctx, batch)
	if err != nil {
		log.Fatalf("send batch: %v", err)
	}
	fmt.Printf("batch sent, seq=%d\n", seq)
}
