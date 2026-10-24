// Package main 演示一个最小的 MBTA 客户端：连接服务端并发送一批信号事件。
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
		// 证书用仓库脚本生成后引用（路径相对本示例目录，与 server 示例一致）：
		//   bash ../../test/data/certificates/gen_certs.sh
		// InsecureSkipVerify 仅限本地临时调试，绝不可用于生产——本示例用的是
		// CA 校验路径。
		mbtago.WithV1Credentials(v1.ClientCredentials{
			CAFile:     "../../test/data/certificates/ca.crt",
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
