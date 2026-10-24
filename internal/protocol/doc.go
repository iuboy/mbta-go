// Package protocol 承载 MBTA 服务端/客户端的共享协议核心（r3 重设计）：
// CoreHandler/CoreClient 状态机、credit 守恒（模型 B）、RESULT/CREDIT 处理、
// 运维命令通道。仅依赖 core 与 Transport 接口，不感知 quic.Stream/net.Conn。
package protocol
