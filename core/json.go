package core

import "github.com/bytedance/sonic"

// FastMarshal / FastUnmarshal 用 sonic 序列化（热路径）。
//
// sonic 用 asm/编译期优化消除反射开销：marshal allocs 显著下降、unmarshal 耗时大幅下降。
// 默认配置产出的 JSON 可被 encoding/json 正常 Unmarshal（两端兼容），server 端无需改动。
//
// 注意：sonic 默认不做 HTML escape（标准库 json.Marshal 默认会转义 < >& ）。
// 对 MBTA 协议无影响——wire 上的 JSON 由 server 的 json.Unmarshal 解析，< 与 <
// 等价；且 HMAC 签名作用于 base64 后的 payload，不直接 hash 原始 JSON 字节。
//
// 平台：amd64 / arm64（含 Apple Silicon）；其他平台 sonic 自动回退纯 Go 实现。
func FastMarshal(v any) ([]byte, error)   { return sonic.Marshal(v) }
func FastUnmarshal(b []byte, v any) error { return sonic.Unmarshal(b, v) }
