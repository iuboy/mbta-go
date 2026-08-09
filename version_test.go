package mbta

import (
	"testing"
)

// TestParseVersion 覆盖 ParseVersion 的已知版本映射与未知版本错误。
// 用于从配置文件/环境变量读取 string 场景的运行时转换。
func TestParseVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    ProtocolVersion
		wantErr bool
	}{
		{"v1", Version1, false},
		{"v2", "", true}, // A2：v2 已删除，现在返回 error
		{"ntls", VersionNTLS, false},
		{"", "", true},
		{"V1", "", true},   // 大小写敏感
		{"v3", "", true},   // 不存在
		{"v11", "", true},  // 拼写错误
		{" tls", "", true}, // 前缀不匹配
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseVersion(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseVersion(%q) expected error, got %v", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseVersion(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
