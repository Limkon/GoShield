// 文件路径: internal/compiler/generator.go
package compiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// BuildProtectedExe 核心构建调度
func BuildProtectedExe(encryptedData []byte, key []byte, outputExe string) error {
	stubDir := "./stub"
	payloadFile := filepath.Join(stubDir, "payload.go")

	// 1. 将加密数据和密钥格式化为 Go 源码文件
	// 使用 %#v 语法可以直接将 byte 切片格式化为合法的 Go 数组字面量
	payloadCode := fmt.Sprintf(`package main

var EncryptionKey = %#v
var EncryptedPayload = %#v
`, key, encryptedData)

	// 2. 写入 payload.go 到 stub 目录
	err := os.WriteFile(payloadFile, []byte(payloadCode), 0644)
	if err != nil {
		return fmt.Errorf("failed to write payload.go: %v", err)
	}

	// 确保编译结束后清理生成的临时源码，防止密钥泄露
	defer os.Remove(payloadFile)

	// 3. 调用 go build 编译 Stub 目录
	// -s -w：剥离符号表和调试信息，防逆向且极大减小体积
	// -H=windowsgui：隐藏黑框控制台窗口
	cmd := exec.Command("go", "build", "-ldflags", "-s -w -H=windowsgui", "-o", outputExe, stubDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("go build failed: %v", err)
	}

	return nil
}
