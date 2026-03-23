// 文件路径: internal/compiler/generator.go
package compiler

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"os"
)

//go:embed stub_base.exe
var stubBase []byte

// BuildProtectedExe 核心构建调度 (Overlay 附加注入模式)
func BuildProtectedExe(encryptedData []byte, key []byte, outputExe string) error {
	// 1. 创建输出文件
	file, err := os.OpenFile(outputExe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("无法创建输出文件: %v", err)
	}
	defer file.Close()

	// 2. 写入预编译的基础外壳代码 (stub_base.exe)
	if _, err := file.Write(stubBase); err != nil {
		return fmt.Errorf("写入外壳基础失败: %v", err)
	}

	// 3. 附加写入加密的 Payload
	if _, err := file.Write(encryptedData); err != nil {
		return fmt.Errorf("写入加密核心失败: %v", err)
	}

	// 4. 附加写入 32 字节的 AES 密钥
	if len(key) != 32 {
		return fmt.Errorf("密钥长度异常，必须为 32 字节")
	}
	if _, err := file.Write(key); err != nil {
		return fmt.Errorf("写入密钥失败: %v", err)
	}

	// 5. 附加写入 Payload 长度 (转换为 8 字节的小端序 uint64)
	payloadSize := uint64(len(encryptedData))
	sizeBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBuf, payloadSize)
	if _, err := file.Write(sizeBuf); err != nil {
		return fmt.Errorf("写入长度信息失败: %v", err)
	}

	// 6. 附加写入特征码 (8 字节 Magic Bytes)
	magic := []byte("GOSHIELD")
	if _, err := file.Write(magic); err != nil {
		return fmt.Errorf("写入特征码失败: %v", err)
	}

	return nil
}
