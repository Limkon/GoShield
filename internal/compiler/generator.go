// 文件路径: internal/compiler/generator.go
package compiler

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"os"
)

// 使用 go:embed 将预编译的外壳程序嵌入到加壳机中
// 注意：在 GitHub Actions 构建或本地构建加壳机前，需先编译 stub 产出此文件
//go:embed stub_base.exe
var stubBase []byte

// BuildProtectedExe 核心构建调度 (Overlay 附加注入模式)
func BuildProtectedExe(originalExe string, encryptedData []byte, key []byte, outputExe string) error {
	// 1. 将基础外壳释放为临时文件
	// 为了防止 Windows API 破坏 Overlay 尾部数据，必须在拼装加密数据前注入图标
	tmpExe := outputExe + ".tmp"
	if err := os.WriteFile(tmpExe, stubBase, 0755); err != nil {
		return fmt.Errorf("释放临时外壳失败: %v", err)
	}
	defer os.Remove(tmpExe) // 处理完后自动销毁

	// 2. 自动化注入图标：从原程序完美克隆到临时外壳
	CloneIcon(originalExe, tmpExe)

	// 3. 重新读取已经注入好图标的新外壳数据
	newStubBase, err := os.ReadFile(tmpExe)
	if err != nil {
		return fmt.Errorf("读取注入图标后的外壳失败: %v", err)
	}

	// 4. 创建并准备写入最终输出文件
	file, err := os.OpenFile(outputExe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("无法创建输出文件: %v", err)
	}
	defer file.Close()

	// 5. 写入带原程序图标的外壳 (Stub Base)
	if _, err := file.Write(newStubBase); err != nil {
		return fmt.Errorf("写入外壳基础数据失败: %v", err)
	}

	// 6. 写入加密后的 Payload 数据
	if _, err := file.Write(encryptedData); err != nil {
		return fmt.Errorf("写入加密核心数据失败: %v", err)
	}

	// 7. 写入 32 字节的 AES-GCM 密钥
	if len(key) != 32 {
		return fmt.Errorf("密钥长度错误: 期望 32 字节，实际 %d 字节", len(key))
	}
	if _, err := file.Write(key); err != nil {
		return fmt.Errorf("写入加密密钥失败: %v", err)
	}

	// 8. 写入 Payload 的长度 (uint64, 8 字节)
	payloadSize := uint64(len(encryptedData))
	sizeBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBuf, payloadSize)
	if _, err := file.Write(sizeBuf); err != nil {
		return fmt.Errorf("写入长度元数据失败: %v", err)
	}

	// 9. 写入特征码 (Magic Bytes, 8 字节)
	magic := []byte("GOSHIELD")
	if _, err := file.Write(magic); err != nil {
		return fmt.Errorf("写入特征码失败: %v", err)
	}

	// 同步缓冲区到磁盘
	return file.Sync()
}
