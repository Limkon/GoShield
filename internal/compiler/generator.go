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
// 该模式不再依赖本机 Go 环境，通过直接拼接二进制数据实现加壳
func BuildProtectedExe(encryptedData []byte, key []byte, outputExe string) error {
	// 1. 创建并准备写入输出文件
	file, err := os.OpenFile(outputExe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("无法创建输出文件: %v", err)
	}
	defer file.Close()

	// 2. 写入基础外壳 (Stub Base)
	// 这是整个程序的头部，负责程序启动后的初始化和防御逻辑
	if _, err := file.Write(stubBase); err != nil {
		return fmt.Errorf("写入外壳基础数据失败: %v", err)
	}

	// 3. 写入加密后的 Payload 数据
	if _, err := file.Write(encryptedData); err != nil {
		return fmt.Errorf("写入加密核心数据失败: %v", err)
	}

	// 4. 写入 32 字节的 AES-GCM 密钥
	// 密钥固定放置在文件尾部标识符之前，方便 Stub 准确定位
	if len(key) != 32 {
		return fmt.Errorf("密钥长度错误: 期望 32 字节，实际 %d 字节", len(key))
	}
	if _, err := file.Write(key); err != nil {
		return fmt.Errorf("写入加密密钥失败: %v", err)
	}

	// 5. 写入 Payload 的长度 (uint64, 8 字节)
	// 使用小端序存储，Stub 程序将通过此长度计算读取偏移
	payloadSize := uint64(len(encryptedData))
	sizeBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBuf, payloadSize)
	if _, err := file.Write(sizeBuf); err != nil {
		return fmt.Errorf("写入长度元数据失败: %v", err)
	}

	// 6. 写入特征码 (Magic Bytes, 8 字节)
	// 用于 Stub 验证自身是否已被正确加壳及定位数据起始点
	magic := []byte("GOSHIELD")
	if _, err := file.Write(magic); err != nil {
		return fmt.Errorf("写入特征码失败: %v", err)
	}

	// 同步缓冲区到磁盘
	return file.Sync()
}
