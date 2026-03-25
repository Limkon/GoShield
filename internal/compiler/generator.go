// 文件路径: internal/compiler/generator.go
package compiler

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// 使用 go:embed 将预编译的外壳程序嵌入到加壳机中
// 注意：在 GitHub Actions 构建或本地构建加壳机前，需先编译 stub 产出此文件
//go:embed stub_base.exe
var stubBase []byte

// BuildProtectedExe 核心构建调度 (Overlay 附加注入模式)
func BuildProtectedExe(originalExe string, encryptedData []byte, key []byte, outputExe string) error {
	// 🌟 修复：校验 stubBase 是否合法
	// PE 文件通常远大于 1KB，0 字节或过小则说明 stub 前置编译失败
	if len(stubBase) < 1024 {
		return errors.New("内置外壳 (stub_base.exe) 无效或损坏，请重新编译项目！")
	}

	// 🌟 修复：使用更安全的系统临时文件机制，防止目录权限问题或并发构建冲突
	tmpFile, err := os.CreateTemp("", "goshield_stub_*.exe")
	if err != nil {
		return fmt.Errorf("无法创建临时外壳文件: %v", err)
	}
	tmpExe := tmpFile.Name()
	
	// 写入基础外壳数据
	if _, err := tmpFile.Write(stubBase); err != nil {
		tmpFile.Close()
		os.Remove(tmpExe)
		return fmt.Errorf("释放临时外壳失败: %v", err)
	}
	
	// 🌟 修复：必须显式关闭文件句柄解除系统占用锁，否则后续图标注入和重新读取会报错
	tmpFile.Close() 

	defer os.Remove(tmpExe) // 处理完后自动销毁系统临时文件

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
