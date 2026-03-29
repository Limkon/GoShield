// 文件路径: internal/crypto/aesgcm.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// ChunkSize 定义流式加密的单块大小 (4MB)
// 完美平衡加密性能与内存占用，解决超大文件 OOM 问题
const ChunkSize = 4 * 1024 * 1024 

// GenerateRandomKey 生成 32 字节 (256-bit) 的 AES 密钥
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptStream 使用 AES-GCM 进行流式分块加密
// 从 Reader 读取明文，加密后持续写入 Writer
func EncryptStream(r io.Reader, w io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buf := make([]byte, ChunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			nonce := make([]byte, aesgcm.NonceSize())
			if _, randErr := io.ReadFull(rand.Reader, nonce); randErr != nil {
				return randErr
			}

			// 1. 写入 12字节 的 Nonce
			if _, wErr := w.Write(nonce); wErr != nil {
				return wErr
			}

			// 2. 执行当前分块加密
			ciphertext := aesgcm.Seal(nil, nonce, buf[:n], nil)

			// 3. 写入 4字节 的密文长度 (小端序)
			lenBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
			if _, wErr := w.Write(lenBuf); wErr != nil {
				return wErr
			}

			// 4. 写入密文数据本身
			if _, wErr := w.Write(ciphertext); wErr != nil {
				return wErr
			}
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream 使用 AES-GCM 进行流式分块解密
// 从 Reader 读取分块密文，解密后持续写入 Writer
func DecryptStream(r io.Reader, w io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	lenBuf := make([]byte, 4)

	for {
		// 1. 读取 Nonce
		_, err := io.ReadFull(r, nonce)
		if err == io.EOF {
			break // 正常结束，所有块解密完毕
		}
		if err != nil {
			return fmt.Errorf("读取 Nonce 失败: %v", err)
		}

		// 2. 读取当前块的密文长度
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return fmt.Errorf("读取密文块长度失败: %v", err)
		}
		chunkLen := binary.LittleEndian.Uint32(lenBuf)

		// 安全防御校验：单块长度绝对不能超过 ChunkSize + MAC 长度 (防止恶意构造导致 OOM 攻击)
		if chunkLen > uint32(ChunkSize+aesgcm.Overhead()) {
			return fmt.Errorf("拦截到异常的加密块长度，数据可能被非法篡改")
		}

		// 3. 读取当前块的完整密文
		chunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return fmt.Errorf("读取密文块数据失败: %v", err)
		}

		// 4. 🌟 极客优化：使用 chunk[:0] 进行底层重叠复用 (In-place Decryption)
		// 不分配新的内存，直接在原密文地址上覆盖写入明文，榨干性能
		plaintext, err := aesgcm.Open(chunk[:0], nonce, chunk, nil)
		if err != nil {
			return fmt.Errorf("解密分块失败 (密码错误或数据受损): %v", err)
		}

		// 5. 写入解密后的明文
		if _, err := w.Write(plaintext); err != nil {
			return err
		}
	}
	return nil
}
