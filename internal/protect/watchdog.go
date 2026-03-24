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
	procCreateEventW           = kernel32.NewProc("CreateEventW")
	procOpenEventW             = kernel32.NewProc("OpenEventW")
	procSetEvent               = kernel32.NewProc("SetEvent")
	procWaitForMultipleObjects = kernel32.NewProc("WaitForMultipleObjects")
)

const (
	EVENT_MODIFY_STATE       = 0x0002
	SYNCHRONIZE              = 0x00100000
	DETACHED_PROCESS         = 0x00000008
	CREATE_NEW_PROCESS_GROUP = 0x00000200
)

var normalExitEvent syscall.Handle
var isExiting bool

// StartWatchdog 启动双进程互斥守护机制
func StartWatchdog() {
	shadowPIDStr := os.Getenv("GOSHIELD_SHADOW_PID")

	if shadowPIDStr == "" {
		// ==== 主进程逻辑 ====
		myPID := os.Getpid()
		eventName := fmt.Sprintf("GoShield_Exit_%d", myPID)
		evPtr, _ := syscall.UTF16PtrFromString(eventName)

		// 1. 创建一个供主进程正常退出时触发的安全事件
		hEvent, _, _ := procCreateEventW.Call(0, 1, 0, uintptr(unsafe.Pointer(evPtr)))
		normalExitEvent = syscall.Handle(hEvent)

		// 2. 开启后台守护协程：紧盯影子进程
		go func() {
			exePath, _ := os.Executable()
			for {
				if isExiting {
					break
				}
				cmd := exec.Command(exePath)
				cmd.Env = append(os.Environ(), fmt.Sprintf("GOSHIELD_SHADOW_PID=%d", myPID))
				
				// 🌟 核心：脱离当前进程树！防止被 Win11 任务管理器“结束进程树”连坐带走
				cmd.SysProcAttr = &syscall.SysProcAttr{
					CreationFlags: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
				}
				
				_ = cmd.Start()
				if cmd.Process != nil {
					cmd.Wait() // 阻塞等待影子进程，如果影子被杀，循环会瞬间再次拉起它！
				}
			}
		}()
		return // 主进程继续往下执行 RunPE 等业务代码
		
	} else {
		// ==== 影子进程逻辑 ====
		mainPID, _ := strconv.Atoi(shadowPIDStr)

		// 1. 获取主进程句柄
		mainHandle, _, _ := procOpenProcess.Call(uintptr(SYNCHRONIZE), 0, uintptr(mainPID))
		if mainHandle == 0 {
			restartMainAndExit() // 句柄都拿不到说明主进程已经被秒了，直接复活它
		}

		// 2. 获取主进程的安全退出事件句柄
		eventName := fmt.Sprintf("GoShield_Exit_%d", mainPID)
		evPtr, _ := syscall.UTF16PtrFromString(eventName)
		hEvent, _, _ := procOpenEventW.Call(uintptr(SYNCHRONIZE|EVENT_MODIFY_STATE), 0, uintptr(unsafe.Pointer(evPtr)))
		if hEvent == 0 {
			restartMainAndExit()
		}

		handles := []syscall.Handle{syscall.Handle(mainHandle), syscall.Handle(hEvent)}

		// 3. 🌟 核心死锁监听：[0]为主进程生死状态，[1]为安全退出信号
		ret, _, _ := procWaitForMultipleObjects.Call(
			2,
			uintptr(unsafe.Pointer(&handles[0])),
			0,          // 任意一个有信号就触发
			0xFFFFFFFF, // INFINITE 无限期死等
		)

		if ret == 0 {
			// 如果是 [0] 触发了，说明主进程死了，而且安全事件没发信号 => 遭遇强杀！立刻拉起主进程！
			restartMainAndExit()
		} else {
			// 如果是 [1] 触发了，说明业务代码正常走完了 => 功成身退，和平解散
			os.Exit(0)
		}
	}
}

// restartMainAndExit 影子拉起主进程
func restartMainAndExit() {
	exePath, _ := os.Executable()
	cmd := exec.Command(exePath)

	// 清洗环境变量，让新拉起的程序作为“主进程”身份复活
	var newEnv []string
	for _, env := range os.Environ() {
		if len(env) > 20 && env[:20] == "GOSHIELD_SHADOW_PID=" {
			continue
		}
		newEnv = append(newEnv, env)
	}
	cmd.Env = newEnv
	
	// 拉起主进程也要脱离进程树
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
	}
	_ = cmd.Start()
	os.Exit(0) // 自己死掉，把舞台交给新的主进程去创建新的影子
}

// NotifyNormalExit 通知影子进程解除警报，准备一起正常退出
func NotifyNormalExit() {
	isExiting = true
	if normalExitEvent != 0 {
		procSetEvent.Call(uintptr(normalExitEvent))
	}
}
