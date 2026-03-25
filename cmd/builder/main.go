// 文件路径: cmd/builder/main.go
package main

import (
	"fmt"
	"os"

	"github.com/Limkon/GoShield/internal/compiler"
	"github.com/Limkon/GoShield/internal/crypto"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative" // 引入声明式 UI 语法
)

// appendLog 线程安全地向文本框中追加日志
func appendLog(logTE *walk.TextEdit, msg string) {
	logTE.Synchronize(func() {
		logTE.AppendText(msg + "\r\n")
	})
}

func main() {
	var mw *walk.MainWindow
	var inTE, outTE, pwdTE, confirmPwdTE *walk.LineEdit
	var exitPwdTE, confirmExitPwdTE *walk.LineEdit // 🌟 新增：退出密码与确认退出密码输入框
	var rememberCB *walk.CheckBox
	var logTE *walk.TextEdit
	var pb *walk.ProgressBar
	var runBtn *walk.PushButton

	err := MainWindow{
		AssignTo: &mw,
		Title:    "GoShield",
		MinSize:  Size{Width: 300, Height: 380}, // 🌟 调高高度以适应新增的密码框
		Size:     Size{Width: 600, Height: 380},
		Layout:   VBox{},
		Children: []Widget{
			GroupBox{
				Title:  "目标文件配置",
				Layout: Grid{Columns: 3},
				Children: []Widget{
					Label{Text: "原始程序:"},
					LineEdit{AssignTo: &inTE, ReadOnly: true},
					PushButton{
						Text: "浏览...",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*"
							dlg.Title = "选择需要加壳保护的 EXE"
							if ok, _ := dlg.ShowOpen(mw); ok {
								inTE.SetText(dlg.FilePath)
								outTE.SetText(dlg.FilePath[:len(dlg.FilePath)-4] + "_protected.exe")
							}
						},
					},

					Label{Text: "输出路径:"},
					LineEdit{AssignTo: &outTE},
					PushButton{
						Text: "浏览...",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Filter = "可执行文件 (*.exe)|*.exe"
							dlg.Title = "保存保护后的 EXE"
							if ok, _ := dlg.ShowSave(mw); ok {
								outTE.SetText(dlg.FilePath)
							}
						},
					},

					// 启动密码保护选项配置区
					Label{Text: "启动密码:"},
					LineEdit{AssignTo: &pwdTE, PasswordMode: true},
					CheckBox{
						AssignTo: &rememberCB, 
						Text: "免密缓存",
						Checked: true, 
					},

					Label{Text: "确认启动:"},
					LineEdit{AssignTo: &confirmPwdTE, PasswordMode: true},
					Label{Text: "(留空则无启动密码)"}, // 提示占位符

					// 🌟 新增：退出密码保护配置区
					Label{Text: "退出密码:"},
					LineEdit{AssignTo: &exitPwdTE, PasswordMode: true},
					Label{Text: ""}, // 留空占位，保持 Grid 三列对齐

					Label{Text: "确认退出:"},
					LineEdit{AssignTo: &confirmExitPwdTE, PasswordMode: true},
					Label{Text: "(留空则无退出密码)"}, // 提示占位符
				},
			},
			Label{Text: "加壳与混淆进度:"},
			ProgressBar{
				AssignTo: &pb,
				MinValue: 0,
				MaxValue: 100,
			},
			TextEdit{
				AssignTo: &logTE,
				ReadOnly: true,
				VScroll:  true,
			},
			PushButton{
				AssignTo: &runBtn,
				Text:     "⚡ 开始加壳保护",
				OnClicked: func() {
					inFile := inTE.Text()
					outFile := outTE.Text()
					password := pwdTE.Text()
					confirmPassword := confirmPwdTE.Text()
					exitPassword := exitPwdTE.Text()               // 获取退出密码
					confirmExitPassword := confirmExitPwdTE.Text() // 获取确认退出密码
					rememberPwd := rememberCB.Checked()

					if inFile == "" || outFile == "" {
						walk.MsgBox(mw, "错误", "请先选择输入和输出文件路径！", walk.MsgBoxIconError)
						return
					}

					// 严谨的二次密码核对逻辑：启动密码
					if password != confirmPassword {
						walk.MsgBox(mw, "错误", "两次输入的启动密码不一致，请重新输入！", walk.MsgBoxIconError)
						pwdTE.SetText("")
						confirmPwdTE.SetText("")
						return
					}

					// 🌟 新增：严谨的二次密码核对逻辑：退出密码
					if exitPassword != confirmExitPassword {
						walk.MsgBox(mw, "错误", "两次输入的退出密码不一致，请重新输入！", walk.MsgBoxIconError)
						exitPwdTE.SetText("")
						confirmExitPwdTE.SetText("")
						return
					}

					fileInfo, err := os.Stat(inFile)
					if err != nil {
						walk.MsgBox(mw, "错误", "无法读取输入文件状态！", walk.MsgBoxIconError)
						return
					}
					if fileInfo.Size() > 500*1024*1024 {
						walk.MsgBox(mw, "警告", "目标文件过大（超过 500MB），一次性载入内存可能导致崩溃，请重新选择！", walk.MsgBoxIconWarning)
						return
					}

					runBtn.SetEnabled(false)
					logTE.SetText("")
					pb.SetValue(0)

					go func() {
						defer mw.Synchronize(func() { runBtn.SetEnabled(true) })

						appendLog(logTE, "[*] 读取原始可执行文件...")
						mw.Synchronize(func() { pb.SetValue(10) })
						plaintext, err := os.ReadFile(inFile)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						appendLog(logTE, "[*] 动态生成 256-bit AES 混淆密钥...")
						mw.Synchronize(func() { pb.SetValue(30) })
						key, err := crypto.GenerateRandomKey()
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						appendLog(logTE, "[*] 执行 AES-GCM 高级加密引擎...")
						mw.Synchronize(func() { pb.SetValue(50) })
						ciphertext, err := crypto.Encrypt(plaintext, key)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						appendLog(logTE, "[*] 正在执行无损图标注入与预编译壳拼接...")
						mw.Synchronize(func() { pb.SetValue(70) })
						
						// 🌟 修改：传入新增的 exitPassword 参数
						err = compiler.BuildProtectedExe(inFile, ciphertext, key, password, exitPassword, rememberPwd, outFile)
						if err != nil {
							appendLog(logTE, fmt.Sprintf("[-] 编译失败: %v", err))
							mw.Synchronize(func() { pb.SetValue(0) })
							return
						}

						mw.Synchronize(func() { pb.SetValue(100) })
						appendLog(logTE, fmt.Sprintf("[+] 加壳成功！\r\n[+] 带壳程序已安全保存至: %s", outFile))
						
						mw.Synchronize(func() {
							walk.MsgBox(mw, "成功", "程序加壳与底层保护植入完成！\n原程序图标已完美继承，您可以测试运行了。", walk.MsgBoxIconInformation)
						})
					}()
				},
			},
		},
	}.Create()

	if err != nil {
		os.Exit(1)
	}

	mw.Run()
}
