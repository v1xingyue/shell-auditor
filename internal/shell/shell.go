package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/cevin/shell-auditor/internal/audit"
)

// Shell 交互式shell
type Shell struct {
	auditor    *audit.Auditor
	uid        int
	gid        int
	username   string
	homeDir    string
	workingDir string
	history    []string
	historyIdx int
	mu         sync.Mutex
}

// NewShell 创建新的shell实例
func NewShell(auditor *audit.Auditor) (*Shell, error) {
	uid := os.Getuid()
	gid := os.Getgid()
	username := getUsername(uid)
	homeDir, _ := os.UserHomeDir()
	workingDir, _ := os.Getwd()

	return &Shell{
		auditor:    auditor,
		uid:        uid,
		gid:        gid,
		username:   username,
		homeDir:    homeDir,
		workingDir: workingDir,
		history:    make([]string, 0, 1000),
	}, nil
}

// Run 运行shell
func (s *Shell) Run() error {
	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 打印欢迎信息
	s.printWelcome()

	// 主循环
	reader := bufio.NewReader(os.Stdin)
	for {
		// 显示提示符
		prompt := s.buildPrompt()
		fmt.Print(prompt)

		// 读取输入
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println()
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		// 去除空白
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 处理命令
		if err := s.handleCommand(line); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	}
}

// printWelcome 打印欢迎信息
func (s *Shell) printWelcome() {
	fmt.Printf("\n")
	fmt.Printf("╔════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║           Shell Auditor - 安全审计 Shell                    ║\n")
	fmt.Printf("║           所有操作将被记录和审计                             ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
}

// buildPrompt 构建提示符
func (s *Shell) buildPrompt() string {
	s.mu.Lock()
	wd := s.workingDir
	s.mu.Unlock()

	// 简化路径显示
	if strings.HasPrefix(wd, s.homeDir) {
		wd = "~" + wd[len(s.homeDir):]
	}

	// 根据用户显示不同颜色
	if s.uid == 0 {
		return fmt.Sprintf("\033[31m%s@%s:%s#\033[0m ", s.username, getHostname(), wd)
	}
	return fmt.Sprintf("\033[32m%s@%s:%s$\033[0m ", s.username, getHostname(), wd)
}

// handleCommand 处理命令
func (s *Shell) handleCommand(line string) error {
	// 添加到历史记录
	s.addToHistory(line)

	// 解析命令
	parts := parseCommand(line)
	if len(parts) == 0 {
		return nil
	}

	cmdName := parts[0]
	args := parts[1:]

	// 处理内置命令
	if s.isBuiltinCommand(cmdName) {
		return s.handleBuiltinCommand(cmdName, args)
	}

	// 执行外部命令
	return s.executeCommand(cmdName, args)
}

// isBuiltinCommand 检查是否为内置命令
func (s *Shell) isBuiltinCommand(cmd string) bool {
	builtins := map[string]bool{
		"cd":      true,
		"exit":    true,
		"logout":  true,
		"clear":   true,
		"history": true,
		"pwd":     true,
		"export":  true,
		"unset":   true,
		"alias":   true,
		"audit":   true,
	}
	return builtins[cmd]
}

// handleBuiltinCommand 处理内置命令
func (s *Shell) handleBuiltinCommand(cmd string, args []string) error {
	switch cmd {
	case "cd":
		return s.handleCD(args)
	case "exit", "logout":
		os.Exit(0)
	case "clear":
		fmt.Print("\033[H\033[2J")
		return nil
	case "history":
		return s.handleHistory(args)
	case "pwd":
		fmt.Println(s.workingDir)
		return nil
	case "export":
		return s.handleExport(args)
	case "audit":
		return s.handleAudit(args)
	default:
		return fmt.Errorf("builtin command not implemented: %s", cmd)
	}
	return nil
}

// handleCD 处理cd命令
func (s *Shell) handleCD(args []string) error {
	var target string
	if len(args) == 0 {
		target = s.homeDir
	} else {
		target = args[0]
	}

	// 处理 ~
	if strings.HasPrefix(target, "~") {
		target = filepath.Join(s.homeDir, target[1:])
	}

	// 处理相对路径
	if !filepath.IsAbs(target) {
		target = filepath.Join(s.workingDir, target)
	}

	// 规范化路径
	target = filepath.Clean(target)

	// 检查目录是否存在
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cd: %s: %w", target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cd: %s: Not a directory", target)
	}

	s.mu.Lock()
	s.workingDir = target
	s.mu.Unlock()

	return nil
}

// handleHistory 处理history命令
func (s *Shell) handleHistory(args []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, cmd := range s.history {
		fmt.Printf("  %4d  %s\n", i+1, cmd)
	}
	return nil
}

// handleExport 处理export命令
func (s *Shell) handleExport(args []string) error {
	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			os.Setenv(parts[0], parts[1])
		}
	}
	return nil
}

// handleAudit 处理audit命令
func (s *Shell) handleAudit(args []string) error {
	if len(args) == 0 {
		// 显示最近的审计事件
		events := s.auditor.GetEvents()
		fmt.Printf("\n=== 最近 %d 条审计事件 ===\n\n", len(events))
		for _, e := range events {
			data, _ := e.ToJSON()
			fmt.Println(string(data))
		}
		return nil
	}

	switch args[0] {
	case "clear":
		// 清空审计日志
		fmt.Println("审计日志已清空")
		return nil
	case "pid":
		if len(args) < 2 {
			return fmt.Errorf("usage: audit pid <pid>")
		}
		var pid int
		fmt.Sscanf(args[1], "%d", &pid)
		events := s.auditor.GetEventsByPID(pid)
		fmt.Printf("\n=== PID %d 的审计事件 ===\n\n", pid)
		for _, e := range events {
			data, _ := e.ToJSON()
			fmt.Println(string(data))
		}
		return nil
	default:
		return fmt.Errorf("unknown audit command: %s", args[0])
	}
}

// executeCommand 执行外部命令
func (s *Shell) executeCommand(name string, args []string) error {
	// 查找命令路径
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s: command not found", name)
	}

	// 记录命令执行
	s.auditor.LogCommand(
		os.Getpid(),
		os.Getppid(),
		s.uid,
		s.gid,
		s.username,
		name,
		args,
		s.workingDir,
	)

	// 创建命令
	cmd := exec.Command(path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = s.workingDir
	cmd.Env = os.Environ()

	// 执行命令
	err = cmd.Run()

	// 记录退出码
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	s.auditor.LogCommandExit(os.Getpid(), exitCode)

	return nil
}

// addToHistory 添加到历史记录
func (s *Shell) addToHistory(cmd string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 避免重复
	if len(s.history) > 0 && s.history[len(s.history)-1] == cmd {
		return
	}

	s.history = append(s.history, cmd)
	s.historyIdx = len(s.history)

	// 限制历史记录数量
	if len(s.history) > 1000 {
		s.history = s.history[1:]
	}
}

// parseCommand 解析命令
func parseCommand(line string) []string {
	var parts []string
	var current strings.Builder
	var inQuote bool
	var quoteChar rune

	for _, r := range line {
		switch {
		case (r == '\'' || r == '"') && !inQuote:
			inQuote = true
			quoteChar = r
		case r == quoteChar && inQuote:
			inQuote = false
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// getUsername 获取用户名
func getUsername(uid int) string {
	return os.Getenv("USER")
}

// getHostname 获取主机名
func getHostname() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		return "localhost"
	}
	return hostname
}