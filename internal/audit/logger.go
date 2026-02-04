package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileLogger 文件日志记录器
type FileLogger struct {
	filePath string
	file     *os.File
	mu       sync.Mutex
}

// NewFileLogger 创建文件日志记录器
func NewFileLogger(filePath string) (*FileLogger, error) {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 打开文件（追加模式）
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &FileLogger{
		filePath: filePath,
		file:     file,
	}, nil
}

// Log 记录事件
func (l *FileLogger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// 写入JSON行
	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return err
	}

	return l.file.Sync()
}

// Close 关闭日志记录器
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// RotatingLogger 支持日志轮转的日志记录器
type RotatingLogger struct {
	basePath    string
	maxSize     int64
	currentSize int64
	currentFile *os.File
	mu          sync.Mutex
}

// NewRotatingLogger 创建支持轮转的日志记录器
func NewRotatingLogger(basePath string, maxSizeMB int) (*RotatingLogger, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 100 // 默认100MB
	}

	rl := &RotatingLogger{
		basePath: basePath,
		maxSize:  int64(maxSizeMB) * 1024 * 1024,
	}

	if err := rl.rotate(); err != nil {
		return nil, err
	}

	return rl, nil
}

// rotate 轮转日志文件
func (rl *RotatingLogger) rotate() error {
	if rl.currentFile != nil {
		rl.currentFile.Close()
	}

	// 生成新文件名
	timestamp := time.Now().Format("20060102-150405")
	filePath := fmt.Sprintf("%s.%s.log", rl.basePath, timestamp)

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	rl.currentFile = file
	rl.currentSize = 0

	return nil
}

// Log 记录事件
func (rl *RotatingLogger) Log(event AuditEvent) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// 检查是否需要轮转
	if rl.currentSize+int64(len(data)) > rl.maxSize {
		if err := rl.rotate(); err != nil {
			return err
		}
	}

	// 写入数据
	if _, err := rl.currentFile.Write(append(data, '\n')); err != nil {
		return err
	}

	rl.currentSize += int64(len(data)) + 1
	return rl.currentFile.Sync()
}

// Close 关闭日志记录器
func (rl *RotatingLogger) Close() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.currentFile != nil {
		return rl.currentFile.Close()
	}
	return nil
}

// StdoutLogger 标准输出日志记录器
type StdoutLogger struct{}

// NewStdoutLogger 创建标准输出日志记录器
func NewStdoutLogger() *StdoutLogger {
	return &StdoutLogger{}
}

// Log 记录事件到标准输出
func (l *StdoutLogger) Log(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// Close 关闭日志记录器
func (l *StdoutLogger) Close() error {
	return nil
}