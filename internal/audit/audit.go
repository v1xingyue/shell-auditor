package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// EventType 审计事件类型
type EventType string

const (
	EventCommand   EventType = "command"
	EventPortOpen  EventType = "port_open"
	EventNetwork   EventType = "network"
	EventDNS       EventType = "dns"
	EventFile      EventType = "file"
)

// AuditEvent 审计事件
type AuditEvent struct {
	Timestamp   time.Time   `json:"timestamp"`
	Type        EventType   `json:"type"`
	PID         int         `json:"pid"`
	PPID        int         `json:"ppid"`
	UID         int         `json:"uid"`
	GID         int         `json:"gid"`
	Username    string      `json:"username"`
	Command     string      `json:"command,omitempty"`
	Args        []string    `json:"args,omitempty"`
	ExitCode    int         `json:"exit_code,omitempty"`
	WorkingDir  string      `json:"working_dir,omitempty"`
	Details     interface{} `json:"details,omitempty"`
}

// PortDetails 端口详情
type PortDetails struct {
	Protocol string `json:"protocol"` // tcp, udp
	Port     int    `json:"port"`
	Address  string `json:"address"`
}

// NetworkDetails 网络请求详情
type NetworkDetails struct {
	Protocol string `json:"protocol"` // tcp, udp
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
}

// DNSDetails DNS解析详情
type DNSDetails struct {
	Domain   string `json:"domain"`
	Resolved string `json:"resolved"`
	Type     string `json:"type"` // A, AAAA, CNAME, etc.
}

// Auditor 审计器
type Auditor struct {
	mu       sync.RWMutex
	events   []AuditEvent
	logger   Logger
	maxSize  int
}

// Logger 日志接口
type Logger interface {
	Log(event AuditEvent) error
	Close() error
}

// NewAuditor 创建审计器
func NewAuditor(logger Logger, maxSize int) *Auditor {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &Auditor{
		events:  make([]AuditEvent, 0, maxSize),
		logger:  logger,
		maxSize: maxSize,
	}
}

// LogCommand 记录命令执行
func (a *Auditor) LogCommand(pid, ppid, uid, gid int, username, command string, args []string, workingDir string) {
	event := AuditEvent{
		Timestamp:  time.Now(),
		Type:       EventCommand,
		PID:        pid,
		PPID:       ppid,
		UID:        uid,
		GID:        gid,
		Username:   username,
		Command:    command,
		Args:       args,
		WorkingDir: workingDir,
	}
	a.log(event)
}

// LogCommandExit 记录命令退出
func (a *Auditor) LogCommandExit(pid int, exitCode int) {
	a.mu.RLock()
	// 查找最近的命令事件并更新
	for i := len(a.events) - 1; i >= 0; i-- {
		if a.events[i].Type == EventCommand && a.events[i].PID == pid && a.events[i].ExitCode == 0 {
			a.events[i].ExitCode = exitCode
			break
		}
	}
	a.mu.RUnlock()
}

// LogPortOpen 记录端口开放
func (a *Auditor) LogPortOpen(pid, uid, gid int, username string, protocol string, port int, address string) {
	event := AuditEvent{
		Timestamp: time.Now(),
		Type:      EventPortOpen,
		PID:       pid,
		UID:       uid,
		GID:       gid,
		Username:  username,
		Details: PortDetails{
			Protocol: protocol,
			Port:     port,
			Address:  address,
		},
	}
	a.log(event)
}

// LogNetwork 记录网络请求
func (a *Auditor) LogNetwork(pid, uid, gid int, username string, protocol string, srcIP string, srcPort int, dstIP string, dstPort int) {
	event := AuditEvent{
		Timestamp: time.Now(),
		Type:      EventNetwork,
		PID:       pid,
		UID:       uid,
		GID:       gid,
		Username:  username,
		Details: NetworkDetails{
			Protocol: protocol,
			SrcIP:    srcIP,
			SrcPort:  srcPort,
			DstIP:    dstIP,
			DstPort:  dstPort,
		},
	}
	a.log(event)
}

// LogDNS 记录DNS解析
func (a *Auditor) LogDNS(pid, uid, gid int, username string, domain string, resolved string, dnsType string) {
	event := AuditEvent{
		Timestamp: time.Now(),
		Type:      EventDNS,
		PID:       pid,
		UID:       uid,
		GID:       gid,
		Username:  username,
		Details: DNSDetails{
			Domain:   domain,
			Resolved: resolved,
			Type:     dnsType,
		},
	}
	a.log(event)
}

// log 内部日志方法
func (a *Auditor) log(event AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 限制内存中的事件数量
	if len(a.events) >= a.maxSize {
		a.events = a.events[1:]
	}
	a.events = append(a.events, event)

	// 异步写入日志
	if a.logger != nil {
		go func(e AuditEvent) {
			if err := a.logger.Log(e); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to log event: %v\n", err)
			}
		}(event)
	}
}

// GetEvents 获取所有事件
func (a *Auditor) GetEvents() []AuditEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	events := make([]AuditEvent, len(a.events))
	copy(events, a.events)
	return events
}

// GetEventsByPID 获取指定PID的事件
func (a *Auditor) GetEventsByPID(pid int) []AuditEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var events []AuditEvent
	for _, e := range a.events {
		if e.PID == pid {
			events = append(events, e)
		}
	}
	return events
}

// Close 关闭审计器
func (a *Auditor) Close() error {
	if a.logger != nil {
		return a.logger.Close()
	}
	return nil
}

// ToJSON 转换为JSON
func (e *AuditEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}