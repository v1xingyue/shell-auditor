package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ./bpf/trace.c -- -I/usr/include/bpf

// EventTypes BPF事件类型
const (
	EventExecve = iota
	EventConnect
	EventAccept
	EventBind
	EventDNSQuery
)

// ExecveEvent 执行命令事件
type ExecveEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	GID        uint32
	Comm       [16]byte
	ArgCount   uint32
	Args       [512]byte
	WorkingDir [256]byte
}

// ConnectEvent 连接事件
type ConnectEvent struct {
	PID     uint32
	UID     uint32
	GID     uint32
	Comm    [16]byte
	SrcAddr [16]byte
	SrcPort uint16
	DstAddr [16]byte
	DstPort uint16
	Protocol uint8
}

// BindEvent 绑定端口事件
type BindEvent struct {
	PID     uint32
	UID     uint32
	GID     uint32
	Comm    [16]byte
	Address [16]byte
	Port    uint16
	Protocol uint8
}

// DNSQueryEvent DNS查询事件
type DNSQueryEvent struct {
	PID      uint32
	UID      uint32
	GID      uint32
	Comm     [16]byte
	Domain   [256]byte
	Resolved [16]byte
	Type     uint8
}

// BPFTracer BPF追踪器
type BPFTracer struct {
	objs       *bpfObjects
	eventsChan chan interface{}
	done       chan struct{}
}

// NewBPFTracer 创建BPF追踪器
func NewBPFTracer() (*BPFTracer, error) {
	bt := &BPFTracer{
		eventsChan: make(chan interface{}, 1000),
		done:       make(chan struct{}),
	}

	// 加载BPF程序
	if err := loadBpfObjects(&bt.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	return bt, nil
}

// Start 启动追踪
func (bt *BPFTracer) Start() error {
	// 挂载BPF程序到各个tracepoint
	if err := bt.objs.TraceExecve.Attach(); err != nil {
		return fmt.Errorf("failed to attach execve tracepoint: %w", err)
	}

	if err := bt.objs.TraceConnect.Attach(); err != nil {
		return fmt.Errorf("failed to attach connect tracepoint: %w", err)
	}

	if err := bt.objs.TraceAccept.Attach(); err != nil {
		return fmt.Errorf("failed to attach accept tracepoint: %w", err)
	}

	if err := bt.objs.TraceBind.Attach(); err != nil {
		return fmt.Errorf("failed to attach bind tracepoint: %w", err)
	}

	// 启动事件读取goroutine
	go bt.readEvents()

	return nil
}

// readEvents 读取BPF事件
func (bt *BPFTracer) readEvents() {
	for {
		select {
		case <-bt.done:
			return
		default:
			bt.readExecveEvents()
			bt.readConnectEvents()
			bt.readBindEvents()
		}
	}
}

// readExecveEvents 读取执行命令事件
func (bt *BPFTracer) readExecveEvents() {
	var event ExecveEvent
	for {
		err := bt.objs.ExecveEvents.Read(&event, nil)
		if err != nil {
			break
		}
		bt.eventsChan <- &event
	}
}

// readConnectEvents 读取连接事件
func (bt *BPFTracer) readConnectEvents() {
	var event ConnectEvent
	for {
		err := bt.objs.ConnectEvents.Read(&event, nil)
		if err != nil {
			break
		}
		bt.eventsChan <- &event
	}
}

// readBindEvents 读取绑定端口事件
func (bt *BPFTracer) readBindEvents() {
	var event BindEvent
	for {
		err := bt.objs.BindEvents.Read(&event, nil)
		if err != nil {
			break
		}
		bt.eventsChan <- &event
	}
}

// Events 返回事件通道
func (bt *BPFTracer) Events() <-chan interface{} {
	return bt.eventsChan
}

// Close 关闭追踪器
func (bt *BPFTracer) Close() error {
	close(bt.done)
	if bt.objs != nil {
		bt.objs.Close()
	}
	return nil
}

// ParseExecveEvent 解析执行命令事件
func ParseExecveEvent(e *ExecveEvent) (command string, args []string, workingDir string) {
	command = bytesToString(e.Comm[:])
	workingDir = bytesToString(e.WorkingDir[:])

	// 解析参数
	argData := e.Args[:]
	var offset uint32
	for i := uint32(0); i < e.ArgCount; i++ {
		if offset >= uint32(len(argData)) {
			break
		}
		// 读取字符串长度
		if offset+4 > uint32(len(argData)) {
			break
		}
		strLen := binary.LittleEndian.Uint32(argData[offset : offset+4])
		offset += 4

		// 读取字符串
		if offset+strLen > uint32(len(argData)) {
			break
		}
		arg := bytesToString(argData[offset : offset+strLen])
		args = append(args, arg)
		offset += strLen
	}

	return command, args, workingDir
}

// ParseConnectEvent 解析连接事件
func ParseConnectEvent(e *ConnectEvent) (srcIP, dstIP string, srcPort, dstPort int, protocol string) {
	srcIP = ipToString(e.SrcAddr[:])
	dstIP = ipToString(e.DstAddr[:])
	srcPort = int(e.SrcPort)
	dstPort = int(e.DstPort)
	protocol = "tcp"
	if e.Protocol == 1 {
		protocol = "udp"
	}
	return
}

// ParseBindEvent 解析绑定端口事件
func (bt *BPFTracer) ParseBindEvent(e *BindEvent) (address string, port int, protocol string) {
	address = ipToString(e.Address[:])
	port = int(e.Port)
	protocol = "tcp"
	if e.Protocol == 1 {
		protocol = "udp"
	}
	return
}

// bytesToString 字节数组转字符串
func bytesToString(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		return string(b)
	}
	return string(b[:i])
}

// ipToString IP地址转字符串
func ipToString(b []byte) string {
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0xff && b[11] == 0xff {
		// IPv4
		return net.IPv4(b[12], b[13], b[14], b[15]).String()
	}
	// IPv6
	return net.IP(b).String()
}

// GetUsername 获取用户名
func GetUsername(uid uint32) string {
	uidStr := fmt.Sprintf("%d", uid)
	// 使用C库函数获取用户名
	buf := make([]byte, 1024)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETPWUID,
		uintptr(uid),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, 0, 0,
	)
	if errno != 0 {
		return uidStr
	}

	// 解析passwd结构
	// 格式: name:passwd:uid:gid:gecos:dir:shell
	parts := bytes.Split(buf, []byte(":"))
	if len(parts) > 0 {
		return string(parts[0])
	}
	return uidStr
}