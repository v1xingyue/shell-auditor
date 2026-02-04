# Shell Auditor

一个基于 Go 和 eBPF 的 Shell 执行审计工具，用于监控和记录用户在 Linux 服务器上的所有操作。

## 功能特性

- **命令审计**: 记录所有执行的命令及其参数
- **端口监控**: 记录所有开放的端口
- **网络审计**: 记录所有网络连接请求
- **DNS 监控**: 记录所有 DNS 解析请求
- **交互式 Shell**: 提供安全的审计 Shell 环境
- **守护进程模式**: 可作为后台服务运行
- **日志轮转**: 支持日志文件自动轮转

## 系统要求

- Linux 内核 4.10+ (支持 eBPF)
- Go 1.21+
- clang/LLVM (用于编译 eBPF 程序)
- root 权限

## 安装

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/cevin/shell-auditor.git
cd shell-auditor

# 安装依赖
make deps

# 构建
make build

# 安装到系统
sudo make install
```

### 使用预编译二进制

下载对应平台的二进制文件并赋予执行权限：

```bash
chmod +x shell-auditor
sudo mv shell-auditor /usr/local/bin/
```

## 使用方法

### 交互式 Shell 模式

```bash
sudo shell-auditor -shell -v
```

### 守护进程模式

```bash
sudo shell-auditor -log /var/log/shell-auditor/audit.log -v
```

### 作为用户 Shell

编辑 `/etc/passwd` 文件，将用户的 shell 改为 shell-auditor：

```bash
# 编辑用户 shell
sudo usermod -s /usr/local/bin/shell-auditor username

# 或手动编辑 /etc/passwd
username:x:1000:1000:User:/home/username:/usr/local/bin/shell-auditor
```

## 命令行选项

```
  -log string
        Path to audit log file (default: ~/.shell-auditor/audit.log)
  -log-size int
        Max log file size in MB before rotation (default: 100)
  -no-bpf
        Disable BPF tracing (fallback mode)
  -shell
        Run in interactive shell mode
  -v
        Verbose mode
```

## 内置命令

Shell Auditor 提供以下内置命令：

- `cd` - 切换目录
- `pwd` - 显示当前目录
- `history` - 显示命令历史
- `clear` - 清屏
- `exit/logout` - 退出 shell
- `export` - 设置环境变量
- `audit` - 查询审计日志
  - `audit` - 显示最近的审计事件
  - `audit pid <pid>` - 显示指定 PID 的审计事件
  - `audit clear` - 清空审计日志

## 审计日志格式

日志以 JSON Lines 格式记录，每行一个事件：

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "type": "command",
  "pid": 1234,
  "ppid": 1000,
  "uid": 1000,
  "gid": 1000,
  "username": "user",
  "command": "ls",
  "args": ["-la", "/tmp"],
  "working_dir": "/home/user",
  "exit_code": 0
}
```

### 事件类型

| 类型 | 说明 |
|------|------|
| `command` | 命令执行 |
| `port_open` | 端口开放 |
| `network` | 网络连接 |
| `dns` | DNS 解析 |

## 日志查询

使用 `jq` 查询日志：

```bash
# 查看所有命令
jq 'select(.type=="command")' /var/log/shell-auditor/audit.log

# 查看网络连接
jq 'select(.type=="network")' /var/log/shell-auditor/audit.log

# 查看特定用户的操作
jq 'select(.username=="user")' /var/log/shell-auditor/audit.log

# 查看特定时间范围
jq 'select(.timestamp >= "2024-01-01" and .timestamp <= "2024-01-02")' /var/log/shell-auditor/audit.log
```

## Systemd 服务

创建 systemd 服务文件 `/etc/systemd/system/shell-auditor.service`：

```ini
[Unit]
Description=Shell Auditor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shell-auditor -log /var/log/shell-auditor/audit.log -v
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable shell-auditor
sudo systemctl start shell-auditor
sudo systemctl status shell-auditor
```

## 安全注意事项

1. **日志保护**: 确保审计日志文件权限正确，防止用户修改
2. **日志备份**: 定期备份审计日志到安全位置
3. **监控告警**: 配置日志监控和告警机制
4. **权限控制**: 限制对审计工具的访问权限

## 故障排除

### BPF 加载失败

如果 BPF 程序加载失败，可以使用 `-no-bpf` 参数运行，此时只记录命令执行：

```bash
sudo shell-auditor -shell -no-bpf
```

### 权限问题

确保以 root 权限运行：

```bash
sudo shell-auditor -shell
```

### 内核版本过低

检查内核版本：

```bash
uname -r
```

需要内核 4.10 或更高版本。

## 开发

```bash
# 生成 BPF 代码
make generate

# 运行测试
make test

# 代码格式化
make fmt

# 代码检查
make lint
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request。