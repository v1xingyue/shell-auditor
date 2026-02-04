//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>

#define MAX_ARGS 8
#define MAX_ARG_LEN 64
#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16

// 事件类型
#define EVENT_EXECVE 1
#define EVENT_CONNECT 2
#define EVENT_ACCEPT 3
#define EVENT_BIND 4
#define EVENT_DNS 5

// 执行命令事件
struct execve_event_t {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[MAX_COMM_LEN];
    __u32 arg_count;
    char args[512];
    char working_dir[MAX_PATH_LEN];
};

// 连接事件
struct connect_event_t {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[MAX_COMM_LEN];
    __u8 src_addr[16];
    __u16 src_port;
    __u8 dst_addr[16];
    __u16 dst_port;
    __u8 protocol;
};

// 绑定端口事件
struct bind_event_t {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[MAX_COMM_LEN];
    __u8 address[16];
    __u16 port;
    __u8 protocol;
};

// BPF maps
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} execve_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} connect_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} bind_events SEC(".maps");

// 辅助函数：复制字符串
static __always_inline int copy_str(char *dst, const char *src, int max_len) {
    int i;
    for (i = 0; i < max_len - 1; i++) {
        char c = src[i];
        if (c == 0) break;
        dst[i] = c;
    }
    dst[i] = 0;
    return i;
}

// 辅助函数：获取IP地址
static __always_inline void get_ip_addr(struct sockaddr *addr, __u8 *out, __u16 *port) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        __builtin_memcpy(out, &sin->sin_addr, 4);
        // IPv4映射到IPv6格式
        __builtin_memset(out + 4, 0, 10);
        out[10] = 0xff;
        out[11] = 0xff;
        *port = __builtin_bswap16(sin->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        __builtin_memcpy(out, &sin6->sin6_addr, 16);
        *port = __builtin_bswap16(sin6->sin6_port);
    }
}

// 追踪 execve 系统调用
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct execve_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    event.pid = pid;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.gid = bpf_get_current_uid_gid();

    // 获取命令名
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 获取工作目录
    char cwd[MAX_PATH_LEN] = {};
    bpf_probe_read_kernel_str(&cwd, sizeof(cwd), &task->fs->pwd.dentry->d_iname);
    copy_str(event.working_dir, cwd, sizeof(event.working_dir));

    // 获取参数
    const char *const *argv = (const char *const *)ctx->args[1];
    __u32 offset = 0;
    __u32 count = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp) break;

        char arg[MAX_ARG_LEN] = {};
        bpf_probe_read_user_str(&arg, sizeof(arg), argp);

        __u32 len = 0;
        #pragma unroll
        for (int j = 0; j < MAX_ARG_LEN; j++) {
            if (arg[j] == 0) break;
            if (offset + 4 + len < sizeof(event.args)) {
                event.args[4 + offset + len] = arg[j];
                len++;
            }
        }

        if (offset + 4 + len <= sizeof(event.args)) {
            __builtin_memcpy(&event.args[offset], &len, 4);
            offset += 4 + len;
            count++;
        }
    }

    event.arg_count = count;
    bpf_perf_event_output(ctx, &execve_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// 追踪 connect 系统调用
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct connect_event_t event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.gid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (addr) {
        get_ip_addr(addr, event.dst_addr, &event.dst_port);
        event.protocol = (addr->sa_family == AF_INET6) ? 1 : 0;
    }

    bpf_perf_event_output(ctx, &connect_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// 追踪 bind 系统调用
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    struct bind_event_t event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.gid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (addr) {
        get_ip_addr(addr, event.address, &event.port);
        event.protocol = (addr->sa_family == AF_INET6) ? 1 : 0;
    }

    bpf_perf_event_output(ctx, &bind_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";