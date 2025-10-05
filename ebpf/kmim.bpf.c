// SPDX-License-Identifier: GPL-2.0

// Define basic types first
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

// Define essential BPF constants
#define BPF_MAP_TYPE_RINGBUF 27

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_RING_SIZE (256 * 1024)

struct {
    __u32 type;
    __u32 max_entries;
} events SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = BPF_RING_SIZE,
};

struct module_event {
    char name[64];
    __u64 addr;
    __u64 size;
    __u64 timestamp;
    char compiler_info[128];
    __u32 sections_count;
};

// Simplified tracepoint context structures
struct trace_module_load_ctx {
    __u64 __unused_1;
    __u64 __unused_2;
    char name[56];
    __u64 ip;
    __u32 size;
    int refcnt;
};

struct trace_module_free_ctx {
    __u64 __unused_1;
    __u64 __unused_2;
    char name[56];
    __u64 ip;
    int refcnt;
};

SEC("tp/module/module_load")
int trace_module_load(struct trace_module_load_ctx *ctx) {
    struct module_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Capture module metadata
    bpf_probe_read_kernel_str(event->name, sizeof(event->name), ctx->name);
    event->addr = ctx->ip;
    event->size = ctx->size;
    event->timestamp = bpf_ktime_get_ns();
    event->sections_count = 0; // Will be filled by userspace
    
    // Initialize compiler info
    event->compiler_info[0] = '\0';
    
    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

SEC("tp/module/module_free")
int trace_module_free(struct trace_module_free_ctx *ctx) {
    struct module_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Capture module metadata
    bpf_probe_read_kernel_str(event->name, sizeof(event->name), ctx->name);
    event->addr = ctx->ip;
    event->size = 0; // Size not available in free event
    event->timestamp = bpf_ktime_get_ns();
    event->sections_count = 0;
    
    // Initialize compiler info
    event->compiler_info[0] = '\0';
    
    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
