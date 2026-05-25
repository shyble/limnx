# Limnx

[![Build & Test](https://github.com/limnxos/limnx/actions/workflows/build.yml/badge.svg)](https://github.com/limnxos/limnx/actions/workflows/build.yml)

A small, hackable Unix-like OS for x86_64 and ARM64.

Limnx is a from-scratch kernel + userland built for learning and tinkering. Full arch parity between x86_64 and ARM64, modern virtio drivers, busybox + musl userspace, SMP preemptive scheduling, fork/exec with COW, signals, TCP/IP, LimnFS on virtio-blk. BIOS/UEFI boot on x86_64, PSCI/FDT on ARM64, runs in QEMU.

## Try It

```bash
# x86_64
make clean && make
make run                        # busybox ash on COM1

# ARM64
make arm64 && make arm64-run    # QEMU virt, PL011 serial
```

## What's In It

| Subsystem | What |
|-----------|------|
| **Kernel** | 4-level paging, SMP (2 CPUs, LAPIC/GIC), preemptive scheduler, fork+exec+COW, signals, 140+ syscalls |
| **Filesystem** | VFS, LimnFS on virtio-blk, block cache (write-back), symlinks, FIFOs, /proc, tmpfs mount, /dev |
| **Networking** | Ethernet/ARP/IP/ICMP/UDP/TCP, virtio-net (PCI on x86, MMIO on ARM), software loopback |
| **Userland** | Busybox (47 applets), musl libc, login, job control (SIGTSTP/SIGCONT, tcsetpgrp), shell scripting |
| **Boot** | Limine (x86_64 BIOS+UEFI), direct boot (ARM64), FDT/DTB parser, persistent /etc/inittab |
| **Optional services** | `inferd` (GGUF inference), `agentd` (RAG + tool dispatch), `serviced` (supervisor trees) — see [Optional Services](#optional-services) below |

## Architecture

```
 User Space (Ring 3 / EL0)
 ┌──────────────────────────────────────────────────────────┐
 │  orchestrator   agent_worker(×3)   inferd   agentd       │
 │  chat           toolagent          shell    busybox      │
 │                                                          │
 │  libc: syscalls, printf, math, tokenizer, GGUF, HTTP     │
 ├──────────────────────────────────────────────────────────┤
 │           SYSCALL/SYSRET (x86_64) | SVC (ARM64)          │
 ├──────────────────────────────────────────────────────────┤
 Kernel (Ring 0 / EL1)
 │                                                          │
 │  Process        Scheduler       Memory       Filesystem  │
 │  fork/exec/COW  SMP preemptive  4-level PT   LimnFS/VFS  │
 │  signals        2 CPUs          swap/demand  block cache │
 │                                                          │
 │  Orchestration                  Security                 │
 │  infer_svc (routing/cache)      namespaces               │
 │  supervisor trees               capability tokens        │
 │  task graphs (DAG)              seccomp filters          │
 │  pub/sub messaging              UID/GID/caps             │
 │  agent registry                                          │
 │                                                          │
 │  Networking     IPC             Devices                  │
 │  TCP/IP/UDP     unix sockets    virtio-net/blk           │
 │  ICMP/ARP       epoll/eventfd   PCI / MMIO               │
 │                 io_uring        LAPIC / GIC              │
 │                 pipes/shm       PL011 / COM1             │
 │                                                          │
 │  HAL (arch/)                                             │
 │  x86_64: GDT/IDT/TSS, LAPIC, MSR, CR3, SYSCALL/SYSRET    │
 │  ARM64:  GIC, TTBR, VBAR, SVC, PSCI SMP                  │
 └──────────────────────────────────────────────────────────┘
       Limine (x86_64 BIOS/UEFI)  |  Direct boot (ARM64)
```

## Optional Services

The sections below describe userspace daemons that ship with Limnx for AI/inference workloads. They're optional — the OS boots and is fully usable without them.

## Inference Pipeline

```
User program                    Kernel                         inferd daemon
     │                            │                                │
     │ sys_infer_request ──────►  │ route to service ────────────► │
     │  ("default", prompt)       │ (namespace-aware,              │ load GGUF model
     │                            │  health-checked,               │ BPE tokenize
     │                            │  cached results)               │ transformer forward
     │                            │                                │ temperature + top-k sample
     │ ◄────── response ───────── │ ◄──── unix socket ───────────  │ BPE decode
     │                            │ cache result                   │
     │                            │                                │
     │ sys_infer_submit ────────► │ async worker thread ─────────► │
     │  (non-blocking)            │                                │
     │ sys_infer_poll ──────────► │ check completion               │
     │ sys_infer_result ────────► │ copy response                  │
```

Supported model formats: GGUF v3 (F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q2_K–Q6_K). BPE tokenizer loaded from GGUF metadata (FNV-1a hash table for O(1) merge lookup). Transformer: RMS norm, multi-head attention, GQA, RoPE, SwiGLU, KV cache.

**Quantized inference**: Models with quantized weights (e.g. Q4_K_M) stay quantized in memory — a 1GB model uses 1GB RAM, not 7.6GB. Dequantization happens on-the-fly during each matmul. Tested with Qwen3-1.7B-Q4_K_M (1.03GB, 151K vocab, 28 layers).

**Three inference paths**:
- **Local CPU**: inferd loads GGUF model, runs transformer directly
- **Remote GPU**: `inferd_proxy` forwards requests over TCP to `gpu_inference_server.py` on a host with GPU
- **Hardware accelerator**: virtio-accel device (when QEMU backend is compiled)

## Agent Daemon (agentd)

agentd is the persistent agent runtime — the "brain" that ties together inference, tools, and memory into a continuously running service.

```
                     ┌─────────────────────────────────────┐
                     │              agentd                  │
                     │                                      │
 client ──unix──►    │  ┌──────────┐  ┌────────┐  ┌──────┐ │
 (shell,             │  │ Session  │  │  Tool  │  │Memory│ │
  chat,              │  │ Manager  │  │Registry│  │System│ │
  agent)             │  │(8 slots) │  │(16)    │  │(RAG) │ │
                     │  └────┬─────┘  └───┬────┘  └──┬───┘ │
                     │       │            │          │     │
                     │  ┌────┴─────────���──┴──────────┴───┐ │
                     │  │       Event Loop (accept)       │ │
                     │  └────────────┬────────────────────┘ │
                     └───────────────┼─────────────────────┘
                                     │ sys_infer_request
                                     ▼
                                  inferd
```

**Boot order**: `init → serviced → agentd → shell` (configurable via `/etc/inittab`)

### How It Works

1. Client connects to `/tmp/agentd.sock` and sends a prompt
2. agentd appends it to the session's context buffer (2KB sliding window)
3. Retrieves relevant memories from vecstore (semantic similarity / RAG)
4. Assembles full prompt: `[recalled memories] + [conversation history] + [user input]`
5. Calls `sys_infer_request("default", ...)` → routed to inferd by the kernel
6. Checks response for tool-use intent (keyword matching)
7. If tool needed: `fork + exec + pipe` via `tool_dispatch()`, captures output
8. Appends tool output to context, re-infers (up to 4 tool chain iterations)
9. Returns final response to client
10. Stores interaction embedding in session vecstore for future recall

### Features

- **8 concurrent sessions** with independent context and memory
- **Dual-layer memory**: per-session vecstore + global vecstore
- **7 built-in tools**: ls, cat, echo, ps, wc, grep, head
- **Custom tools** via `/etc/agentd/tools.conf` (name|path|description|keywords)
- **Tool chaining**: infer → tool → re-infer, up to 4 iterations
- **Agent registry**: registered as `"agentd"` for system-level IPC

## Service Configuration

Limnx uses persistent config files in `/etc/` that are created with defaults on first boot and preserved across reboots. Edit them to customize your system.

### `/etc/inittab` — Init System

Controls which services start at boot. Format: `name:path:flags`

```bash
# Default (first boot):
serviced:/serviced.elf:respawn
agentd:/agentd.elf:respawn
shell:/bin/ash:wait

# To auto-start inference with a GGUF model:
serviced:/serviced.elf:respawn
inferd:/inferd.elf /model.gguf:respawn
agentd:/agentd.elf:respawn
shell:/bin/ash:wait
```

Flags:
- `respawn` — restart if the process exits
- `once` — run once, don't restart
- `wait` — run and wait for exit before continuing

Edit from the shell: `vi /etc/inittab` — changes take effect on next boot.

### `/etc/services` — Service Daemon

Controls services managed by `serviced`. Format: `name|path|policy|after`

```bash
# Example:
inferd|/inferd.elf /model.gguf|one-for-one|none
agentd|/agentd.elf|one-for-one|inferd
```

Policies: `one-for-one` (restart only crashed child), `one-for-all` (restart all on any crash).
Dependencies: `after` field specifies which service must start first.

### Loading AI Models

Models are NOT auto-loaded by default (to keep boot fast). Load manually:

```bash
# Start inference daemon with a GGUF model:
/inferd.elf /model.gguf

# Or with a custom service name and socket:
/inferd.elf /model.gguf qwen /tmp/qwen.sock

# To load a model from a LimnFS disk (prepared with mklimnfs.py):
/inferd.elf /model.gguf
```

To prepare a disk with a GGUF model (run on the host):

```bash
# Create a LimnFS disk image with the model pre-loaded:
python3 tools/mklimnfs.py -o build/disk.img -s 1536 \
  /path/to/model.gguf:model.gguf

# Boot with the model disk:
make run
# Then from the shell: /inferd.elf /model.gguf
```

Supported: GGUF v3 with Q4_K, Q4_0, Q8_0, Q2_K–Q6_K, F16, F32 quantization. Weights stay quantized in memory (zero-copy) and dequantize on-the-fly during inference.

## Use Cases

### 1. Loading and Serving an AI Model

```
┌────────────────┐     sys_infer_register      ┌───────────────────┐
│   inferd       │ ──────────────────────────► │  Kernel           │
│                │   "summarizer"              │  infer_svc        │
│  1. Open       │   "/tmp/summarizer.sock"    │  registry         │
│     model.gguf |                             │                   │
│  2. Parse      │     sys_infer_health ──────►│  health monitor   │
│     GGUF v3    │     (heartbeat)             │  load balancer    │
│  3. Dequant    │                             │  result cache     │
│     Q4_0→F32   │◄────── unix socket ──────── │  request router   │
│  4. Init       │   receive prompt            │                   │
│     transformer|                             └───────────────────┘
│  5. Listen     │
│     on socket  │
└────────────────┘

# Start the inference daemon:
/inferd.elf /model.gguf summarizer /tmp/summarizer.sock
```

Multiple daemons can register under the same name — the kernel load-balances across them.

### 2. Chatting with an AI Model

```
┌───────────┐   sys_infer_request   ┌─────────┐   unix sock  ┌──────────┐
│  chat.elf │ ───────────────────►  │ Kernel  │ ───────────► │  inferd  │
│           │  "summarizer"         │ infer   │              │          │
│ you> Hi   │  "Hi there"           │ _svc    │              │ tokenize │
│           │                       │         │              │ forward  │
│ [bot] ... │ ◄───────────────────  │ cache?  │ ◄─────────── │ sample   │
│           │   response            │ return  │  response    │ decode   │
└───────────┘                       └─────────┘              └──────────┘

# Interactive chat with RAG memory:
/chat.elf

# Or direct text generation:
/generate.elf
prompt> The quick brown fox
[gen] jumps over the lazy...
```

The kernel caches responses — repeated prompts return instantly without hitting the daemon.

### 3. Setting Up a Single AI Agent

```
┌───────────────────┐
│   toolagent.elf   │
│                   │
│  1. Register      │─── sys_agent_register("code_reviewer")
│  2. Load model    │─── gguf_load / transformer_init
│  3. Listen        │─── sys_topic_subscribe(review_topic)
│                   │
│  Loop:            │
│    recv task  ◄───│─── sys_topic_recv(review_topic)
│    think      ────│─── transformer_forward (local)
│         or    ────│─── sys_infer_request (remote)
│    act        ────│─── sys_exec / sys_fwrite / sys_sendto
│    publish    ────│─── sys_topic_publish(results_topic)
│                   │
└───────────────────┘
```

Agents discover each other via `sys_agent_lookup("code_reviewer")` → returns PID.

### 4. Agent Communication Channels

Limnx provides 5 IPC channels, each suited to different agent patterns:

```
 Agent A                              Agent B
 ┌──────┐    pub/sub (broadcast)     ┌──────┐
 │      │ ═══════════════════════════│      │    1-to-many, fire-and-forget
 │      │                            │      │    sys_topic_publish / _recv
 │      │    unix socket (stream)    │      │
 │      │ ───────────────────────────│      │    1-to-1, bidirectional
 │      │                            │      │    sys_unix_connect / _send
 │      │    pipe (parent→child)     │      │
 │      │ ──────────────────────────►│      │    1-to-1, unidirectional
 │      │                            │      │    sys_pipe + sys_fork
 │      │    shared memory (fast)    │      │
 │      │ ◄═══════════════════════►  │      │    zero-copy, lock-free
 │      │                            │      │    sys_shmget / _shmat
 │      │    inference service       │      │
 │      │ ─────── kernel ───────────►│      │    routed, cached, load-balanced
 │      │                            │      │    sys_infer_request
 └──────┘                            └──────┘
```

### 5. Agent Swarm with Orchestration

```
                    ┌──────────────────┐
                    │   orchestrator   │
                    │                  │
                    │ 1. ns_create     │─── isolated namespace
                    │ 2. token_create  │─── CAP_INFER bearer token
                    │ 3. super_create  │─── supervisor tree
                    │ 4. task_create   │─── A → B → C (DAG)
                    │ 5. super_start   │─── launch workers
                    └──────┬───────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
         ┌────▼────┐   ┌───▼─────┐   ┌───▼─────┐
         │worker_0 │   │worker_1 │   │worker_2 │
         │         │   │         │   │         │
         │seccomp  │   │seccomp  │   │seccomp  │    sandboxed
         │sandbox  │   │sandbox  │   │sandbox  │    (no fork/exec/kill)
         │         │   │         │   │         │
         │cap_token│   │cap_token│   │cap_token│   scoped CAP_INFER
         │(bearer) │   │(bearer) │   │(bearer) │
         │         │   │         │   │         │
         │topic_   │   │topic_   │   │topic_   │    receive tasks
         │ recv    │   │ recv    │   │ recv    │    via pub/sub
         │         │   │         │   │         │
         │infer_   │   │infer_   │   │infer_   │    call AI model
         │request  │   │request  │   │request  │    via kernel router
         │         │   │         │   │         │
         │topic_   │   │topic_   │   │topic_   │    publish results
         │ pub     │   │ pub     │   │ pub     │    via pub/sub
         └─────────┘   └─────────┘   └─────────┘

Task graph enforces execution order:
  Task A (analyze)  ─── must complete before ───►  Task B (transform)
  Task B (transform) ── must complete before ───►  Task C (summarize)
```

### 6. Spawning Agents Dynamically

```
# Supervisor handles lifecycle — crashed agents auto-restart

super_id = sys_super_create("data_pipeline")
sys_super_set_policy(super_id, ONE_FOR_ONE)    # restart only crashed child

sys_super_add(super_id, "/fetcher.elf",   ns_id, CAP_NET)
sys_super_add(super_id, "/parser.elf",    ns_id, CAP_FS_READ)
sys_super_add(super_id, "/analyzer.elf",  ns_id, CAP_INFER)
sys_super_add(super_id, "/writer.elf",    ns_id, CAP_FS_WRITE)

sys_super_start(super_id)    # launch all 4

# If analyzer crashes → supervisor restarts only analyzer
# If using ONE_FOR_ALL → supervisor restarts all 4

sys_super_stop(super_id)     # clean shutdown
```

Agents can also be spawned ad-hoc via `fork + execve` with scoped capabilities:

```c
long pid = sys_fork();
if (pid == 0) {
    sys_seccomp(allowed_mask, 1, allowed_mask_hi);  // sandbox
    sys_execve("/agent.elf", argv);
}
// Parent delegates a capability token to the child:
sys_token_delegate(parent_token, pid, CAP_INFER, "summarizer");
```

### 7. AI Agent Orchestration as a Service

```
┌─────────────────────────────────────────────────────────┐
│                   Limnx Kernel                          │
│                                                         │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐   │
│  │Namespace │  │Supervisor│  │Task Graph│  │Inference│  │
│  │  ns=1    │  │  tree    │  │  DAG     │  │ Service │  │
│  │ agents   │  │ restart  │  │ deps     │  │ routing │  │
│  │ quotas   │  │ policy   │  │ fan-out  │  │ caching │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘  │
│       │             │             │              │      │
│  ┌────▼─────────────▼─────────────▼──────────────▼────┐ │
│  │              Pub/Sub Message Bus                   │ │
│  │   topics: tasks, results, alerts, model_updates    │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │Cap Tokens│  │ Seccomp  │  │  Epoll   │               │
│  │ delegate │  │ sandbox  │  │ I/O mux  │               │
│  │ revoke   │  │ restrict │  │ events   │               │
│  └──────────┘  └──────────┘  └──────────┘               │
└─────────────────────────────────────────────────────────┘

The kernel IS the orchestration layer:

  ┌──────────┐        ┌──────────┐        ┌──────────┐
  │ Customer │        │ Internal │        │ External │
  │ Service  │        │ Pipeline │        │ API      │
  │          │        │          │        │          │
  │ ns=1     │        │ ns=2     │        │ ns=3     │
  │ 3 agents │        │ 5 agents │        │ 2 agents │
  │ CAP_NET  │        │ CAP_INFER│        │ CAP_NET  │
  │          │        │ CAP_FS   │        │ CAP_INFER│
  └──────────┘        └──────────┘        └──────────┘

  Each namespace is a self-contained service:
  - Own supervisor tree (auto-restart)
  - Own task graphs (workflow DAGs)
  - Own capability tokens (scoped permissions)
  - Own pub/sub topics (internal messaging)
  - Cross-namespace access requires CAP_XNS_* tokens
```

### 8. Real-World Tool Use (MCP-Style)

Modern agents need to call tools — browse the web, read files, execute code, query APIs. Limnx supports this through **tools-as-agents**: each tool registers as a named agent, and the AI agent invokes tools through the kernel's IPC:

```
                    ┌──────────────┐
                    │  AI Agent    │
                    │              │
                    │  1. Think    │── transformer_forward (what tool to call?)
                    │  2. Decide   │── "I need to read config.txt"
                    │  3. Call     │── sys_agent_lookup("file_reader") → pid
                    │  4. Request  │── sys_topic_publish(tool_topic, "read config.txt")
                    │  5. Wait     │── sys_topic_recv(result_topic)
                    │  6. Process  │── feed result back into transformer
                    │  7. Respond  │── final answer
                    └──────┬───────┘
                           │ pub/sub
          ┌────────────────┼────────────────┐
          │                │                │
     ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
     │file_    │     │web_     │     │code_    │
     │reader   │     │fetcher  │     │executor │
     │         │     │         │     │         │
     │CAP_FS   │     │CAP_NET  │     │seccomp  │
     │_READ    │     │         │     │sandbox  │
     │         │     │         │     │         │
     │sys_open │     │sys_tcp_ │     │sys_fork │
     │sys_read │     │connect  │     │sys_exec │
     │sys_stat │     │sys_tcp_ │     │sys_pipe │
     │         │     │send/recv│     │         │
     └─────────┘     └─────────┘     └─────────┘

Each tool has ONLY the capabilities it needs:
  - file_reader: CAP_FS_READ (can read, cannot write or delete)
  - web_fetcher: CAP_NET (can connect, cannot touch filesystem)
  - code_executor: seccomp sandbox (can exec, cannot network)
```

**Sandboxed tool execution** via `tooldispatch.c`:

```c
// Agent wants to run a tool:
tool_result_t result;
tool_dispatch(
    "/web_fetcher.elf",              // tool binary
    argv,                             // arguments
    CAP_NET,                          // scoped capability
    1000,                             // CPU time limit (ticks)
    "GET https://api.example.com",    // input via stdin pipe
    input_len,
    &result                           // output via stdout pipe
);
// result.output = "{ \"data\": ... }"
// result.exit_status = 0 (success)
```

The kernel enforces isolation:
- Tool runs in a **forked child process** with capability-dropped permissions
- Input/output via **pipes** (no shared memory, no side channels)
- **Seccomp** restricts syscalls (web_fetcher can't call `sys_open`)
- **Capability tokens** scope access (file_reader can't call `sys_tcp_connect`)
- **Resource limits** cap CPU time and memory
- Child is **reaped on completion** — no persistent state

### 9. Multi-Tool Chains (Agent Planning)

Agents can plan multi-step tool sequences, where each step's output feeds the next:

```
User: "Summarize the contents of /data/report.txt"

Agent planning (transformer-based):
  Step 1: read /data/report.txt    → tool: file_reader
  Step 2: summarize the content    → tool: inference (summarizer model)
  Step 3: write summary to output  → tool: file_writer

Execution:
  ┌─────────┐  pipe   ┌──────────┐  pipe   ┌──────────┐  pipe   ┌─────────┐
  │ Agent   │────────►│file_     │────────►│ inferd   │────────►│file_    │
  │ (plan)  │ "read"  │reader    │ content │summarizer│ summary │writer   │
  │         │◄────────│          │◄────────│          │◄────────│         │
  └─────────┘  result └──────────┘  result └──────────┘  result └─────────┘

Each step:
  1. Agent publishes task to tool topic
  2. Appropriate tool picks it up (capability-scoped)
  3. Tool executes, publishes result
  4. Agent receives result, feeds to next step
  5. Task graph tracks dependencies (step 2 waits for step 1)
```

```c
// Multi-tool chain in code:
long t1 = sys_task_create("read_file", ns_id);
long t2 = sys_task_create("summarize", ns_id);
long t3 = sys_task_create("write_output", ns_id);
sys_task_depend(t2, t1);    // summarize waits for read
sys_task_depend(t3, t2);    // write waits for summarize

sys_task_start(t1);
sys_topic_publish(tool_topic, "TASK:1:read /data/report.txt");
// ... agent loop handles results and advances the chain
```

### 10. Skill and Plugin System

Tools can be extended at runtime. A "skill" is just an ELF binary that follows the tool convention (read stdin, write stdout, exit):

```
/skills/
  web_search.elf       # CAP_NET — search the web
  db_query.elf         # CAP_FS_READ — query local database
  image_gen.elf        # CAP_INFER — call image model
  email_send.elf       # CAP_NET — send email
  calculator.elf       # no caps needed — pure compute

# Register a new skill at runtime:
sys_agent_register("calculator")

# Discovery — agent lists available skills:
for each registered agent:
    sys_agent_lookup(skill_name, &pid)
    if pid > 0: skill is available
```

The kernel provides the **guarantees**:
- Skills can't escape their sandbox (seccomp + capabilities)
- Skills can't access other skills' data (namespace isolation)
- Skills can be revoked instantly (token revocation + SIGKILL)
- Crashed skills auto-restart (supervisor tree)
- Resource exhaustion is bounded (rlimits + namespace quotas)

## Implementation Status

| Use Case | Status | Notes |
|----------|--------|-------|
| 1. Load & serve model | **Verified** | inferd + GGUF + kernel registry, 49/49 tests both archs |
| 2. Chat with model | **Verified** | chat.elf + generate.elf, kernel cache, sync + async |
| 3. Single AI agent | **Verified** | toolagent.c routes through sys_infer_request, falls back to local |
| 4. Communication channels | **Verified** | pub/sub, unix sockets, pipes, inference service all tested |
| 5. Agent swarm | **Verified** | orchestrator.elf: supervisor + task graph + pub/sub + seccomp |
| 6. Dynamic spawning | **Verified** | Supervisor auto-restart, fork+execve, bearer token delegation |
| 7. Orchestration as service | **Verified** | Multi-namespace isolation tested (ipc_test), concurrent topics per namespace |
| 8. Tool use (MCP-style) | **Verified** | file_reader.elf + code_executor.elf + tool_demo.elf, sandboxed via tool_dispatch |
| 9. Multi-tool chains | **Verified** | tool_demo.elf chains tools: "read /hello.txt and count words" |
| 10. Skill/plugin system | **Verified** | Tools are ELF binaries, discovered at runtime, sandboxed execution |

## Build

**x86_64** requires: `x86_64-elf-gcc`, `x86_64-elf-ld`, `nasm`, `xorriso`, `qemu-system-x86_64`

**ARM64** requires: `aarch64-elf-gcc` (or `aarch64-linux-gnu-gcc`), `qemu-system-aarch64`

```bash
make clean && make     # build x86_64 ISO (fetches Limine on first run)
make run               # boot in QEMU with virtio-net + virtio-blk
make disk              # create 64MB virtio-blk disk image
make arm64             # build ARM64 kernel ELF
./run-arm64.sh         # clean build + boot ARM64 in QEMU
```

## Test Suite

```bash
# In the Limnx shell:
/infer_test.elf        # 49 inference pipeline tests (both archs)
/fs_test.elf           # Filesystem tests
/proc_test.elf         # Process/fork/exec tests
/ipc_test.elf          # IPC tests
/mm_test.elf           # Memory management tests
/net_test.elf          # Network tests
/security_test.elf     # Security tests
/system_test.elf       # System integration tests
```

## Kernel Stats

- **140+ syscalls** (Linux-compatible numbers + Limnx-specific 512+)
- **2 architectures**: x86_64 (primary), ARM64 (full feature parity)
- **SMP**: 2 CPUs, per-CPU data, LAPIC timer preemption
- **Memory**: 4-level paging, HHDM, kernel heap up to 1GB, mmap up to 2GB
- **Filesystem**: LimnFS (ext2-inspired, triple indirect blocks, dynamic disk size up to 1GB+)
- **Networking**: TCP (full state machine), UDP, ICMP, ARP, software loopback
- **Userspace**: Busybox ash (47 applets), custom libc, init system

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
