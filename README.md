# Linux Containers From Scratch (MVP)

This project implements a minimal Linux container runtime in ~500 lines of C code, demonstrating how modern containerization technologies work at the kernel level.

**⚠️ Disclaimer**: This project reproduces and modifies the code from Lizzie Dixon’s blog post: [Linux Containers in 500 LOC](https://blog.lizzie.io/linux-containers-in-500-loc.html). The code has been adapted, annotated, and extended for educational purposes. This is an **educational project only**. Do NOT use in production. Use Docker, Podman, or other established container runtimes for real workloads.

---

## Table of Contents

1. [Introduction](#introduction)
2. [What Are Linux Containers](#what-are-linux-containers)
3. [Prerequisites & Setup](#prerequisites--setup)
4. [Quick Start](#quick-start)
5. [Architecture Overview](#architecture-overview)
6. [Core Technologies Deep Dive](#core-technologies-deep-dive)
   - [Namespaces](#namespaces)
   - [Capabilities](#capabilities)
   - [Cgroups](#cgroups-control-groups)
   - [Seccomp](#seccomp-system-call-filtering)
   - [Filesystem Isolation](#filesystem-isolation-pivot_root)
7. [Security Analysis](#security-analysis)
8. [Implementation Details](#implementation-details)
9. [Comparison with Docker](#comparison-with-docker)
10. [Troubleshooting](#troubleshooting)

---

## Introduction

### What This Project Does

This implementation demonstrates the fundamental Linux kernel features that enable container isolation:

- **Process isolation** via PID namespaces
- **Filesystem isolation** via mount namespaces and pivot_root
- **Network isolation** via network namespaces
- **Privilege limitation** via capabilities
- **Resource control** via cgroups
- **System call filtering** via seccomp

### Learning Objectives

After studying this code, you'll understand:

1. How containers achieve process isolation without virtual machines
2. How Linux capabilities subdivide root privileges
3. How cgroups prevent resource exhaustion
4. How seccomp filters dangerous system calls
5. How pivot_root creates true filesystem isolation
6. Why Docker needs ~1 million lines when we only need 500

### Why 500 Lines?

This is the minimal implementation that demonstrates all core containerization features. Real container runtimes add:
- Image management and layered filesystems
- Advanced networking (bridges, port mapping, DNS)
- Volume management and persistence
- Orchestration integration
- Production-grade error handling
- Many more features

---

## What Are Linux Containers

### Conceptual Overview

**Containers** are lightweight, isolated execution environments that share the host kernel while maintaining separation. Unlike VMs, they don't require a separate OS instance.

```
┌─────────────────────────────────────┐     ┌─────────────────────────────────────┐
│         Virtual Machines            │     │           Containers                │
├─────────────────────────────────────┤     ├─────────────────────────────────────┤
│  App A  │  App B  │  App C          │     │  App A  │  App B  │  App C          │
│  Bins   │  Bins   │  Bins           │     │  Bins   │  Bins   │  Bins           │
│  Libs   │  Libs   │  Libs           │     │  Libs   │  Libs   │  Libs           │
├─────────┼─────────┼─────────────────┤     ├─────────┼─────────┼─────────────────┤
│ Guest OS│ Guest OS│ Guest OS        │     │      Container Runtime              │
├─────────┴─────────┴─────────────────┤     ├─────────────────────────────────────┤
│         Hypervisor                  │     │         Host OS (Shared)            │
├─────────────────────────────────────┤     ├─────────────────────────────────────┤
│         Host OS                     │     │         Hardware                    │
├─────────────────────────────────────┤     └─────────────────────────────────────┘
│         Hardware                    │     
└─────────────────────────────────────┘     
```

### Key Characteristics

| Aspect | Containers | Virtual Machines |
|--------|-----------|------------------|
| **Startup Time** | Milliseconds | Seconds to minutes |
| **Memory Overhead** | MBs | GBs |
| **Isolation** | Process-level (kernel-enforced) | Hardware-level (hypervisor) |
| **Kernel** | Shared with host | Separate per VM |
| **Portability** | High (same kernel) | Medium (different kernels OK) |
| **Security** | Good (namespaces + capabilities) | Excellent (hardware isolation) |

---

## Prerequisites & Setup

### System Requirements

- **Linux Kernel**: 4.7.x or 4.8.x (hardcoded for this implementation)
- **Architecture**: x86_64
- **Root Access**: Required for namespace creation
- **Cgroups**: Must be mounted at `/sys/fs/cgroup/`

### Build Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential libcap-dev libseccomp-dev

# Fedora/RHEL/CentOS
sudo dnf install gcc libcap-devel libseccomp-devel

# Arch Linux
sudo pacman -S gcc libcap libseccomp
```

### Verify Cgroups

```bash
# Check if cgroups are mounted
ls /sys/fs/cgroup/
# Should show: blkio cpu cpuacct cpuset devices freezer memory net_cls pids ...

# If not mounted, mount them:
sudo mount -t tmpfs cgroup_root /sys/fs/cgroup
for subsys in memory cpu pids blkio; do
    sudo mkdir -p /sys/fs/cgroup/$subsys
    sudo mount -t cgroup -o $subsys cgroup_$subsys /sys/fs/cgroup/$subsys
done
```

### Prepare Container Filesystem

You need a complete Linux filesystem (rootfs) for the container:

#### Option 1: BusyBox (Minimal, ~2MB)

```bash
mkdir -p ~/rootfs
cd ~/rootfs
wget https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
chmod +x busybox
for cmd in sh ls cat echo ps mount; do
    ln -s busybox $cmd
done
mkdir -p bin lib etc proc sys dev tmp
mv busybox sh ls cat echo ps mount bin/
```

#### Option 2: Alpine Linux (Small, ~5MB)

```bash
mkdir -p ~/alpine-rootfs
cd ~/alpine-rootfs
wget https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz
tar xzf alpine-minirootfs-3.19.0-x86_64.tar.gz
```

#### Option 3: Debian (Full-featured, ~120MB)

```bash
sudo debootstrap stable ~/debian-rootfs http://deb.debian.org/debian/
```

---

## Quick Start

### Compilation

```bash
gcc -Wall -Werror -lcap -lseccomp contained.c -o contained
```

**Compiler flags**:
- `-Wall -Werror`: Enable all warnings and treat them as errors
- `-lcap`: Link against libcap (capability library)
- `-lseccomp`: Link against libseccomp (seccomp filter library)

### Basic Usage

```bash
sudo ./contained -m <rootfs_path> -u <uid> -c <command> [args...]
```

**Arguments**:
- `-m <path>`: Path to container root filesystem
- `-u <uid>`: User ID to run as (typically 0 for root)
- `-c <cmd>`: Command to execute (everything after `-c` belongs to the command)

### Examples

**Run interactive shell**:
```bash
sudo ./contained -m ~/alpine-rootfs/ -u 0 -c /bin/sh
```

**Run specific command**:
```bash
sudo ./contained -m ~/alpine-rootfs/ -u 0 -c /bin/ls -la /
```

**Run as non-root user**:
```bash
sudo ./contained -m ~/alpine-rootfs/ -u 1000 -c /bin/sh
```

### Expected Output

```
=> validating Linux version...4.8.0-59-generic on x86_64.
=> setting cgroups...memory...cpu...pids...blkio...done.
=> setting rlimit...done.
=> remounting everything with MS_PRIVATE...remounted.
=> making a temp directory and a bind mount there...done.
=> pivoting root...done.
=> unmounting /oldroot.XXXXXX...done.
=> trying a user namespace...writing /proc/1234/uid_map...writing /proc/1234/gid_map...done.
=> switching to uid 0 / gid 0...done.
=> dropping capabilities...bounding...inheritable...done.
=> filtering syscalls...done.
/ # whoami
root
/ # hostname
05fe5c-three-of-pentacles
/ # ps aux
PID   USER     COMMAND
    1 root     /bin/sh
/ # exit
=> cleaning cgroups...done.
```

---

## Architecture Overview

### Program Flow

```
┌─────────────── PARENT PROCESS (host) ────────────────┐
│  1. Parse arguments                                  │
│  2. Validate kernel version (4.7 or 4.8)             │
│  3. Generate random hostname (tarot card names)      │
│  4. Create socketpair for parent-child communication │
│  5. Set up cgroups (BEFORE forking)                  │
│  6. Allocate stack for child                         │
│  7. clone() with namespace flags                     │
└──────────────────────┬───────────────────────────────┘
                       │
                       ├─────────────────────────────────┐
                       ▼                                 ▼
    ┌─── PARENT ────────────────┐      ┌─── CHILD (container) ──────────┐
    │  8. Wait for child signals│      │  1. Set hostname               │
    │  9. Write UID/GID mappings│      │  2. Isolate filesystem         │
    │ 10. Signal completion     │      │     - Bind mount rootfs        │
    │ 11. Wait for child exit   │      │     - pivot_root               │
    │ 12. Clean up cgroups      │      │     - Unmount old root         │
    └───────────────────────────┘      │  3. Setup user namespace       │
                                       │  4. Switch to target UID       │
                                       │  5. Drop capabilities          │
                                       │  6. Filter syscalls (seccomp)  │
                                       │  7. Close coordination socket  │
                                       │  8. execve() target command    │
                                       └────────────────────────────────┘
```

### Core Data Structure

```c
struct child_config {
    int argc;        // Number of args for container command
    uid_t uid;       // UID to run as inside container
    int fd;          // Socket for parent-child sync
    char *hostname;  // Container hostname
    char **argv;     // Command and arguments
    char *mount_dir; // Path to container rootfs
};
```

This structure passes all necessary information from parent to child through the `clone()` syscall.

---

## Core Technologies Deep Dive

## Namespaces

Namespaces are the foundation of container isolation. They create separate instances of global system resources.

### Overview of Namespace Types

| Namespace | Flag | Isolates |
|-----------|------|----------|
| **Mount** | `CLONE_NEWNS` | Filesystem mount points |
| **PID** | `CLONE_NEWPID` | Process ID numbers |
| **Network** | `CLONE_NEWNET` | Network devices, stacks, ports |
| **IPC** | `CLONE_NEWIPC` | System V IPC, POSIX message queues |
| **UTS** | `CLONE_NEWUTS` | Hostname and domain name |
| **User** | `CLONE_NEWUSER` | User and group IDs |
| **Cgroup** | `CLONE_NEWCGROUP` | Cgroup root directory |

### Creating Namespaces with clone()

```c
int flags = CLONE_NEWNS      // Mount namespace
          | CLONE_NEWCGROUP  // Cgroup namespace  
          | CLONE_NEWPID     // PID namespace
          | CLONE_NEWIPC     // IPC namespace
          | CLONE_NEWNET     // Network namespace
          | CLONE_NEWUTS;    // UTS namespace (hostname)

// Allocate stack (required for clone)
#define STACK_SIZE (1024 * 1024)
char *stack = malloc(STACK_SIZE);

// Create child with new namespaces
pid_t child_pid = clone(child_function, 
                       stack + STACK_SIZE,  // Stack grows down
                       flags | SIGCHLD,     // Send SIGCHLD on exit
                       &config);            // Argument to child_function
```

### Mount Namespace (CLONE_NEWNS)

**Purpose**: Isolate filesystem mount points

**What it provides**:
- Separate view of mounted filesystems
- Container can have its own `/`
- Changes to mounts don't affect host

**Example isolation**:

```bash
# Host
$ df -h /
/dev/sda1  100G  50G  50G  50% /

# Container (after pivot_root)
$ df -h /
overlay    10G   2G   8G  20% /
# Different filesystem entirely
```

**Implementation steps**:
1. Make all mounts private (`MS_PRIVATE`)
2. Bind mount container rootfs to temp directory
3. Use `pivot_root()` to swap roots
4. Unmount old root

**Security benefit**: Container cannot access host files, cannot see host mounts.

### PID Namespace (CLONE_NEWPID)

**Purpose**: Isolate process ID number space

**Key features**:
- First process becomes PID 1 (like init)
- Can only see processes in same namespace
- When PID 1 exits, all children get SIGKILL

**Example**:

```bash
# Host
$ ps aux | wc -l
157  # Many processes

# Container
$ ps aux
PID   USER     COMMAND
    1 root     /bin/sh
    7 root     ps aux
# Only 2 processes visible
```

**The special role of PID 1**:
- Reaps orphaned processes
- Has special signal handling (many signals ignored by default)
- When it exits, namespace is destroyed

**Security benefit**: Container processes cannot signal, ptrace, or inspect host processes.

### Network Namespace (CLONE_NEWNET)

**Purpose**: Isolate network stack

**What's isolated**:
- Network interfaces (eth0, lo, etc.)
- IP addresses and routing tables
- Firewall rules (iptables)
- Port numbers (multiple containers can bind to same port)

**Initial state**: Only loopback interface (down)

```bash
# In new network namespace
$ ip link
1: lo: <LOOPBACK> mtu 65536 state DOWN
# Only lo, and it's down!
```

**Note**: This implementation doesn't configure networking. Production containers would:
1. Create virtual ethernet pair (veth)
2. Move one end into container namespace
3. Configure routing/NAT on host side

**Security benefit**: Container's network activity is completely isolated from host.

### IPC Namespace (CLONE_NEWIPC)

**Purpose**: Isolate System V IPC and POSIX message queues

**What's isolated**:
- Message queues (`msgget`, `msgsnd`, `msgrcv`)
- Semaphores (`semget`, `semop`)
- Shared memory (`shmget`, `shmat`)

**Why it matters**:
```c
// Without IPC namespace:
// Container creates shared memory
int shmid = shmget(0x1234, SIZE, IPC_CREAT);

// Host can access it:
void *mem = shmat(shmid, NULL, 0);  // Access container's memory!

// With IPC namespace:
// Container's IPC objects invisible to host
```

**Security benefit**: Prevents information leaks through IPC, prevents DoS by exhausting IPC resources.

### UTS Namespace (CLONE_NEWUTS)

**Purpose**: Isolate hostname and domain name

**Example**:
```c
// In container:
sethostname("my-container", 12);

// Check:
char name[256];
gethostname(name, sizeof(name));
// Returns: "my-container"

// On host:
gethostname(name, sizeof(name));  
// Returns: "host-system" (unchanged)
```

**This implementation**: Generates random hostnames from tarot cards
- Format: `[timestamp]-[card-name]`
- Example: `05fe5c-three-of-pentacles`
- Ensures uniqueness and adds whimsy to logs

### Cgroup Namespace (CLONE_NEWCGROUP)

**Purpose**: Virtualize cgroup hierarchy view

**What it does**:
- Makes container's cgroup appear as root cgroup
- Hides host's cgroup structure

**Without cgroup namespace**:
```bash
$ cat /proc/self/cgroup
11:memory:/docker/a1b2c3/container-name
# Shows full path including host structure
```

**With cgroup namespace**:
```bash
$ cat /proc/self/cgroup  
11:memory:/
# Appears to be at root
```

### User Namespaces (Optional in this Implementation)

**Purpose**: Map UID/GID between container and host

**The problem they solve**:
- Container needs root (UID 0) for many operations
- But real root is dangerous if container escapes
- Solution: UID 0 in container → UID 10000 on host

**Mapping example**:
```
Container UID  →  Host UID
     0         →   10000
     1         →   10001
   ...         →   ...
  1999         →   11999
```

**Why optional**: Many distros disable unprivileged user namespaces due to security concerns. This code tries to use them but continues if unavailable.

**Implementation**:
1. Child calls `unshare(CLONE_NEWUSER)`
2. Child notifies parent via socket
3. Parent writes to `/proc/[pid]/uid_map` and `/proc/[pid]/gid_map`
4. Child switches to target UID

---

## Capabilities

Capabilities divide root privileges into ~40 granular permissions.

### Traditional vs Capability Model

**Traditional UNIX**:
```c
if (uid == 0) {
    /* Can do EVERYTHING */
} else {
    /* Very limited access */
}
```

**With Capabilities**:
```c
if (has_capability(CAP_NET_ADMIN)) {
    /* Can configure network */
}
if (has_capability(CAP_SYS_ADMIN)) {
    /* Can mount filesystems */
}
// Each operation checked independently
```

### Capability Sets

Each process has five capability sets:

1. **Permitted (P)**: Capabilities the process may use
2. **Effective (E)**: Currently active capabilities  
3. **Inheritable (I)**: Capabilities that can pass to children
4. **Bounding (B)**: Upper limit, cannot be raised
5. **Ambient (A)**: Kept across execve()

### Our Dropping Strategy

**Goal**: Prevent gaining capabilities through `execve()` of setcap/setuid binaries

**Two-step approach**:

1. **Drop from bounding set** (irreversible):
```c
for (size_t i = 0; i < num_caps; i++) {
    prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0);
}
```

2. **Clear inheritable set**:
```c
cap_t caps = cap_get_proc();
cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR);
cap_set_proc(caps);
```

**Why both?**: Even if we drop current capabilities, execve() could regain them from file capabilities. Clearing bounding + inheritable prevents this.

### Dangerous Capabilities We Drop

#### CAP_DAC_READ_SEARCH  
- **Danger**: `open_by_handle_at()` can access files by inode, bypassing mount namespace
- **Attack**: Read `/etc/shadow` by brute-forcing inode numbers
- **Used in**: "shocker" Docker escape (2014)

#### CAP_MKNOD
- **Danger**: Create device files
- **Attack**:
```c
mknod("/disk", S_IFBLK, makedev(8, 0));  // /dev/sda
mount("/disk", "/mnt", "ext4", 0, NULL);
// Now can read/write entire host disk
```

#### CAP_SYS_ADMIN
- **Danger**: Allows ~200 different operations (mount, sethostname, many ioctls, etc.)
- **Too powerful**: Catch-all for administrative operations

#### CAP_SYS_MODULE
- **Danger**: Load/unload kernel modules
- **Attack**: Load malicious module → complete system compromise
- **Impact**: Runs in kernel space with full privileges

#### CAP_SYS_BOOT
- **Danger**: Reboot system, load new kernel
- **Attack**: `reboot()` or `kexec_load()` → DoS or compromise

#### CAP_SYS_RAWIO
- **Danger**: Access `/dev/mem`, `/dev/kmem`, I/O ports
- **Attack**: Read/write physical memory, modify kernel code

#### CAP_FSETID
- **Danger**: Modify setuid files without losing setuid bit
- **Attack**: Create setuid-root binary → any user can gain root

**Full list of dropped capabilities**: See `capabilities()` function in code.

### Safe Capabilities We Keep

- **CAP_NET_ADMIN**: Safe due to network namespace isolation
- **CAP_DAC_OVERRIDE**: Only works in mount namespace  
- **CAP_SYS_PTRACE**: Only works in PID namespace
- **CAP_KILL**: Only works in PID namespace
- **CAP_SETUID/CAP_SETGID**: Needed for processes to drop privileges

---

## Cgroups (Control Groups)

Cgroups limit resource consumption to prevent DoS attacks.

### What Cgroups Control

| Controller | Limits |
|------------|--------|
| **memory** | RAM usage (user + kernel) |
| **cpu** | CPU time shares |
| **pids** | Number of processes |
| **blkio** | Disk I/O bandwidth |

### Limits

```c
#define MEMORY "1073741824"  // 1 GB
#define SHARES "256"         // 256/1024 = 25% CPU
#define PIDS "64"            // Max 64 processes
#define WEIGHT "10"          // Low I/O priority
```

### How Cgroups Work (v1)

**Directory structure**:
```
/sys/fs/cgroup/memory/[hostname]/
├── memory.limit_in_bytes       (write limit here)
├── memory.kmem.limit_in_bytes  (kernel memory limit)
├── tasks                       (write PID to add process)
└── ...
```

**Creating a cgroup**:
```bash
# 1. Create directory
mkdir /sys/fs/cgroup/memory/container-name

# 2. Write settings
echo "1073741824" > /sys/fs/cgroup/memory/container-name/memory.limit_in_bytes

# 3. Add process
echo $$ > /sys/fs/cgroup/memory/container-name/tasks
```

**In this code**:
```c
// Create cgroup
mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR);

// Write limit
int fd = open(path, O_WRONLY);
write(fd, "1073741824", 10);

// Add current process (and all future children)
write(tasks_fd, "0", 2);  // "0" = current process
```

### Why Cgroups Matter

**Without cgroups**:
```c
// Container can exhaust all memory
while (1) {
    malloc(1024*1024*1024);  // Allocate 1GB
}
// System runs out of memory → OOM killer starts killing processes
```

**With cgroups**:
```c
// Container limited to 1GB
while (1) {
    malloc(1024*1024*1024);  
}
// Container's processes killed when reaching 1GB
// Host system unaffected
```

### Additional Limit: rlimit

We also set file descriptor limit:
```c
setrlimit(RLIMIT_NOFILE, &(struct rlimit){
    .rlim_max = 64,
    .rlim_cur = 64
});
```

**Why**: File descriptor limits are per-user, not per-container. Without this, container could exhaust user's FD quota.

---

## Seccomp (System Call Filtering)

Seccomp filters which system calls a process can make.

### Our Approach

**Default**: Allow all (blacklist approach)
```c
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
```

**Better approach**: Deny all, allow specific calls (whitelist)
- More secure
- Harder to get right
- Used by Docker

### System Calls We Block

#### Preventing Setuid Binary Creation
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID));
```

**Blocks**: `chmod(file, mode | S_ISUID)`  
**Allows**: `chmod(file, 0644)`
**Why**: Without user namespaces, setuid binaries persist on host disk

#### Blocking User Namespace Creation
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
```

**Why**: New user namespaces grant capabilities

#### Terminal Injection (TIOCSTI)
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI));
```

**Attack**: Inject keystrokes into user's terminal
**Example**: Inject `"rm -rf / # "` into terminal buffer

#### Kernel Keyring
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0);
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0);
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0);
```

**Why**: Kernel keyring not namespaced, could access system secrets

#### Ptrace
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0);
```

**Why**: Before kernel 4.8, could bypass seccomp entirely

#### NUMA Operations
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0);
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0);
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0);
```

**Why**: Could cause DoS on NUMA systems

#### Userfaultfd
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0);
```

**Why**: Used in kernel exploits to win race conditions

#### Performance Monitoring
```c
seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0);
```

**Why**: Can leak kernel addresses, defeat KASLR

---

## Filesystem Isolation (pivot_root)

### Why Not chroot?

**chroot is escapable**:
```c
// Escape method 1:
int fd = open("/", O_RDONLY);  // Before chroot
chroot("/container");
fchdir(fd);    // Back to real /
chroot(".");   // Real / is now root

// Escape method 2:
mkdir("out");
chroot("out");
for (int i = 0; i < 100; i++) chdir("..");
chroot(".");   // Likely back to real /
```

**pivot_root is secure**: Designed specifically for containers, cannot be escaped.

### How pivot_root Works

**Step 1: Make mounts private**
```c
mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
```
Prevents mount propagation between namespaces.

**Step 2: Bind mount container rootfs**
```c
char mount_dir[] = "/tmp/tmp.XXXXXX";
mkdtemp(mount_dir);  // Creates /tmp/tmp.aB3XyZ

mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL);
// Container rootfs now visible at /tmp/tmp.aB3XyZ
```

**Step 3: Create directory for old root**
```c
char inner[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
memcpy(inner, mount_dir, sizeof(mount_dir) - 1);
mkdtemp(inner);  // Creates /tmp/tmp.aB3XyZ/oldroot.qR8sT1
```

**Step 4: Pivot**
```c
pivot_root(mount_dir, inner_mount_dir);
// New / is container rootfs
// Old / is at /oldroot.qR8sT1
```

**Step 5: Clean up old root**
```c
char *old_root_dir = basename(inner_mount_dir);
char old_root[PATH_MAX] = {"/"};
strcpy(&old_root[1], old_root_dir);  // "/oldroot.qR8sT1"

chdir("/");
umount2(old_root, MNT_DETACH);  // Lazy unmount
rmdir(old_root);
// Old root completely gone
```

**Result**: Container has no way to access host filesystem.

---

## Security Analysis

### Attack Surface

**What could go wrong**:

1. **Kernel vulnerabilities**: Shared kernel means kernel exploit escapes container
2. **Capability bypass**: Missed a dangerous capability
3. **Syscall bypass**: Missed a dangerous syscall
4. **Namespace escape**: Bug in namespace implementation
5. **Resource exhaustion**: Cgroup limits too high or bypassed

### Known Limitations

**1. Kernel version dependency**
- Hardcoded to 4.7/4.8
- Newer kernels may have new syscalls/capabilities we don't block
- Solution: Update blacklists for each kernel version

**2. Blacklist approach**
- Easier to get wrong (might miss something)
- Whitelist (default deny) is more secure
- Docker uses whitelist

**3. No network configuration**
- Container has only loopback
- Production needs veth pairs, bridges, NAT

**4. Optional user namespaces**
- More secure with them
- Less secure without them
- Many distros disable them

**5. Root required**
- Must run as root to create namespaces
- Rootless containers exist but complex

### Real-World Container Escapes

**CVE-2019-5736 (runc)**:
- Exploit in runc
- Overwrite host's runc binary
- Escape on next container start

**shocker.c (2014)**:
- Used `CAP_DAC_READ_SEARCH`
- Read host files via `open_by_handle_at()`
- We drop this capability

**Dirty COW (2016)**:
- Kernel vulnerability
- Worked from containers
- Demonstrates: kernel exploits bypass all containerization

### Defense in Depth

This implementation uses multiple layers:

1. **Namespaces**: Process isolation
2. **Capabilities**: Limit root powers
3. **Seccomp**: Block dangerous syscalls
4. **Cgroups**: Prevent resource exhaustion
5. **pivot_root**: Filesystem isolation

All layers must be bypassed to escape.

---

## Implementation Details

### Command-Line Parsing

```c
while ((option = getopt(argc, argv, "c:m:u:"))) {
    switch (option) {
    case 'c':
        // Everything after -c belongs to container command
        config.argc = argc - last_optind - 1;
        config.argv = &argv[argc - config.argc];
        goto finish_options;  // Stop parsing
    case 'm':
        config.mount_dir = optarg;
        break;
    case 'u':
        sscanf(optarg, "%d", &config.uid);
        break;
    }
    last_optind = optind;
}
```

**Key point**: `-c` stops option parsing because everything after belongs to the container command.

### Parent-Child Communication

Uses socketpair for synchronization:

```c
int sockets[2];
socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets);
fcntl(sockets[0], F_SETFD, FD_CLOEXEC);  // Close on exec
config.fd = sockets[1];  // Child gets this one
```

**Protocol**:
1. Child attempts user namespace creation
2. Child writes success/failure to parent
3. Parent writes UID/GID maps (if successful)
4. Parent writes completion signal
5. Child proceeds

### Stack Allocation for clone()

```c
#define STACK_SIZE (1024 * 1024)
char *stack = malloc(STACK_SIZE);

clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config);
//           ^^^^^^^^^^^^^^^^^^^^^
//           Stack grows downward on x86
```

**Why `stack + STACK_SIZE`?**  
x86 stacks grow downward (toward lower addresses). We pass the high address, and it grows down.

### Hostname Generation

Random hostnames from tarot cards:

```c
struct timespec now;
clock_gettime(CLOCK_MONOTONIC, &now);
size_t ix = now.tv_nsec % 78;  // 78 tarot cards

if (ix < 22) {
    snprintf(buff, len, "%05lx-%s", now.tv_sec, major[ix]);
    // Example: "05fe5c-fool"
} else {
    ix -= 22;
    snprintf(buff, len, "%05lx-%s-of-%s",
             now.tv_sec,
             minor[ix % 14],
             suits[ix / 14]);
    // Example: "05fe5c-three-of-pentacles"
}
```

**Format**: `[timestamp]-[card-name]`
- Timestamp ensures uniqueness
- Card name is memorable

---

## Comparison with Docker

### What Docker Adds

**Image Management**:
- Layered filesystems (overlay2)
- Image registry (Docker Hub)
- Build system (Dockerfile)
- Image caching and versioning

**Networking**:
- Virtual ethernet pairs (veth)
- Bridge network configuration
- Port mapping (`-p 80:80`)
- DNS resolution
- Network drivers (bridge, host, macvlan)

**Storage**:
- Volumes (persistent storage)
- Bind mounts (host directory mapping)
- tmpfs mounts

**Resource Management**:
- More granular cgroup controls
- CPU pinning
- Memory swappiness
- Device access control

**Security**:
- AppArmor/SELinux profiles
- Seccomp whitelist (default deny)
- User namespace support
- Read-only root filesystem option

**Orchestration**:
- Docker Compose (multi-container)
- Docker Swarm (clustering)
- Health checks
- Auto-restart policies

**Developer Experience**:
- Simple CLI (`docker run`, `docker build`)
- Dockerfile for reproducible builds
- Image layers for efficiency
- Extensive documentation

### What's the Same

**Core isolation mechanisms**:
- Same namespace types
- Same capability system
- Same cgroup controllers
- Same seccomp filtering

**Kernel features**:
- Both rely on Linux kernel
- Both use clone() for process creation
- Both use pivot_root for filesystem isolation

---

## Troubleshooting

### Permission Denied Creating Cgroups

**Symptom**:
```
=> setting cgroups...memory...mkdir /sys/fs/cgroup/memory/hostname failed: Permission denied
```

**Solution**:
```bash
# Must run as root
sudo ./contained ...

# Check if cgroups are mounted
ls /sys/fs/cgroup/
```

### User Namespace Fails

**Symptom**:
```
=> trying a user namespace...unsupported? continuing.
```

**Explanation**: User namespaces are disabled on many systems.

**Check**:
```bash
# Ubuntu/Debian
sysctl kernel.unprivileged_userns_clone
# 0 = disabled, 1 = enabled

# Enable (if allowed):
sudo sysctl kernel.unprivileged_userns_clone=1
```

**Note**: Program continues anyway but is less secure.

### Wrong Kernel Version

**Symptom**:
```
=> validating Linux version...expected 4.7.x or 4.8.x: 5.10.0
```

**Solution**: This implementation only works on kernel 4.7 or 4.8. For other kernels, you'd need to audit all capabilities and syscalls for that version.

### Cannot Execute Command

**Symptom**:
```
execve failed! No such file or directory.
```

**Cause**: Command not in container rootfs, or missing shared libraries.

**Solution**:
```bash
# Ensure command exists
ls ~/alpine-rootfs/bin/sh

# Check for libraries
ldd ~/alpine-rootfs/bin/sh
# All libraries must exist in container rootfs
```

### Container Can't Access Network

**Symptom**: `ping` doesn't work, no internet access.

**Explanation**: This is expected. Implementation doesn't configure networking.

**Workaround**: Use `--net=host` in a real container runtime, or configure veth pairs manually (beyond scope of this minimal implementation).

---

## License

- **Code and Documentation**: This repository, including all code, comments, explanations, and examples, is licensed under the [GNU GPLv3](LICENSE).  
- Portions of the code are derived from [Lizzie Dixon’s blog](https://blog.lizzie.io/linux-containers-in-500-loc.html) and are included under GPLv3 in accordance with the original license.

---

## Credits

- Lizzie Dixon – Original code and blog post inspiration  
- Linux kernel developers  
- Docker and container runtime maintainers  
- Security researchers who contributed knowledge to container isolation and vulnerabilities
