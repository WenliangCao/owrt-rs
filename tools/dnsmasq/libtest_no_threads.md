# Selected libtest thread-creation failure

Linux test launcher only; not product code or a production seccomp policy.
Compile on the target Linux host, or with its matching SDK compiler:

```sh
cc -O2 -std=c11 -Wall -Wextra -Werror libtest_no_threads.c -o libtest_no_threads
./libtest_no_threads /private/probe-tests/lib-dnsmasq_rs EXACT_FORK_TEST \
  --exact --nocapture --test-threads=1
```

Use only for explicitly selected fork/process tests. Do not wrap the full test
suite. The launcher sets `NO_NEW_PRIVS`, installs the filter, then `execvp`s the
target. The target and descendants inherit the filter: `clone3` returns
`ENOSYS`; `clone` with `CLONE_THREAD` returns `EAGAIN`; other calls are allowed.
The filter cannot inspect the pointed-to `clone3` flags, so every `clone3`
request is rejected to permit libc's `clone` fallback. Actual libtest fallback
and fork/posix_spawn behavior must be verified separately on the target libc.

Supported ABIs: Linux x86_64 and little-endian aarch64. An unexpected audit
architecture terminates the process with `SIGSYS`; x32 syscall numbers are
also checked for clone/clone3. Usage exits 2, setup failure exits 125, exec
failure exits 126 (127 for `ENOENT`). Successful exec preserves target status.

Run inside an already prepared unprivileged test environment. `NO_NEW_PRIVS`
prevents privilege acquisition across exec; this is not an unmodified
production-jail boundary test. No router execution is part of this tool.

Filter API reference: [Linux seccomp filter documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
