#!/usr/bin/env python3
"""Linux-only accept recovery probe on a private socket, without root or a router.

Use a dynamically linked GNU ubusd-rs so LD_PRELOAD can wrap accept4. An
existing connection stays open and answers PING throughout each fault. The
EMFILE case exhausts only the child process's descriptor limit, then closes
dummy /dev/null descriptors without disconnecting any bus client. Other
errors are injected at accept4 for 350 ms (or once for the transient cases).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import struct
import subprocess
import sys
import tempfile
import time


INJECTOR = r'''
#define _GNU_SOURCE
#include <sys/socket.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
static const char *trigger;
static int audit_fd, error_number, one_shot, real_emfile;
static int dummy[256], dummy_count;
static atomic_int started, released;

static void *release_resources(void *unused) {
    (void)unused;
    struct timespec delay = { .tv_nsec = 350000000 };
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
    for (int i = 0; i < dummy_count; i++) close(dummy[i]);
    atomic_store(&released, 1);
    dprintf(audit_fd, "released\n");
    return NULL;
}

__attribute__((constructor)) static void init(void) {
    real_accept4 = dlsym(RTLD_NEXT, "accept4");
    trigger = getenv("R93_TRIGGER");
    error_number = atoi(getenv("R93_ERRNO"));
    one_shot = atoi(getenv("R93_ONCE"));
    real_emfile = atoi(getenv("R93_EMFILE"));
    audit_fd = open(getenv("R93_AUDIT"), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!real_accept4 || audit_fd < 0) _exit(90);
}

int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    if (!atomic_load(&started) && access(trigger, F_OK) == 0) {
        atomic_store(&started, 1);
        if (real_emfile) {
            while (dummy_count < 256) {
                int d = open("/dev/null", O_RDONLY | O_CLOEXEC);
                if (d < 0) break;
                dummy[dummy_count++] = d;
            }
            if (errno != EMFILE) _exit(91);
        }
        if (!one_shot) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, release_resources, NULL)) _exit(92);
            pthread_detach(thread);
        }
        if (one_shot) {
            atomic_store(&released, 1);
            dprintf(audit_fd, "injected %d\nreleased\n", error_number);
            errno = error_number;
            return -1;
        }
    }
    if (atomic_load(&started) && !atomic_load(&released)) {
        if (real_emfile) {
            int result = real_accept4(fd, addr, len, flags);
            int saved = errno;
            dprintf(audit_fd, "kernel %d %d\n", result, saved);
            errno = saved;
            return result;
        }
        dprintf(audit_fd, "injected %d\n", error_number);
        errno = error_number;
        return -1;
    }
    return real_accept4(fd, addr, len, flags);
}
'''

CASES = {
    "eintr_once": (4, True, False),
    "econnaborted_once": (103, True, False),
    "eintr_storm": (4, False, False),
    "enfile": (23, False, False),
    "enomem": (12, False, False),
    "enobufs": (105, False, False),
    "unknown_error": (22, False, False),
    "emfile_kernel": (24, False, True),
}


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("bus closed an existing connection")
        result.extend(chunk)
    return bytes(result)


def read_message(sock):
    head = read_exact(sock, 12)
    version, kind, seq, peer, length = struct.unpack("!BBHII", head)
    body = read_exact(sock, (length & 0xFFFFFF) - 4)
    return kind, seq, peer, body


def ping(sock, seq):
    before = time.monotonic()
    sock.sendall(struct.pack("!BBHII", 0, 3, seq, 0, 4))
    assert read_message(sock)[:2] == (2, seq)
    assert read_message(sock)[:2] == (1, seq)
    return time.monotonic() - before


def child_limits():
    resource.setrlimit(resource.RLIMIT_NOFILE, (96, 96))


def run_case(binary, injector, directory, case):
    directory.mkdir()
    (directory / "acl").mkdir()
    code, once, emfile = CASES[case]
    env = {**os.environ, "LD_PRELOAD": str(injector),
           "R93_TRIGGER": str(directory / "trigger"),
           "R93_AUDIT": str(directory / "accept.log"),
           "R93_ERRNO": str(code), "R93_ONCE": str(int(once)), "R93_EMFILE": str(int(emfile))}
    # Evidence may live below a long immutable qualification path. Keep the
    # transient AF_UNIX name in this run's existing short private tempdir.
    sockpath = str(injector.parent / (case + ".sock"))
    if len(os.fsencode(sockpath)) >= 108:
        raise ValueError("private accept socket exceeds Linux sun_path")
    row = {"case": case, "passed": False, "socket_path_bytes": len(os.fsencode(sockpath))}
    with (directory / "daemon.log").open("wb") as log:
        daemon = subprocess.Popen([str(binary), "-s", sockpath, "-A", str(directory / "acl")],
                                  env=env, stdout=log, stderr=log, preexec_fn=child_limits)
        try:
            until = time.monotonic() + 3
            while not Path(sockpath).exists() and time.monotonic() < until:
                if daemon.poll() is not None:
                    raise RuntimeError("daemon exited before listening")
                time.sleep(.01)
            with socket.socket(socket.AF_UNIX) as existing, socket.socket(socket.AF_UNIX) as queued:
                existing.settimeout(1)
                existing.connect(sockpath)
                assert read_message(existing)[0] == 0
                ping(existing, 1)
                (directory / "trigger").touch()
                queued.settimeout(.02)
                queued.connect(sockpath)
                started = time.monotonic()
                seq, worst_ping, recovered = 2, 0.0, False
                while time.monotonic() - started < 2:
                    worst_ping = max(worst_ping, ping(existing, seq))
                    seq += 1
                    try:
                        if queued.recv(1, socket.MSG_PEEK):
                            queued.settimeout(1)
                            assert read_message(queued)[0] == 0
                            recovered = True
                            break
                    except TimeoutError:
                        pass
                elapsed = time.monotonic() - started
                # Both sockets are still open when these checks run.
                ping(existing, seq)
                lines = (directory / "accept.log").read_text().splitlines()
                failures = [line for line in lines if line.startswith(("kernel ", "injected "))]
                kernel_emfile = not emfile or "kernel -1 24" in lines
                row.update(recovered_without_disconnect=recovered, released="released" in lines,
                           error_observed=bool(failures), kernel_emfile=kernel_emfile,
                           accept_failures=len(failures), existing_ping_count=seq,
                           worst_ping_ms=round(worst_ping * 1000, 3), recovery_ms=round(elapsed * 1000, 3),
                           daemon_alive=daemon.poll() is None)
                row["passed"] = (recovered and row["released"] and bool(failures) and kernel_emfile
                                 and len(failures) <= 100 and row["daemon_alive"])
        except Exception as error:
            row["error"] = str(error)
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=2)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
    (directory / "result.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("requires Linux and a dynamically linked GNU binary")
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="r93-accept-") as tmp:
        work = Path(tmp)
        source, injector = work / "inject.c", work / "inject.so"
        source.write_text(INJECTOR)
        subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-O2",
                        str(source), "-o", str(injector), "-ldl", "-pthread"], check=True)
        rows = []
        for case in args.cases:
            row = run_case(binary, injector, output / case, case)
            rows.append(row)
            print(json.dumps(row), flush=True)
    summary = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "cases": rows}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if not all(row["passed"] for row in rows):
        raise SystemExit("accept recovery failed; see summary.json")


if __name__ == "__main__":
    main()
