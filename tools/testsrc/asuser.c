/* Test-only: drop to a named user then exec. The sandbox rootfs's busybox has
 * no `su`, and r36 needs a genuine non-root client to exercise ubusd's ACLs.
 */
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc < 3) { fprintf(stderr, "usage: asuser <user> <cmd> [args...]\n"); return 2; }
	struct passwd *p = getpwnam(argv[1]);
	if (!p) { fprintf(stderr, "no such user %s\n", argv[1]); return 2; }
	if (setgroups(0, 0) || setgid(p->pw_gid) || setuid(p->pw_uid)) { perror("drop"); return 2; }
	execv(argv[2], &argv[2]);
	perror("exec");
	return 127;
}
