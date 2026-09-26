# Shared by the Linux netifd differential suite and standalone cases.
# Call with the tools directory and the case output directory.
netifd_test_ns_init() {
	_test_tools=$1
	_test_out=$(cd "$2" && pwd)
	mkdir -p "$_test_out/.tools" || return
	if [ -z "${NETIFD_TEST_NS_EXEC:-}" ]; then
		NETIFD_TEST_NS_EXEC=$_test_out/.tools/ns-exec
		cc -O2 -Wall -Wextra -Werror "$_test_tools/benchmark/ns_exec.c" \
			-o "$NETIFD_TEST_NS_EXEC" || return
	fi
	case "$NETIFD_TEST_NS_EXEC" in
		/*) ;;
		*) echo "NETIFD_TEST_NS_EXEC must be an absolute path" >&2; return 2 ;;
	esac
	[ -x "$NETIFD_TEST_NS_EXEC" ] || return 2
	export NETIFD_TEST_NS_EXEC
	sha256sum "$_test_tools/benchmark/ns_exec.c" "$NETIFD_TEST_NS_EXEC" \
		> "$_test_out/.tools/ns-exec.sha256" || return
}
