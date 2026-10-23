# Single entry point for the repository. Each crate stays independent (the
# OpenWrt package Makefiles copy crate directories one by one), so there is no
# root Cargo workspace on purpose.
COMPONENTS := platform ubus uci reload-config logd httpd fw4 rpcd ubusd netifd procd dnsmasq/platform dnsmasq odhcpd
VERSION ?= 25.12.5

.PHONY: check-netlink-consts test check-rust fmt-check check-tools check-harnesses check-benchmark check-toolchain check-toolchain-negative check-abi build apk image ci-image

test:
	@python3 tools/rust_check.py test

check-rust:
	@python3 tools/rust_check.py check

fmt-check:
	@python3 tools/rust_check.py fmt-check

build:
	@python3 tools/rust_check.py build

# rust-toolchain.toml is the single source of truth. tools/toolchain_identity.sh
# resolves the compiler Cargo will actually use -- $CARGO, $RUSTC, the wrappers
# and config overrides included -- and fails if it is not the pinned one.
check-toolchain:
	@id=$$(sh tools/toolchain_identity.sh) || exit 1; \
	echo "$$id" | grep -E '^(channel|cargo_version|rustc_version|official)=' | sed 's/=/: /'; \
	channel=$$(echo "$$id" | sed -n 's/^channel=//p'); \
	for c in $(COMPONENTS); do \
		have=$$(sed -n 's/^rust-version = "\(.*\)"/\1/p' components/$$c/Cargo.toml); \
		[ "$$have" = "$$channel" ] || { echo "components/$$c: rust-version $$have != $$channel" >&2; exit 1; }; \
	done; \
	echo "toolchain: pinned and consistent"

# Negative half of the pin: overrides a release must refuse. No SDK, no device.
check-toolchain-negative:
	@sh tools/toolchain_negative_test.sh

# The FFI structs are the one thing here that can be wrong without the compiler
# noticing: a layout mismatch just reads and writes the wrong offsets. Needs an
# OpenWrt SDK present; exits 2 (not run) when it is unavailable.
# The kernel constants netifd-rs hard-codes, against the real UAPI headers.
# A wrong constant is not a compile error and often not a runtime error either
# -- it silently sets the wrong option. Needs a C compiler whose <linux/*.h>
# match the target; pass CC="gcc -I<sdk include>" on a build host.
check-netlink-consts:
	sh tools/check_netlink_consts.sh components/netifd/src "$(CC)"

# The RLIMIT_* numbers procd-rs hard-codes. Same failure mode, and these are
# architecture-dependent, so the CC must be the target's.
check-rlimit-consts:
	sh tools/check_rlimit_consts.sh components/procd/src/sys.rs "$(CC)"

check-abi:
	@sh tools/check_abi.sh

check-tools:
	@# bash scripts (`<<<`, `<( )`) must be checked with bash: CI's sh is dash
	@for f in tools/*.sh tools/benchmark/*.sh packaging/image/owrt-recover-c packaging/image/05-owrt-native packaging/image/06-owrt-log-settings; do \
		if head -1 "$$f" | grep -q bash; then bash -n "$$f" || exit 1; else sh -n "$$f" || exit 1; fi; \
	done
	@python3 -m py_compile tools/*.py tools/benchmark/*.py tools/dnsmasq/*.py
	@echo "tools: syntax ok"

check-harnesses:
	@python3 tools/test_rust_check.py
	@python3 tools/test_mbx_cargo.py
	@python3 tools/test_r1_reference_oracle.py
	@python3 tools/dnsmasq/test_build_package.py
	@python3 tools/test_audit_checks.py
	@python3 tools/test_r85_procd_busy_gate.py
	@python3 tools/test_stack_manifest.py
	@python3 tools/test_native_release_prepare.py
	@python3 tools/test_native_image.py
	@python3 tools/test_native_trial_prepare.py
	@python3 tools/test_native_deploy_window.py

# The load generator must reject failed requests and count every operation.
# Full namespace/rollback gates additionally run on the image's build host.
check-benchmark:
	python3 tools/rust_check.py test --benchmark
	python3 tools/rust_check.py check --benchmark
	python3 tools/rust_check.py build --benchmark
	@host=$$(rustc -vV | sed -n 's/^host: //p'); \
		python3 tools/benchmark/test_fw4_cli.py "$${CARGO_TARGET_DIR:-tools/benchmark/target}/$$host/release/owrt-benchmark"
	python3 tools/benchmark/test_http_client.py
	python3 tools/benchmark/test_analyze.py
	python3 tools/benchmark/test_httpd_analysis.py
	python3 tools/benchmark/test_netifd_analysis.py
	python3 tools/benchmark/test_netifd_gate.py
	python3 tools/benchmark/test_r92_analysis.py
	python3 tools/benchmark/test_reload_exec.py
	python3 tools/benchmark/test_stack_analysis.py
	$(CC) -std=c11 -Wall -Wextra -Werror -fsyntax-only tools/benchmark/stack_config_cycle.c
	$(CC) -Wall -Wextra -Werror -fsyntax-only tools/benchmark/ns_exec.c
	$(CC) -Wall -Wextra -Werror -fsyntax-only tools/benchmark/socket_constants.c

# Release pipeline (runs on the build host, see docs/RELEASE.md)
apk:
	sh tools/release.sh apk $(VERSION)

image:
	sh tools/release.sh image $(VERSION)

# Same as the release-image GitHub workflow, on this machine (x86_64 Linux with rustup):
ci-image:
	OPENWRT_VERSION=$(VERSION) sh tools/ci_build_image.sh work
	OPENWRT_VERSION=$(VERSION) OWRT_CORE_INCLUDE_ODHCPD=1 sh tools/ci_build_core.sh work
	OPENWRT_VERSION=$(VERSION) python3 tools/ci_build_dnsmasq.py work
	OPENWRT_VERSION=$(VERSION) sh tools/ci_integrate_image.sh work
