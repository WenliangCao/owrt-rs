# Single entry point for the repository. Each crate stays independent (the
# OpenWrt package Makefiles copy crate directories one by one), so there is no
# root Cargo workspace on purpose.
COMPONENTS := ubus uci reload-config logd httpd fw4 rpcd ubusd netifd
VERSION ?= 25.12.5

.PHONY: check-netlink-consts test check-tools check-toolchain check-toolchain-negative check-abi build apk image ci-image

test:
	@for c in $(COMPONENTS); do \
		echo "== cargo test: $$c"; \
		(cd components/$$c && cargo test --quiet --locked) || exit 1; \
	done

build:
	@for c in $(COMPONENTS); do \
		echo "== cargo build: $$c"; \
		(cd components/$$c && cargo build --quiet --release) || exit 1; \
	done

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
# OpenWrt SDK present; skips cleanly when there is none.
# The kernel constants netifd-rs hard-codes, against the real UAPI headers.
# A wrong constant is not a compile error and often not a runtime error either
# -- it silently sets the wrong option. Needs a C compiler whose <linux/*.h>
# match the target; pass CC="gcc -I<sdk include>" on a build host.
check-netlink-consts:
	sh tools/check_netlink_consts.sh components/netifd/src "$(CC)"

check-abi:
	@sh tools/check_abi.sh

check-tools:
	@for f in tools/*.sh; do sh -n "$$f" || exit 1; done
	@python3 -m py_compile tools/*.py
	@echo "tools: syntax ok"

# Release pipeline (runs on the build host, see docs/RELEASE.md)
apk:
	sh tools/release.sh apk $(VERSION)

image:
	sh tools/release.sh image $(VERSION)

# Same as the release-image GitHub workflow, on this machine (x86_64 Linux with rustup):
ci-image:
	OPENWRT_VERSION=$(VERSION) sh tools/ci_build_image.sh work
