# Single entry point for the repository. Each crate stays independent (the
# OpenWrt package Makefiles copy crate directories one by one), so there is no
# root Cargo workspace on purpose.
COMPONENTS := ubus uci reload-config logd httpd fw4 rpcd
VERSION ?= 25.12.5

.PHONY: test check-tools build apk image ci-image

test:
	@for c in $(COMPONENTS); do \
		echo "== cargo test: $$c"; \
		(cd components/$$c && cargo test --quiet) || exit 1; \
	done

build:
	@for c in $(COMPONENTS); do \
		echo "== cargo build: $$c"; \
		(cd components/$$c && cargo build --quiet --release) || exit 1; \
	done

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
