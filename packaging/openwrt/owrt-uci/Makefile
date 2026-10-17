include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-uci
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),9)

PKG_MAINTAINER:=owrt-control-plane-rs project
PKG_LICENSE:=MIT OR Apache-2.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1

V1_CARGO?=cargo
V1_CARGO_HOME?=
V1_RUSTUP_HOME?=
OWRT_COMPONENTS_SOURCE?=$(CURDIR)/../../../components
RUST_TARGET:=aarch64-unknown-linux-musl

include $(INCLUDE_DIR)/package.mk

define Package/owrt-uci
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Contract C6 compatible uci CLI and libuci semantics (Rust /sbin/uci replacement)
  DEPENDS:=@(aarch64) +uci
endef

define Package/owrt-uci/description
 Rust replacement for /sbin/uci with libuci-compatible read/write/delta
 semantics (shares /etc/config, /tmp/.uci and /var/state with libuci users).
 Installation is inert; owrt-uci-switch enable first proves that uci-rs
 produces byte-identical export/show/changes for the live configuration and
 only then bind-mounts it over /sbin/uci; disable unmounts. boot-enable makes
 the mount persistent (S00, before any init script calls uci).
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/uci/src
	test -f $(OWRT_COMPONENTS_SOURCE)/uci/Cargo.toml
	test -f $(OWRT_COMPONENTS_SOURCE)/uci/Cargo.lock
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/uci/Cargo.lock $(OWRT_COMPONENTS_SOURCE)/uci/build.rs $(PKG_BUILD_DIR)/uci/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/src/*.rs $(PKG_BUILD_DIR)/uci/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/platform $(PKG_BUILD_DIR)/uci/
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/platform
	$(CP) $(OWRT_COMPONENTS_SOURCE)/platform/Cargo.toml $(PKG_BUILD_DIR)/platform/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/platform/src $(PKG_BUILD_DIR)/platform/
endef

define Build/Configure
endef

define Build/Compile
	# build from a host-independent path: cargo hashes the absolute path of path
	# dependencies into symbol names, so this is what makes CI and build-host
	# binaries byte-identical (target dir stays under PKG_BUILD_DIR for install)
	rm -rf /tmp/owrt-build/$(PKG_NAME) && mkdir -p /tmp/owrt-build && cp -a $(PKG_BUILD_DIR) /tmp/owrt-build/$(PKG_NAME)
	+RUSTUP_HOME="$(V1_RUSTUP_HOME)" \
	CARGO_HOME="$(V1_CARGO_HOME)" \
	CARGO_BUILD_TARGET="$(RUST_TARGET)" \
	CARGO_PROFILE_RELEASE_PANIC=abort \
	CC_aarch64_unknown_linux_musl="$(TARGET_CC_NOCACHE)" \
	AR_aarch64_unknown_linux_musl="$(TARGET_AR)" \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$(TARGET_CC_NOCACHE)" \
	RUSTFLAGS="-Dwarnings --remap-path-prefix=/tmp/owrt-build/$(PKG_NAME)=/build --remap-path-prefix=$(V1_CARGO_HOME)=/cargo -Clink-arg=-fuse-ld=$(TARGET_LINKER) -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs" \
	$(V1_CARGO) build --release --locked --manifest-path /tmp/owrt-build/$(PKG_NAME)/uci/Cargo.toml --target-dir $(PKG_BUILD_DIR)/uci/target
endef

define Package/owrt-uci/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uci/target/$(RUST_TARGET)/release/uci-rs \
		$(1)/usr/sbin/uci-rs
	$(INSTALL_BIN) ./files/owrt-uci-switch $(1)/usr/sbin/owrt-uci-switch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/owrt-uci.init $(1)/etc/init.d/owrt-uci
endef

define Package/owrt-uci/postinst
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	# fresh install: stay inert. Upgrade with boot-enable on: keep the layer
	# active and restart the service so the new binary runs (apk runs this
	# hook as post-upgrade too; the old hook flipped the device back to C).
	if /usr/sbin/owrt-uci-switch boot-enable status >/dev/null 2>&1; then
		/etc/init.d/owrt-uci enable
		/usr/sbin/owrt-uci-switch disable >/dev/null 2>&1 || true
		/usr/sbin/owrt-uci-switch enable
	else
		/usr/sbin/owrt-uci-switch disable
		/etc/init.d/owrt-uci enable
	fi
}
endef

define Package/owrt-uci/prerm
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	/usr/sbin/owrt-uci-switch disable
	/usr/sbin/owrt-uci-switch boot-enable off >/dev/null
	/etc/init.d/owrt-uci disable
}
endef

$(eval $(call BuildPackage,owrt-uci))
