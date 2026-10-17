include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-logd
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),11)

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

define Package/owrt-logd
  SECTION:=base
  CATEGORY:=Base system
  TITLE:=Contract C2 compatible system log daemon (Rust)
  DEPENDS:=@(aarch64) +procd +ubus +logd
endef

define Package/owrt-logd/description
 Rust replacement for ubox logd serving the ubus object "log". Installation is
 inert; owrt-logd-switch enable swaps the running logd instance for this one
 and disable swaps it back. boot-enable makes the swap persistent across boots.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/logd/src $(PKG_BUILD_DIR)/ubus/src
	test -f $(OWRT_COMPONENTS_SOURCE)/logd/Cargo.toml
	test -f $(OWRT_COMPONENTS_SOURCE)/logd/Cargo.lock
	$(CP) $(OWRT_COMPONENTS_SOURCE)/logd/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/logd/Cargo.lock $(PKG_BUILD_DIR)/logd/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/logd/src/*.rs $(PKG_BUILD_DIR)/logd/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/Cargo.toml $(PKG_BUILD_DIR)/ubus/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/src/*.rs $(PKG_BUILD_DIR)/ubus/src/
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
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$(TARGET_CC_NOCACHE)" \
	RUSTFLAGS="-Dwarnings --remap-path-prefix=/tmp/owrt-build/$(PKG_NAME)=/build --remap-path-prefix=$(V1_CARGO_HOME)=/cargo -Clink-arg=-fuse-ld=$(TARGET_LINKER) -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs" \
	$(V1_CARGO) build --release --locked --manifest-path /tmp/owrt-build/$(PKG_NAME)/logd/Cargo.toml --target-dir $(PKG_BUILD_DIR)/logd/target
endef

define Package/owrt-logd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/logd/target/$(RUST_TARGET)/release/logd-rs $(1)/usr/sbin/logd-rs
	$(INSTALL_BIN) ./files/owrt-logd-switch $(1)/usr/sbin/owrt-logd-switch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/owrt-logd.init $(1)/etc/init.d/owrt-logd
endef

define Package/owrt-logd/postinst
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	# fresh install: stay inert. Upgrade with boot-enable on: keep the layer
	# active and restart the service so the new binary runs (apk runs this
	# hook as post-upgrade too; the old hook flipped the device back to C).
	if /usr/sbin/owrt-logd-switch boot-enable status >/dev/null 2>&1; then
		/etc/init.d/owrt-logd enable
		/etc/init.d/owrt-logd restart
	else
		/etc/init.d/owrt-logd disable
	fi
}
endef

define Package/owrt-logd/prerm
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	/usr/sbin/owrt-logd-switch boot-enable off >/dev/null
	/usr/sbin/owrt-logd-switch disable >/dev/null 2>&1 || true
	/etc/init.d/owrt-logd disable
}
endef

$(eval $(call BuildPackage,owrt-logd))
