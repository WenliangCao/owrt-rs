include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-fw4
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),12)

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

define Package/owrt-fw4
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Contract C4 compatible nftables ruleset generator (Rust firewall4 replacement)
  DEPENDS:=@(aarch64) +firewall4 +ubus
endef

define Package/owrt-fw4/description
 Rust replacement for the firewall4 ucode generator behind /sbin/fw4. Installation
 is inert; owrt-fw4-switch enable first proves that fw4-rs renders the same
 ruleset as the original (byte-identical `print`) and only then bind-mounts it
 over /sbin/fw4; disable unmounts. boot-enable makes the mount persistent.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/fw4/src $(PKG_BUILD_DIR)/ubus/src $(PKG_BUILD_DIR)/uci/src
	test -f $(OWRT_COMPONENTS_SOURCE)/fw4/Cargo.toml
	test -f $(OWRT_COMPONENTS_SOURCE)/fw4/Cargo.lock
	$(CP) $(OWRT_COMPONENTS_SOURCE)/fw4/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/fw4/Cargo.lock $(OWRT_COMPONENTS_SOURCE)/fw4/build.rs $(PKG_BUILD_DIR)/fw4/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/fw4/src/*.rs $(PKG_BUILD_DIR)/fw4/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/Cargo.toml $(PKG_BUILD_DIR)/ubus/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/src/*.rs $(PKG_BUILD_DIR)/ubus/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/uci/build.rs $(PKG_BUILD_DIR)/uci/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/src/*.rs $(PKG_BUILD_DIR)/uci/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/platform $(PKG_BUILD_DIR)/uci/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/fw4/platform $(PKG_BUILD_DIR)/fw4/
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
	$(V1_CARGO) build --release --locked --manifest-path /tmp/owrt-build/$(PKG_NAME)/fw4/Cargo.toml --target-dir $(PKG_BUILD_DIR)/fw4/target
endef

define Package/owrt-fw4/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/fw4/target/$(RUST_TARGET)/release/fw4-rs \
		$(1)/usr/sbin/fw4-rs
	$(INSTALL_BIN) ./files/owrt-fw4-switch $(1)/usr/sbin/owrt-fw4-switch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/owrt-fw4.init $(1)/etc/init.d/owrt-fw4
endef

define Package/owrt-fw4/postinst
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	# fresh install: stay inert. Upgrade with boot-enable on: keep the layer
	# active and restart the service so the new binary runs (apk runs this
	# hook as post-upgrade too; the old hook flipped the device back to C).
	if /usr/sbin/owrt-fw4-switch boot-enable status >/dev/null 2>&1; then
		/etc/init.d/owrt-fw4 enable
		/usr/sbin/owrt-fw4-switch disable >/dev/null 2>&1 || true
		/usr/sbin/owrt-fw4-switch enable
	else
		/usr/sbin/owrt-fw4-switch disable
		/etc/init.d/owrt-fw4 enable
	fi
}
endef

define Package/owrt-fw4/prerm
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	/usr/sbin/owrt-fw4-switch disable
	/usr/sbin/owrt-fw4-switch boot-enable off >/dev/null
	/etc/init.d/owrt-fw4 disable
}
endef

$(eval $(call BuildPackage,owrt-fw4))
