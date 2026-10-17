include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-reload-config
PKG_VERSION:=0.2.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),8)

PKG_MAINTAINER:=owrt-control-plane-rs project
PKG_LICENSE:=MIT OR Apache-2.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1

V1_CARGO?=cargo
V1_CARGO_HOME?=
V1_RUSTUP_HOME?=
RELOAD_CONFIG_RS_SOURCE?=$(CURDIR)/../../../components/reload-config
RUST_TARGET:=aarch64-unknown-linux-musl

include $(INCLUDE_DIR)/package.mk

define Package/owrt-reload-config
  SECTION:=base
  CATEGORY:=Base system
  TITLE:=Observable OpenWrt config change dispatcher
  DEPENDS:=@(aarch64) +procd +uci +ubus
endef

define Package/owrt-reload-config/description
 Contract C1-01 compatible config change dispatcher. Installation is inert;
 an explicit, reboot-volatile bind-mount switch is required to activate it;
 boot-enable re-applies that switch after every boot when turned on.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/reload-config/src $(PKG_BUILD_DIR)/uci/src
	test -f $(RELOAD_CONFIG_RS_SOURCE)/Cargo.toml
	test -f $(RELOAD_CONFIG_RS_SOURCE)/Cargo.lock
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/Cargo.toml $(RELOAD_CONFIG_RS_SOURCE)/Cargo.lock $(PKG_BUILD_DIR)/reload-config/
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/src/*.rs $(PKG_BUILD_DIR)/reload-config/src/
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/../uci/Cargo.toml $(RELOAD_CONFIG_RS_SOURCE)/../uci/build.rs $(PKG_BUILD_DIR)/uci/
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/../uci/src/*.rs $(PKG_BUILD_DIR)/uci/src/
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/ubus/src
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/../ubus/Cargo.toml $(PKG_BUILD_DIR)/ubus/
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/../ubus/src/*.rs $(PKG_BUILD_DIR)/ubus/src/
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/../uci/platform $(PKG_BUILD_DIR)/uci/
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/platform
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/../platform/Cargo.toml $(PKG_BUILD_DIR)/platform/
	$(CP) $(RELOAD_CONFIG_RS_SOURCE)/../platform/src $(PKG_BUILD_DIR)/platform/
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
	$(V1_CARGO) build --release --locked --manifest-path /tmp/owrt-build/$(PKG_NAME)/reload-config/Cargo.toml --target-dir $(PKG_BUILD_DIR)/target
endef

define Package/owrt-reload-config/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUST_TARGET)/release/reload-config-rs \
		$(1)/usr/sbin/reload_config_rs
	$(INSTALL_BIN) ./files/owrt-reload-config-switch \
		$(1)/usr/sbin/owrt-reload-config-switch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/owrt-reload-config.init \
		$(1)/etc/init.d/owrt-reload-config
endef

define Package/owrt-reload-config/postinst
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	# fresh install: stay inert. Upgrade with boot-enable on: keep the layer
	# active and restart the service so the new binary runs (apk runs this
	# hook as post-upgrade too; the old hook flipped the device back to C).
	if /usr/sbin/owrt-reload-config-switch boot-enable status >/dev/null 2>&1; then
		/etc/init.d/owrt-reload-config enable
		/usr/sbin/owrt-reload-config-switch disable >/dev/null 2>&1 || true
		/usr/sbin/owrt-reload-config-switch enable
	else
		/usr/sbin/owrt-reload-config-switch disable
		/etc/init.d/owrt-reload-config enable
	fi
}
endef

define Package/owrt-reload-config/prerm
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	/usr/sbin/owrt-reload-config-switch disable
	/usr/sbin/owrt-reload-config-switch boot-enable off >/dev/null
	/etc/init.d/owrt-reload-config disable
}
endef

$(eval $(call BuildPackage,owrt-reload-config))
