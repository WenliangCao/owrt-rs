include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-httpd
PKG_VERSION:=0.1.1
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),13)

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

define Package/owrt-httpd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Contract C3 compatible HTTP front end (Rust uhttpd replacement)
  DEPENDS:=@(aarch64) +procd +ubus +uhttpd
endef

define Package/owrt-httpd/description
 Rust replacement for uhttpd: static files, CGI (LuCI), /ubus JSON-RPC bridge
 and TLS (rustls). Installation is inert; owrt-httpd-switch enable stops the
 stock uhttpd service and starts this daemon with the same /etc/config/uhttpd
 settings; disable swaps back. boot-enable makes the swap persistent.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/httpd/src $(PKG_BUILD_DIR)/ubus/src
	test -f $(OWRT_COMPONENTS_SOURCE)/httpd/Cargo.toml
	test -f $(OWRT_COMPONENTS_SOURCE)/httpd/Cargo.lock
	$(CP) $(OWRT_COMPONENTS_SOURCE)/httpd/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/httpd/Cargo.lock $(PKG_BUILD_DIR)/httpd/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/httpd/src/*.rs $(PKG_BUILD_DIR)/httpd/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/Cargo.toml $(PKG_BUILD_DIR)/ubus/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/src/*.rs $(PKG_BUILD_DIR)/ubus/src/
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/platform
	$(CP) $(OWRT_COMPONENTS_SOURCE)/platform/Cargo.toml $(PKG_BUILD_DIR)/platform/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/platform/src $(PKG_BUILD_DIR)/platform/
endef

define Build/Configure
endef

# rustls/ring compile C and assembly; give cargo the SDK toolchain
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
	$(V1_CARGO) build --release --locked --manifest-path /tmp/owrt-build/$(PKG_NAME)/httpd/Cargo.toml --target-dir $(PKG_BUILD_DIR)/httpd/target
endef

define Package/owrt-httpd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/httpd/target/$(RUST_TARGET)/release/httpd-rs $(1)/usr/sbin/httpd-rs
	$(INSTALL_BIN) ./files/owrt-httpd-switch $(1)/usr/sbin/owrt-httpd-switch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/owrt-httpd.init $(1)/etc/init.d/owrt-httpd
endef

define Package/owrt-httpd/postinst
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	# fresh install: stay inert. Upgrade with boot-enable on: keep the layer
	# active and restart the service so the new binary runs (apk runs this
	# hook as post-upgrade too; the old hook flipped the device back to C).
	if /usr/sbin/owrt-httpd-switch boot-enable status >/dev/null 2>&1; then
		/etc/init.d/owrt-httpd enable
		/etc/init.d/owrt-httpd restart
	else
		/etc/init.d/owrt-httpd disable
	fi
}
endef

define Package/owrt-httpd/prerm
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	/usr/sbin/owrt-httpd-switch boot-enable off >/dev/null
	/usr/sbin/owrt-httpd-switch disable >/dev/null 2>&1 || true
	/etc/init.d/owrt-httpd disable
}
endef

$(eval $(call BuildPackage,owrt-httpd))
