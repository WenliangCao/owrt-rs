include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-httpd
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),1)

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
endef

define Build/Configure
endef

# rustls/ring compile C and assembly; give cargo the SDK toolchain
define Build/Compile
	+RUSTUP_HOME="$(V1_RUSTUP_HOME)" \
	CARGO_HOME="$(V1_CARGO_HOME)" \
	CARGO_BUILD_TARGET="$(RUST_TARGET)" \
	CARGO_PROFILE_RELEASE_PANIC=abort \
	CC_aarch64_unknown_linux_musl="$(TARGET_CC_NOCACHE)" \
	AR_aarch64_unknown_linux_musl="$(TARGET_AR)" \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$(TARGET_CC_NOCACHE)" \
	RUSTFLAGS="-Ctarget-cpu=cortex-a53 -Ctarget-feature=-crt-static -Clink-arg=-fuse-ld=$(TARGET_LINKER) -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs" \
	$(V1_CARGO) build --release --locked --manifest-path $(PKG_BUILD_DIR)/httpd/Cargo.toml
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
	/usr/sbin/owrt-httpd-switch boot-enable status >/dev/null 2>&1 || /etc/init.d/owrt-httpd disable
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
