include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-rpcd
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

define Package/owrt-rpcd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=rpcd replacement in Rust (session, uci, rc, file, luci, rpc-sys, rrdns, luci-rpc, iwinfo)
  DEPENDS:=@(aarch64) +ubus
endef

define Package/owrt-rpcd/description
 Rust implementation of every rpcd ubus object: `session`, `uci`, `rc`
 (contract C7), `file`, `luci` (C5), `rpc-sys`, `network.rrdns`, `luci-rpc`,
 `iwinfo` (C8) as one object server, with its own rtnetlink and nl80211
 clients. Installation is inert; owrt-rpcd-switch enable stops the original
 rpcd, starts rpcd-rs and removes rpcd's boot link; disable reverses it.
 boot-enable makes the switch persistent.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/rpcd/src $(PKG_BUILD_DIR)/ubus/src $(PKG_BUILD_DIR)/uci/src/bin
	test -f $(OWRT_COMPONENTS_SOURCE)/rpcd/Cargo.toml
	test -f $(OWRT_COMPONENTS_SOURCE)/rpcd/Cargo.lock
	$(CP) $(OWRT_COMPONENTS_SOURCE)/rpcd/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/rpcd/Cargo.lock $(PKG_BUILD_DIR)/rpcd/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/rpcd/src/*.rs $(PKG_BUILD_DIR)/rpcd/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/Cargo.toml $(PKG_BUILD_DIR)/ubus/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/src/*.rs $(PKG_BUILD_DIR)/ubus/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/Cargo.toml $(PKG_BUILD_DIR)/uci/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/src/*.rs $(PKG_BUILD_DIR)/uci/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/uci/src/bin/*.rs $(PKG_BUILD_DIR)/uci/src/bin/
endef

define Build/Configure
endef

define Build/Compile
	+RUSTUP_HOME="$(V1_RUSTUP_HOME)" \
	CARGO_HOME="$(V1_CARGO_HOME)" \
	CARGO_BUILD_TARGET="$(RUST_TARGET)" \
	CARGO_PROFILE_RELEASE_PANIC=abort \
	CC_aarch64_unknown_linux_musl="$(TARGET_CC_NOCACHE)" \
	AR_aarch64_unknown_linux_musl="$(TARGET_AR)" \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$(TARGET_CC_NOCACHE)" \
	RUSTFLAGS="-Ctarget-cpu=cortex-a53 -Ctarget-feature=-crt-static -Clink-arg=-fuse-ld=$(TARGET_LINKER) -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs" \
	$(V1_CARGO) build --release --locked --manifest-path $(PKG_BUILD_DIR)/rpcd/Cargo.toml
endef

define Package/owrt-rpcd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rpcd/target/$(RUST_TARGET)/release/rpcd-rs \
		$(1)/usr/sbin/rpcd-rs
	$(INSTALL_BIN) ./files/owrt-rpcd-switch $(1)/usr/sbin/owrt-rpcd-switch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/owrt-rpcd.init $(1)/etc/init.d/owrt-rpcd
endef

define Package/owrt-rpcd/postinst
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	/usr/sbin/owrt-rpcd-switch disable
	/etc/init.d/owrt-rpcd enable
}
endef

define Package/owrt-rpcd/prerm
#!/bin/sh
set -eu
[ -n "$${IPKG_INSTROOT:-}" ] || {
	/usr/sbin/owrt-rpcd-switch disable
	/usr/sbin/owrt-rpcd-switch boot-enable off >/dev/null
	/etc/init.d/owrt-rpcd disable
}
endef

$(eval $(call BuildPackage,owrt-rpcd))
