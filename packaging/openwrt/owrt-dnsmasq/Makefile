include $(TOPDIR)/rules.mk

PKG_NAME:=dnsmasq
PKG_VERSION:=2.93
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),2)

PKG_MAINTAINER:=owrt-control-plane-rs project
PKG_LICENSE:=GPL-2.0-only OR GPL-3.0-only
PKG_BUILD_DIR:=$(if $(OWRT_DNSMASQ_BUILD_DIR),$(OWRT_DNSMASQ_BUILD_DIR),$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION))
PKG_BUILD_PARALLEL:=1

ifneq ($(OWRT_DNSMASQ_OUTPUT_DIR),)
  OUTPUT_DIR:=$(OWRT_DNSMASQ_OUTPUT_DIR)
  PACKAGE_DIR:=$(OUTPUT_DIR)/packages/$(ARCH_PACKAGES)/base
  PACKAGE_DIR_ALL:=$(OUTPUT_DIR)/package-links
endif

V1_CARGO?=cargo
V1_CARGO_HOME?=
V1_RUSTUP_HOME?=
OWRT_COMPONENTS_SOURCE?=$(CURDIR)/../../../components
RUST_TARGET:=aarch64-unknown-linux-musl

include $(INCLUDE_DIR)/package.mk

# package-pack.mk reads CONFLICTS as a recipe-global field when emitting APK
# metadata. Keep the variant conflicts visible in the generated package.
CONFLICTS:=dnsmasq-dhcpv6 dnsmasq-full

define Package/dnsmasq
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=Rust dnsmasq replacement (deployment candidate)
  URL:=https://github.com/openwrt/openwrt
  DEPENDS:=@(aarch64) +libubus20251202 +@BUSYBOX_CONFIG_PIDOF
  USERID:=dnsmasq=453:dnsmasq=453
  PROVIDES:=dnsmasq-any
  REPLACES:=dnsmasq
endef

define Package/dnsmasq/description
Rust implementation of the OpenWrt dnsmasq 2.93 nodhcpv6 package contract.
This candidate owns the stock package paths so apk can replace the stock
dnsmasq package while retaining its UCI, init, ujail and ubus ACL contract.
endef

define Package/dnsmasq/conffiles
/etc/config/dhcp
/etc/dnsmasq.conf
/etc/dnsmasq.d/
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/dnsmasq/src $(PKG_BUILD_DIR)/ubus/src
	test -f $(OWRT_COMPONENTS_SOURCE)/dnsmasq/Cargo.toml
	test -f $(OWRT_COMPONENTS_SOURCE)/dnsmasq/Cargo.lock
	$(CP) $(OWRT_COMPONENTS_SOURCE)/dnsmasq/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/dnsmasq/Cargo.lock $(PKG_BUILD_DIR)/dnsmasq/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/dnsmasq/src/. $(PKG_BUILD_DIR)/dnsmasq/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/Cargo.toml $(PKG_BUILD_DIR)/ubus/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/src/. $(PKG_BUILD_DIR)/ubus/src/
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
	RUSTFLAGS="--remap-path-prefix=$(PKG_BUILD_DIR)=/build --remap-path-prefix=$(V1_CARGO_HOME)=/cargo -Clink-arg=-fuse-ld=$(TARGET_LINKER) -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs" \
	$(V1_CARGO) build --release --frozen --manifest-path $(PKG_BUILD_DIR)/dnsmasq/Cargo.toml --bin dnsmasq-rs --target-dir $(PKG_BUILD_DIR)/dnsmasq/target
endef

define Package/dnsmasq/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/target/$(RUST_TARGET)/release/dnsmasq-rs $(1)/usr/sbin/dnsmasq
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/dhcp.conf $(1)/etc/config/dhcp
	$(INSTALL_CONF) ./files/dnsmasq.conf $(1)/etc/dnsmasq.conf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dnsmasq.init $(1)/etc/init.d/dnsmasq
	$(INSTALL_DIR) $(1)/etc/hotplug.d/dhcp $(1)/etc/hotplug.d/neigh $(1)/etc/hotplug.d/ntp $(1)/etc/hotplug.d/tftp
	$(INSTALL_DATA) ./files/dnsmasqsec.hotplug $(1)/etc/hotplug.d/ntp/25-dnsmasqsec
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/50-dnsmasq-migrate-resolv-conf-auto.sh $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/50-dnsmasq-migrate-ipset.sh $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/usr/share/dnsmasq
	$(INSTALL_CONF) ./files/dhcpbogushostname.conf $(1)/usr/share/dnsmasq/dhcpbogushostname.conf
	$(INSTALL_CONF) ./files/rfc6761.conf $(1)/usr/share/dnsmasq/rfc6761.conf
	$(INSTALL_DIR) $(1)/usr/lib/dnsmasq
	$(INSTALL_BIN) ./files/dhcp-script.sh $(1)/usr/lib/dnsmasq/dhcp-script.sh
	$(INSTALL_DIR) $(1)/usr/share/acl.d
	$(INSTALL_DATA) ./files/dnsmasq_acl.json $(1)/usr/share/acl.d/dnsmasq_acl.json
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/dnsmasq.keep $(1)/lib/upgrade/keep.d/dnsmasq
endef

# BuildPackage evaluates Package/Default, which resets recipe globals. Set it
# again immediately before emission so the APK control block retains it.
CONFLICTS:=dnsmasq-dhcpv6 dnsmasq-full
$(eval $(call BuildPackage,dnsmasq))
