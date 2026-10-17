include $(TOPDIR)/rules.mk

PKG_NAME:=dnsmasq
PKG_VERSION:=2.93
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),4)

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

ifneq ($(OWRT_DNSMASQ_FROZEN_ELF),)
  # This ELF was already stripped before its regression freeze.
  # Re-running RSTRIP could change identity. build_package.py still checks
  # the APK-extracted ELF hash against that freeze, with no allowed mismatch.
  RSTRIP:=:
  DNSMASQ_INSTALL_ELF:=$(PKG_BUILD_DIR)/frozen-dnsmasq
else
  DNSMASQ_INSTALL_ELF:=$(PKG_BUILD_DIR)/dnsmasq/target/$(RUST_TARGET)/release/dnsmasq-rs
endif

define Package/dnsmasq
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=Rust dnsmasq replacement
  URL:=https://github.com/openwrt/openwrt
  DEPENDS:=@(aarch64) +libubus20251202 +@BUSYBOX_CONFIG_PIDOF
  USERID:=dnsmasq=453:dnsmasq=453
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
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/dnsmasq/platform/src
	$(CP) $(OWRT_COMPONENTS_SOURCE)/dnsmasq/platform/Cargo.toml $(PKG_BUILD_DIR)/dnsmasq/platform/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/dnsmasq/platform/src/. $(PKG_BUILD_DIR)/dnsmasq/platform/src/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/Cargo.toml $(PKG_BUILD_DIR)/ubus/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubus/src/. $(PKG_BUILD_DIR)/ubus/src/
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/platform/src
	$(CP) $(OWRT_COMPONENTS_SOURCE)/platform/Cargo.toml $(PKG_BUILD_DIR)/platform/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/platform/src/. $(PKG_BUILD_DIR)/platform/src/
	$(if $(OWRT_DNSMASQ_FROZEN_ELF),$(CP) $(OWRT_DNSMASQ_FROZEN_ELF) $(PKG_BUILD_DIR)/frozen-dnsmasq)
endef

define Build/Configure
endef

ifneq ($(OWRT_DNSMASQ_FROZEN_ELF),)
define Build/Compile
	test -s $(PKG_BUILD_DIR)/frozen-dnsmasq
endef
else
# Backticks keep this shell substitution intact through BuildPackage's eval.
define Build/Compile
	+RUSTUP_HOME="$(V1_RUSTUP_HOME)" \
	CARGO_HOME="$(V1_CARGO_HOME)" \
	CARGO_BUILD_TARGET="$(RUST_TARGET)" \
	CARGO_PROFILE_RELEASE_PANIC=abort \
	CC_aarch64_unknown_linux_musl="$(TARGET_CC_NOCACHE)" \
	AR_aarch64_unknown_linux_musl="$(TARGET_AR)" \
	DNSMASQ_STATIC_PIE_CC="`command -v "$(TARGET_CC_NOCACHE)"`" \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$(CURDIR)/static-pie-linker.py" \
	RUSTFLAGS="-Cforce-unwind-tables=no --remap-path-prefix=$(PKG_BUILD_DIR)=/build --remap-path-prefix=$(V1_CARGO_HOME)=/cargo -Clink-arg=-fuse-ld=$(TARGET_LINKER) -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Crelocation-model=pie -Ctarget-feature=+crt-static -Dwarnings" \
	$(V1_CARGO) build --release --frozen --manifest-path $(PKG_BUILD_DIR)/dnsmasq/Cargo.toml --bin dnsmasq-rs --target-dir $(PKG_BUILD_DIR)/dnsmasq/target
endef
endif

define Package/dnsmasq/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(DNSMASQ_INSTALL_ELF) $(1)/usr/sbin/dnsmasq
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
endef

# The stock nodhcpv6 package has this same name. APK upgrades it by version;
# do not claim that recipe-only CONFLICTS/REPLACES become APK metadata. The
# other stock variants provide dnsmasq; their solver behavior is tested with
# the actual variant APKs by m4_package_lifecycle.py.
$(eval $(call BuildPackage,dnsmasq))
