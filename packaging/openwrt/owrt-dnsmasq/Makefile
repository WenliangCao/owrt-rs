include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-dnsmasq
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),1)

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

define Package/owrt-dnsmasq
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=Rust dnsmasq rewrite (staging package)
  DEPENDS:=@(aarch64) +libubus
endef

define Package/owrt-dnsmasq/description
Development Rust DNS/DHCPv4/TFTP rewrite artifacts. This package is
deliberately inert: it installs dnsmasq-rs under /usr/libexec and does not
replace the stock dnsmasq binary or init script until the compatibility gates
in docs/dnsmasq/REPORT.md are complete.
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

define Package/owrt-dnsmasq/install
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dnsmasq/target/$(RUST_TARGET)/release/dnsmasq-rs $(1)/usr/libexec/dnsmasq-rs
endef

$(eval $(call BuildPackage,owrt-dnsmasq))
