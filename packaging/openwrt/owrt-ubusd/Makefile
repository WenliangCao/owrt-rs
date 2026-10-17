include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-ubusd
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),4)

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

define Package/owrt-ubusd
  SECTION:=base
  CATEGORY:=Base system
  TITLE:=ubusd replacement: the system message bus (Rust)
  DEPENDS:=@(aarch64) +ubusd
endef

define Package/owrt-ubusd/description
 Rust replacement for ubusd (see docs/contracts/ubusd.md). Unlike the other
 owrt-* packages this one ships NO init script and NO enable/disable switch:
 the system bus cannot be swapped by stopping and starting a service, because
 clients that do not reconnect (odhcpd, an idle dnsmasq, netifd's
 network.wireless) would be left off the bus. Installing, upgrading and
 removing this package never touch the running bus.

 owrt-ubusd-verify runs the candidate on a separate socket and exercises it,
 which is isolated verification only -- it is not a system takeover.

 owrt-ubusd-boot-switch prepares (or undoes) which daemon the NEXT boot starts,
 and never touches the running bus. Its `off` restores /sbin/ubusd from /rom
 rather than removing it: on an overlay, removing a file that exists in the
 read-only layer writes a whiteout, and the next boot then stops at
 "procd: - ubus -" with no init and no shell. Neither script runs by itself --
 installing, upgrading and removing this package leave the bus alone.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/ubusd/src $(PKG_BUILD_DIR)/ubus/src
	test -f $(OWRT_COMPONENTS_SOURCE)/ubusd/Cargo.toml
	test -f $(OWRT_COMPONENTS_SOURCE)/ubusd/Cargo.lock
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubusd/Cargo.toml $(OWRT_COMPONENTS_SOURCE)/ubusd/Cargo.lock $(PKG_BUILD_DIR)/ubusd/
	$(CP) $(OWRT_COMPONENTS_SOURCE)/ubusd/src/*.rs $(PKG_BUILD_DIR)/ubusd/src/
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
	$(V1_CARGO) build --release --locked --manifest-path /tmp/owrt-build/$(PKG_NAME)/ubusd/Cargo.toml --target-dir $(PKG_BUILD_DIR)/ubusd/target
endef

define Package/owrt-ubusd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ubusd/target/$(RUST_TARGET)/release/ubusd-rs $(1)/usr/sbin/ubusd-rs
	$(INSTALL_BIN) ./files/owrt-ubusd-verify $(1)/usr/sbin/owrt-ubusd-verify
	$(INSTALL_BIN) ./files/owrt-ubusd-boot-switch $(1)/usr/sbin/owrt-ubusd-boot-switch
endef

# No postinst and no prerm hook on purpose: nothing this package does may stop,
# start or otherwise disturb the running system bus.

$(eval $(call BuildPackage,owrt-ubusd))
