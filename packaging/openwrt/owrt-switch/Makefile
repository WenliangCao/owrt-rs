include $(TOPDIR)/rules.mk

PKG_NAME:=owrt-switch
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(if $(V1_PACKAGE_RELEASE),$(V1_PACKAGE_RELEASE),1)

PKG_MAINTAINER:=owrt-control-plane-rs project
PKG_LICENSE:=MIT OR Apache-2.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/owrt-switch
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=One switch for the five Rust control-plane components
endef

define Package/owrt-switch/description
 owrt-switch status|enable-all|disable-all|boot-enable on|off|status drives the
 per-component switches (reload-config, logd, httpd, fw4, rpcd) in dependency
 order. It changes nothing by itself.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/owrt-switch/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/owrt-switch $(1)/usr/sbin/owrt-switch
endef

$(eval $(call BuildPackage,owrt-switch))
