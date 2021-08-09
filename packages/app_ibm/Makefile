include $(TOPDIR)/rules.mk

PKG_NAME:=app_ibm
PKG_RELEASE:=1
PKG_VERSION:=1.0.0

include $(INCLUDE_DIR)/package.mk

define Package/app_ibm
	CATEGORY:=Base system
	TITLE:=app_ibm
	DEPENDS:=+libibm +libubus +libubox +libblobmsg-json
endef

define Package/app_ibm/description
	This is an example app package which uses an example library package
endef

define Package/app_ibm/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/app_ibm $(1)/usr/bin
	$(INSTALL_BIN) ./files/ibm.init $(1)/etc/init.d/ibm
	$(INSTALL_CONF) ./files/ibm.config $(1)/etc/config/ibm
endef

$(eval $(call BuildPackage,app_ibm,+libibm))
