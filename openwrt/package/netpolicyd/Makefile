include $(TOPDIR)/rules.mk

PKG_NAME:=netpolicyd
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/netpolicyd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NetPolicy Engine
  DEPENDS:=+libstdcpp
endef

define Package/netpolicyd/description
  Programmable network policy engine.
endef

define Build/Compile
	# Binary is expected to be provided in files/ (see docs/openwrt.md)
endef

define Package/netpolicyd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/netpolicyd $(1)/usr/bin/netpolicyd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/netpolicyd.init $(1)/etc/init.d/netpolicyd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/netpolicyd.config $(1)/etc/config/netpolicyd
	$(INSTALL_DIR) $(1)/usr/share/netpolicyd
	$(INSTALL_DATA) ./files/web/index.html $(1)/usr/share/netpolicyd/index.html
	$(INSTALL_DATA) ./files/web/style.css $(1)/usr/share/netpolicyd/style.css
	$(INSTALL_DATA) ./files/web/app.js $(1)/usr/share/netpolicyd/app.js
endef

$(eval $(call BuildPackage,netpolicyd))
