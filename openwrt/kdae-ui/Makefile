include $(TOPDIR)/rules.mk

PKG_NAME:=kdae-ui
PKG_VERSION:=unstable
PKG_RELEASE:=1
PKG_LICENSE:=AGPL-3.0-only

KDAE_SRC?=$(abspath $(CURDIR)/../..)

include $(INCLUDE_DIR)/package.mk

define Package/kdae-ui
  SECTION:=net
  CATEGORY:=Network
  TITLE:=kdae Vue management panel
  PKGARCH:=all
endef

define Package/kdae-ui/description
  Static Vue 3 panel at /www/kdae-ui/. Talks to kdae /v1 only.
endef

define Build/Compile
endef

define Package/kdae-ui/install
	$(INSTALL_DIR) $(1)/www/kdae-ui $(1)/www/cgi-bin
	$(INSTALL_DATA) $(KDAE_SRC)/web/legacy/index.html $(1)/www/kdae-ui/
	$(INSTALL_DATA) $(KDAE_SRC)/web/legacy/style.css $(1)/www/kdae-ui/
	$(INSTALL_DATA) $(KDAE_SRC)/web/legacy/app.js $(1)/www/kdae-ui/
	$(INSTALL_DATA) $(KDAE_SRC)/web/legacy/vue.global.prod.js $(1)/www/kdae-ui/
	$(INSTALL_BIN) ./files/kdae-proxy.cgi $(1)/www/cgi-bin/kdae-proxy
endef

$(eval $(call BuildPackage,kdae-ui))
