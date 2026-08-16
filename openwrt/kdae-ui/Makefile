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
  Vite-built Vue 3 panel at /www/kdae-ui/. Talks to kdae /v1 only.
endef

define Build/Compile
	if [ ! -f "$(KDAE_SRC)/web/dist/index.html" ]; then \
		echo "web/dist missing; run: cd web && pnpm build" >&2; \
		exit 1; \
	fi
endef

define Package/kdae-ui/install
	$(INSTALL_DIR) $(1)/www/kdae-ui/assets $(1)/www/cgi-bin
	$(INSTALL_DATA) $(KDAE_SRC)/web/dist/index.html $(1)/www/kdae-ui/
	$(CP) $(KDAE_SRC)/web/dist/assets/. $(1)/www/kdae-ui/assets/
	$(INSTALL_BIN) ./files/kdae-proxy.cgi $(1)/www/cgi-bin/kdae-proxy
endef

$(eval $(call BuildPackage,kdae-ui))
