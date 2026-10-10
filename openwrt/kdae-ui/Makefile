include $(TOPDIR)/rules.mk

PKG_NAME:=kdae-ui
PKG_VERSION:=unstable
PKG_RELEASE:=1
PKG_LICENSE:=AGPL-3.0-only MIT

KDAE_SRC?=$(abspath $(CURDIR)/../..)
KDAE_UI_DIR?=$(KDAE_SRC)/web-next

include $(INCLUDE_DIR)/package.mk

define Package/kdae-ui
  SECTION:=net
  CATEGORY:=Network
  TITLE:=fdae dashboard based on zashboard
  PKGARCH:=all
  DEPENDS:=+openssl-util +curl
endef

define Package/kdae-ui/description
  Vite-built Vue 3 panel at /www/kdae-ui/. Talks to fdae /v1 only.
endef

define Build/Compile
	if [ ! -f "$(KDAE_UI_DIR)/dist/index.html" ]; then \
		echo "WebUI dist missing; run: cd $(KDAE_UI_DIR) && FONT=none pnpm build" >&2; \
		exit 1; \
	fi
endef

define Package/kdae-ui/install
	$(INSTALL_DIR) $(1)/www/kdae-ui/assets $(1)/www/cgi-bin
	$(CP) $(KDAE_UI_DIR)/dist/. $(1)/www/kdae-ui/
	$(INSTALL_BIN) ./files/kdae-proxy.cgi $(1)/www/cgi-bin/kdae-proxy
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/www/kdae-ui/ca
	$(INSTALL_BIN) ./files/kdae-ui-cert $(1)/usr/sbin/kdae-ui-cert
	$(INSTALL_BIN) ./files/kdae-ui-http $(1)/usr/sbin/kdae-ui-http
	$(INSTALL_DATA) ./files/ca-index.html $(1)/www/kdae-ui/ca/index.html
	# A plain-HTTP door for the panel alone (see postinst): its document root
	# holds the panel and its proxy and nothing else, so LuCI is not served there.
	$(INSTALL_DIR) $(1)/www/kdae-http/cgi-bin
	ln -sfn ../kdae-ui $(1)/www/kdae-http/kdae-ui
	ln -sfn ../../cgi-bin/kdae-proxy $(1)/www/kdae-http/cgi-bin/kdae-proxy
	$(INSTALL_DATA) ./files/kdae-http-index.html $(1)/www/kdae-http/index.html
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	echo /etc/kdae-ui > $(1)/lib/upgrade/keep.d/kdae-ui
endef

# Issue the local CA and a Safari-compliant leaf certificate for uhttpd, and
# renew it monthly (it is reissued only when near expiry or addresses change).
define Package/kdae-ui/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/usr/sbin/kdae-ui-cert || echo "kdae-ui: certificate setup failed; run kdae-ui-cert" >&2
/usr/sbin/kdae-ui-http || echo "kdae-ui: could not open the plain-HTTP port; run kdae-ui-http" >&2
if ! grep -q kdae-ui-cert /etc/crontabs/root 2>/dev/null; then
	echo '17 4 * * * /usr/sbin/kdae-ui-cert >/dev/null 2>&1' >> /etc/crontabs/root
	/etc/init.d/cron restart >/dev/null 2>&1 || true
fi
exit 0
endef

define Package/kdae-ui/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
sed -i '/kdae-ui-cert/d' /etc/crontabs/root 2>/dev/null
uci -q delete uhttpd.kdae && uci -q commit uhttpd && /etc/init.d/uhttpd reload >/dev/null 2>&1 || true
exit 0
endef

$(eval $(call BuildPackage,kdae-ui))
