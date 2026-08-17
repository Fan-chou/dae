#
# luci-app-kdae — packaged from this tree by openwrt-kdae-feed.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-kdae
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for kdae
LUCI_DEPENDS:=+kdae
LUCI_PKGARCH:=all

PKG_LICENSE:=AGPL-3.0-only
PKG_MAINTAINER:=kdae local feed

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-kdae
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=$(LUCI_TITLE)
  DEPENDS:=$(LUCI_DEPENDS)
  PKGARCH:=$(LUCI_PKGARCH)
  CONFLICTS:=luci-app-dae
endef

define Package/luci-app-kdae/description
  Start/stop/restart, crash recover (purge leftover eBPF), validate, reload,
  rule-sync warnings, and a link to /kdae-ui/. Node URI editing is omitted.
endef

define Package/luci-app-kdae/conffiles
/etc/config/dae
endef

define Build/Compile
endef

define Package/luci-app-kdae/install
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-kdae.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-kdae.json $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/kdae
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/kdae/*.js $(1)/www/luci-static/resources/view/kdae/
	$(INSTALL_DIR) $(1)/usr/libexec/dae
	$(INSTALL_BIN) ./root/usr/libexec/dae/kdae-sync.sh $(1)/usr/libexec/dae/kdae-sync.sh
	$(INSTALL_BIN) ./root/usr/libexec/dae/kdae-write-local.sh $(1)/usr/libexec/dae/kdae-write-local.sh
endef

$(eval $(call BuildPackage,luci-app-kdae))
