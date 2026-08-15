include $(TOPDIR)/rules.mk

PKG_NAME:=kdae-rule-sync
PKG_VERSION:=unstable
PKG_RELEASE:=1
PKG_LICENSE:=AGPL-3.0-only

KDAE_SRC?=$(abspath $(CURDIR)/../..)

include $(INCLUDE_DIR)/package.mk

define Package/kdae-rule-sync
  SECTION:=net
  CATEGORY:=Network
  TITLE:=kdae Mihomo generation publisher
  DEPENDS:=+kdae
endef

define Build/Compile
	$(MAKE) -C $(KDAE_SRC) dae-rule-sync RULE_SYNC_OUTPUT=$(PKG_BUILD_DIR)/dae-rule-sync \
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0
endef

define Package/kdae-rule-sync/install
	$(INSTALL_DIR) $(1)/usr/libexec/dae
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dae-rule-sync $(1)/usr/libexec/dae/dae-rule-sync
endef

$(eval $(call BuildPackage,kdae-rule-sync))
