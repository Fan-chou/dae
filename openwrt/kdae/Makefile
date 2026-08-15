include $(TOPDIR)/rules.mk

PKG_NAME:=kdae
PKG_VERSION:=unstable
PKG_RELEASE:=1
PKG_LICENSE:=AGPL-3.0-only

KDAE_SRC?=$(abspath $(CURDIR)/../..)

include $(INCLUDE_DIR)/package.mk

define Package/kdae
  SECTION:=net
  CATEGORY:=Network
  TITLE:=kdae eBPF transparent proxy
  URL:=https://github.com/daeuniverse/dae
  DEPENDS:=+ca-bundle +kmod-sched-core +kmod-sched-bpf +kmod-xdp-sockets-diag +kmod-veth
  PROVIDES:=dae
  CONFLICTS:=dae
endef

define Package/kdae/description
  kdae installs as /usr/bin/dae. TCP sockmap offload stays off unless
  DAE_ALLOW_TCP_SOCKMAP=1 (needs kernel >= 6.6.94).
endef

define Package/kdae/conffiles
/etc/config/dae
/etc/dae/config.dae
endef

define Build/Compile
	$(MAKE) -C $(KDAE_SRC) dae OUTPUT=$(PKG_BUILD_DIR)/dae \
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0
endef

define Package/kdae/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/etc/dae $(1)/lib/upgrade/keep.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dae $(1)/usr/bin/dae
	$(INSTALL_BIN) ./files/dae.init $(1)/etc/init.d/dae
	$(INSTALL_CONF) ./files/dae.config $(1)/etc/config/dae
	$(INSTALL_DATA) $(KDAE_SRC)/example.dae $(1)/etc/dae/example.dae
	$(INSTALL_DATA) ./files/dae.keep $(1)/lib/upgrade/keep.d/dae
endef

$(eval $(call BuildPackage,kdae))
