include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=twkg
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=BSD-3-Clause
PKG_MAINTAINER:=Aleksander Blazelonis <olokelo@gmail.com>

# Source settings (i.e. where to find the source codes)
# This is a custom variable, used below
SOURCE_DIR:=/home/oloke/Documents/Projects/wifi-tang

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/twkg
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Tang Wi-Fi Keygen
  DEPENDS:=+tang
endef

# Package description; a more verbose description on what our package does
define Package/twkg/description
  Tang key generator based on nearby Wi-Fi networks
endef

# Package preparation instructions; create the build directory and copy the source code.
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

# Package build instructions; invoke the target-specific compiler to first compile the source file, and then to link the file into the final executable
define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/twkg.o -c $(PKG_BUILD_DIR)/twkg.c
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/main.o -c $(PKG_BUILD_DIR)/main.c
	$(TARGET_CC) $(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/nanors/deps/obl -o $(PKG_BUILD_DIR)/nanors/rs.o -c $(PKG_BUILD_DIR)/nanors/rs.c
	$(TARGET_CC) $(TARGET_LDFLAGS) -lssl -lcrypto -ljansson -ljose -o $(PKG_BUILD_DIR)/$1 $(PKG_BUILD_DIR)/nanors/rs.o $(PKG_BUILD_DIR)/twkg.o $(PKG_BUILD_DIR)/main.o
endef

define Package/twkg/conffiles
/usr/share/twkg/
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/twkg/install
	$(INSTALL_DIR)  $(1)/usr/sbin
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/twkg $(1)/usr/sbin/
	$(INSTALL_BIN)  ./files/twkg_then_tang $(1)/usr/sbin/

	$(INSTALL_DIR)  $(1)/etc/init.d
	$(INSTALL_BIN)  ./files/twkg.init $(1)/etc/init.d/twkg

	$(INSTALL_DIR)  $(1)/etc/config
	$(INSTALL_CONF) ./files/config $(1)/etc/config/twkg

	$(INSTALL_DIR) $(1)/usr/share/acl.d
	$(INSTALL_DATA) ./files/twkg_acl.json $(1)/usr/share/acl.d/
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,twkg))