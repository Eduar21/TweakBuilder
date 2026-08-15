ARCHS = arm64
TARGET = iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = iayt

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Iayt
Iayt_FILES = Tweak.xm
Iayt_CFLAGS = -fobjc-arc -fmodules -Wno-deprecated-declarations
Iayt_FRAMEWORKS = UIKit Foundation
include $(THEOS_MAKE_PATH)/tweak.mk
