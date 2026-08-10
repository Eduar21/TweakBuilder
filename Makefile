ARCHS = arm64
TARGET = iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = disasm

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Disasm
Disasm_FILES = Tweak.xm
Disasm_CFLAGS = -fobjc-arc -fmodules -Wno-deprecated-declarations
Disasm_FRAMEWORKS = UIKit Foundation
Disasm_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
