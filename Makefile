TARGET := iphone:clang:latest:12.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = llas-patcher

llas-patcher_FILES = Tweak.x
llas-patcher_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
