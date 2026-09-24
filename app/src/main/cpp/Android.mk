# hev-socks5-tunnel + JNI wrapper.
#
# Sources: anonvector/SlipNet's vendored, patched hev-socks5-tunnel
# (adds reject_quic / reject_non_dns_udp / stats on top of upstream
# heiher/hev-socks5-tunnel). JNI wrapper retargeted to com.dnstun.app.

MY_LOCAL_PATH := $(call my-dir)

include $(MY_LOCAL_PATH)/hev-socks5-tunnel-src/Android.mk

LOCAL_PATH := $(MY_LOCAL_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := hev-tunnel-jni
LOCAL_SRC_FILES := hev_jni.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/hev-socks5-tunnel-src/include
LOCAL_SHARED_LIBRARIES := hev-socks5-tunnel
LOCAL_LDLIBS := -llog
LOCAL_LDFLAGS += -Wl,-z,max-page-size=16384
LOCAL_LDFLAGS += -Wl,-z,common-page-size=16384
LOCAL_LDFLAGS += -Wl,--gc-sections -s

include $(BUILD_SHARED_LIBRARY)
