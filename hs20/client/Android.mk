LOCAL_PATH := $(call my-dir)

INCLUDES = $(LOCAL_PATH)
INCLUDES += $(LOCAL_PATH)/../../src/utils
INCLUDES += $(LOCAL_PATH)/../../src/common
INCLUDES += $(LOCAL_PATH)/../../src
INCLUDES += external/openssl/include
INCLUDES += external/libxml2/include
INCLUDES += external/curl/include
INCLUDES += external/webkit/Source/WebKit/gtk
ifneq ($(wildcard external/icu),)
INCLUDES += external/icu/icu4c/source/common
else
INCLUDES += external/icu4c/common
endif


#GTKCFLAGS := $(shell pkg-config --cflags gtk+-2.0 webkit-1.0)
#GTKLIBS := $(shell pkg-config --libs gtk+-2.0 webkit-1.0)
#CFLAGS += $(GTKCFLAGS)
#LIBS += $(GTKLIBS)

L_CFLAGS += -DCONFIG_CTRL_IFACE
L_CFLAGS += -DCONFIG_CTRL_IFACE_UNIX
L_CFLAGS += -DCONFIG_CTRL_IFACE_CLIENT_DIR=\"/data/misc/wifi/sockets\"
L_CFLAGS += -DLIBXML_SCHEMAS_ENABLED
L_CFLAGS += -DLIBXML_REGEXP_ENABLED

OBJS = spp_client.c
OBJS += oma_dm_client.c
OBJS += osu_client.c
OBJS += est.c
OBJS += ../../src/common/wpa_ctrl.c
OBJS += ../../src/common/wpa_helpers.c
OBJS += ../../src/utils/xml-utils.c
#OBJS += ../../src/utils/browser-android.c
OBJS += ../../src/utils/browser-wpadebug.c
OBJS += ../../src/utils/wpabuf.c
OBJS += ../../src/utils/eloop.c
OBJS += ../../src/wps/httpread.c
OBJS += ../../src/wps/http_server.c
OBJS += ../../src/utils/xml_libxml2.c
OBJS += ../../src/utils/http_curl.c
OBJS += ../../src/utils/base64.c
OBJS += ../../src/utils/os_unix.c
L_CFLAGS += -DCONFIG_DEBUG_FILE
OBJS += ../../src/utils/wpa_debug.c
OBJS += ../../src/utils/common.c
OBJS += ../../src/crypto/crypto_internal.c
OBJS += ../../src/crypto/md5-internal.c
OBJS += ../../src/crypto/sha1-internal.c
OBJS += ../../src/crypto/sha256-internal.c

L_CFLAGS += -DEAP_TLS_OPENSSL

#CFLAGS += $(shell xml2-config --cflags)
#LIBS += $(shell xml2-config --libs)


########################
include $(CLEAR_VARS)
LOCAL_MODULE := hs20-osu-client
LOCAL_MODULE_TAGS := optional

LOCAL_SHARED_LIBRARIES := libc libcutils
LOCAL_SHARED_LIBRARIES += libcrypto libssl
#LOCAL_SHARED_LIBRARIES += libxml2
LOCAL_STATIC_LIBRARIES += libxml2
LOCAL_SHARED_LIBRARIES += libicuuc
LOCAL_SHARED_LIBRARIES += libcurl

LOCAL_CFLAGS := $(L_CFLAGS)
LOCAL_SRC_FILES := $(OBJS)
LOCAL_C_INCLUDES := $(INCLUDES)
include $(BUILD_EXECUTABLE)

########################
