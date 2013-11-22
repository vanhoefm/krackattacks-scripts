LOCAL_PATH:= $(call my-dir)

ifndef WPA_SUPPLICANT_VERSION
WPA_SUPPLICANT_VERSION := VER_0_8_X
endif
ifeq ($(WPA_SUPPLICANT_VERSION),VER_0_8_X)
# The order of the 2 Android.mks does matter!
# TODO: Clean up the Android.mks, reset all the temporary variables at the
# end of each Android.mk, so that one Android.mk doesn't depend on variables
# set up in the other Android.mk.
include $(LOCAL_PATH)/hostapd/Android.mk \
        $(LOCAL_PATH)/wpa_supplicant/Android.mk
endif
ifeq ($(WPA_SUPPLICANT_VERSION),VER_2_1_DEVEL)
include $(call all-subdir-makefiles)
endif
