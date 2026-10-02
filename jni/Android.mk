LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE     := app_info
LOCAL_SRC_FILES  := ../src/app_info.c ../src/main.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include
LOCAL_CFLAGS     := -std=c99 -Wall -Wextra -O2
LOCAL_LDLIBS     := -lz

include $(BUILD_EXECUTABLE)