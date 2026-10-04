CC      := gcc
ROOT    := $(CURDIR)
CFLAGS  := -std=c99 -Wall -Wextra -Wno-format-truncation -Wno-restrict -I$(ROOT)/include -O2 -fPIC
LDLIBS  := -lz

BUILD   := $(ROOT)/build

CLI_SRC := $(ROOT)/src/app_info.c $(ROOT)/src/main.c
CLI_BIN := $(BUILD)/app_info

LIB_SRC := $(ROOT)/src/app_info.c
LIB_OBJ := $(BUILD)/app_info.o
LIB_BIN := $(BUILD)/libapp_info.a

all: $(CLI_BIN) $(LIB_BIN)

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: $(ROOT)/src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLI_BIN): $(CLI_SRC) | $(BUILD)
	$(CC) $(CFLAGS) $(CLI_SRC) -o $@ $(LDLIBS)

$(LIB_BIN): $(LIB_OBJ)
	ar rcs $@ $^

clean:
	rm -rf $(BUILD)

.PHONY: all clean