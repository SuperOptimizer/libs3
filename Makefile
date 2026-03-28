CC ?= gcc
CFLAGS = -std=c2x -Wall -Wextra -Wpedantic -Wno-unused-parameter -g -O2 -I.
LDFLAGS = -lcurl -lpthread

SRC_DIR = src
BUILD_DIR = build

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean test test_unit test_integration

all: $(BUILD_DIR)/libs3.a $(BUILD_DIR)/libs3.so

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c s3.h $(SRC_DIR)/s3_internal.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(BUILD_DIR)/libs3.a: $(OBJECTS)
	ar rcs $@ $^

$(BUILD_DIR)/libs3.so: $(OBJECTS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Tests
$(BUILD_DIR)/test_unit: tests/test_crypto.c $(BUILD_DIR)/libs3.a | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(BUILD_DIR)/libs3.a $(LDFLAGS)

$(BUILD_DIR)/test_integration: tests/test_integration.c $(BUILD_DIR)/libs3.a | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(BUILD_DIR)/libs3.a $(LDFLAGS)

test_unit: $(BUILD_DIR)/test_unit
	$(BUILD_DIR)/test_unit

test_integration: $(BUILD_DIR)/test_integration
	$(BUILD_DIR)/test_integration

test: test_unit

clean:
	rm -rf $(BUILD_DIR)
