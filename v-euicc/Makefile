# Makefile for Virtual eUICC
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -pthread
INCLUDES = -Iinclude -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib -lssl -lcrypto
SRCDIR = src
BUILDDIR = build
BINDIR = bin

# Source files
CORE_SOURCES = $(SRCDIR)/v_euicc_core.c
PROTOCOL_SOURCES = $(SRCDIR)/v_euicc_protocol.c
CRYPTO_SOURCES = $(SRCDIR)/v_euicc_crypto.c
SERVER_SOURCES = $(SRCDIR)/v_euicc_server.c

# Object files
CORE_OBJECTS = $(BUILDDIR)/v_euicc_core.o
PROTOCOL_OBJECTS = $(BUILDDIR)/v_euicc_protocol.o
CRYPTO_OBJECTS = $(BUILDDIR)/v_euicc_crypto.o
SERVER_OBJECTS = $(BUILDDIR)/v_euicc_server.o

# Targets
SERVER_TARGET = $(BINDIR)/v-euicc-server
LIBRARY_TARGET = $(BUILDDIR)/libv-euicc.a

# Debug build
DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -g -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Default target
all: $(SERVER_TARGET) $(LIBRARY_TARGET)

# Create directories
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Object files
$(CORE_OBJECTS): $(CORE_SOURCES) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(PROTOCOL_OBJECTS): $(PROTOCOL_SOURCES) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(CRYPTO_OBJECTS): $(CRYPTO_SOURCES) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(SERVER_OBJECTS): $(SERVER_SOURCES) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Library target
$(LIBRARY_TARGET): $(CORE_OBJECTS) $(PROTOCOL_OBJECTS) $(CRYPTO_OBJECTS) | $(BUILDDIR)
	ar rcs $@ $^

# Server executable
$(SERVER_TARGET): $(SERVER_OBJECTS) $(LIBRARY_TARGET) | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LIBRARY_TARGET) $(LDFLAGS)

# Install target
install: $(SERVER_TARGET)
	cp $(SERVER_TARGET) /usr/local/bin/
	mkdir -p /usr/local/include/v-euicc
	cp include/*.h /usr/local/include/v-euicc/
	cp $(LIBRARY_TARGET) /usr/local/lib/

# Clean target
clean:
	rm -rf $(BUILDDIR) $(BINDIR)

# Debug build
debug:
	$(MAKE) DEBUG=1

# Test run
test: $(SERVER_TARGET)
	./$(SERVER_TARGET) --debug --address /tmp/v-euicc-test.sock

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Build all targets (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  debug      - Build with debug information"
	@echo "  test       - Build and run test server"
	@echo "  install    - Install to system directories"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  DEBUG=1    - Enable debug build"
	@echo "  CC         - C compiler (default: gcc)"

.PHONY: all clean debug test install help 