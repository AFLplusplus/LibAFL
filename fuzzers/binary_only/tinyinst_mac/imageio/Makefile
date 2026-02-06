# Makefile for ImageIO harness on macOS
# Requires Xcode Command Line Tools

CC = clang
CFLAGS = -O2 -g -framework Foundation -framework CoreGraphics -framework ImageIO -framework AppKit
TARGET = imageio

all: $(TARGET)

$(TARGET): imageio.m
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
