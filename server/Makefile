CC = gcc
CFLAGS = -std=c99 -Ofast -Wall -Wextra -g
LIBS = `pkg-config openssl --cflags --libs`
TARGET = build/server
SRCS = $(wildcard src/**.c)
INCLUDE = -Iinclude

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p $(dir $(TARGET))
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^ $(LIBS)

clean:
	rm -rf $(dir $(TARGET))

format:
	bash format.sh

.PHONY: all clean
