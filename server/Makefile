CC = gcc
CFLAGS = -std=c89 -Ofast -Wall -Wextra -fsanitize=address
LIBS = `pkg-config openssl --cflags --libs`
TARGET = build/server
SRCS = $(wildcard src/**.c)
NCLUDE = -Iinclude

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p $(dir $(TARGET))
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^ $(LIBS)

clean:
	rm -rf $(dir $(TARGET))

format:
	bash format.sh

.PHONY: all clean
