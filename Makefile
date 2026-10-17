CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -O2 -pthread
TARGET = process_tree

all: $(TARGET)

$(TARGET): src/main.c
	$(CC) $(CFLAGS) src/main.c -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
