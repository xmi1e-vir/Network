# Makefile for add-nbo

# Compiler
CC = gcc

# Target executable
TARGET = add_nbo

# Source files
SRCS = add_nbo.c

# Default target
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(SRCS)
	$(CC) -o $@ $^

# Clean up build artifacts
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: all clean
