CC      := gcc
CFLAGS  := -g -O2 -Isrc $(shell pkg-config --cflags check)
LDLIBS  := $(shell pkg-config --libs check)

TEST_SRCS   := test_utils.c ../src/utils.c
TEST_BIN    := test_utils

.PHONY: all check clean

all: $(TEST_BIN)

check: all
	@./$(TEST_BIN)

# Compila el ejecutable de tests
$(TEST_BIN): $(TEST_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	@rm -f $(TEST_BIN)