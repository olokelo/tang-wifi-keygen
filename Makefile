CC = gcc

INCDIR = ./nanors/deps/obl

SRCS = twkg.c ./nanors/rs.c
PROG_SRCS = main.c
TEST_SRCS = ./tests/twkg_test.c

TARGET = twkg
TEST_TARGET = twkg_test

CFLAGS = -I$(INCDIR) -Os -g3 -Wall -Wextra

LIBS = -lssl -lcrypto -ljansson -ljose
TEST_LIBS = -lcriterion

all: $(TARGET) tests

$(TARGET): $(SRCS)
	$(CC) $(PROG_SRCS) $(SRCS) $(CFLAGS) $(LIBS) -o $(TARGET)

tests:
	$(CC) $(TEST_SRCS) $(SRCS) $(CFLAGS) $(LIBS) $(TEST_LIBS) -o $(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET)

.PHONY: all tests clean
