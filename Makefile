CC=gcc
CFLAGS=-O2
LDFLAGS=-s -static

TARGET=png_alpha

OBJS=png_alpha.o

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ -lpng16 -lz

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
