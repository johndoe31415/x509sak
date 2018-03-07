.PHONY: all test clean

CFLAGS := $(CFLAGS) -std=c11
CFLAGS += -Wall -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Werror=format -Wshadow
CFLAGS += -O3 -pthread -g -mtune=native
#CFLAGS += -g3 -pie -fPIE -fsanitize=address -fsanitize=undefined -fsanitize=leak
LDFLAGS := -lgmp

OBJS := pgmopts.o primegen.o argparse.o

all: primegen

test: all
	./primegen

clean:
	rm -f $(OBJS) primegen

primegen: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

