CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror
LDFLAGS ?=

.PHONY: all clean

all: fallout-oneshot ref-mirror ref-rate mds-victim msr-freq

fallout-oneshot: fallout-oneshot.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

mds-victim: mds-victim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

msr-freq: msr-freq.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

ref-mirror: ref-mirror.c
	$(CC) -O0 -Wall -Wextra -Werror -o $@ $< $(LDFLAGS)

ref-rate: ref-rate.c
	$(CC) -O0 -Wall -Wextra -Werror -o $@ $< $(LDFLAGS)

ref-rate-inline: ref-rate.c
	$(CC) -O0 -Wall -Wextra -Werror -DINLINE_ACCESS -o $@ $< $(LDFLAGS)

clean:
	rm -f fallout-oneshot ref-mirror ref-rate mds-victim msr-freq
