GCCVERSION := gcc-15
OPT := -O3 -march=native -flto=auto -funroll-loops -pipe
WARN := -Wall -Wextra -Wshadow -Wconversion -Wvla -Wpedantic -Wformat=2 \
        -Wmissing-prototypes -Wcast-qual
CFLAGS := -std=c23 $(OPT) $(WARN) -DNDEBUG -Isrc
LDFLAGS := -std=c23 $(OPT)

SRCS := $(shell find src -name '*.c')
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all run clean

all: pcapan

pcapan: $(OBJS)
	$(GCCVERSION) $(LDFLAGS) $^ -o $@ $(LDLIBS)

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(GCCVERSION) $(CFLAGS) -MMD -MP -c $< -o $@

run: pcapan
	./pcapan

clean:
	$(RM) -r build pcapan

-include $(DEPS)