GCCVERSION := gcc-13
OPT := -O3 -march=native -flto=auto -funroll-loops -pipe
WARN := -Wall -Wextra -Wshadow -Wconversion -Wvla -Wpedantic -Wformat=2 \
        -Wmissing-prototypes -Wcast-qual
CFLAGS := -std=c2x $(OPT) $(WARN) -DNDEBUG -Isrc
LDFLAGS := -std=c2x $(OPT)
PROGRAM_ARGS := $(filter-out run,$(MAKECMDGOALS))

SRCS := $(shell find src -name '*.c')
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all run clean

all: pcapan

pcapan: $(OBJS)
	$(GCCVERSION) $(LDFLAGS) $^ -o $@ $(LDLIBS) -lm

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(GCCVERSION) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

run: pcapan
	./pcapan $(PROGRAM_ARGS)

clean:
	$(RM) -r build pcapan

-include $(DEPS)