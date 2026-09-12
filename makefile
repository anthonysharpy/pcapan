GCCVERSION := gcc-15
OPT := -O3 -march=native -mtune=native -flto=auto -funroll-loops -fomit-frame-pointer -pipe
CFLAGS := -std=c23 $(OPT) -Wall -Wextra -DNDEBUG -Isrc
LDFLAGS := $(OPT)

SRCS := $(shell find src -name '*.c')
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all run clean

all: pcapan

pcapan: $(OBJS)
	$(GCCVERSION) $(LDFLAGS) $^ -o $@

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(GCCVERSION) $(CFLAGS) -MMD -MP -c $< -o $@

run: pcapan
	./pcapan

clean:
	$(RM) -r build pcapan

-include $(DEPS)