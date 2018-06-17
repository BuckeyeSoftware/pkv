CC ?= clang
DEBUG ?= 0
PROFILE ?= 0

rwildcard = $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

SRCS = $(call rwildcard, bes/, *.cpp *.c)
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

# Release builds /w most aggressive optimization flags
CFLAGS_RELEASE = \
	-O3 \
	-fomit-frame-pointer \
	-fno-stack-protector \
	-ffast-math

# Profile builds /w slightly less aggressive optimization and /w debug symbols and
# disables Cef and Leap motion (as they fork the process which gprof cannot deal with)
CFLAGS_PROFILE = \
	-D_NDEBUG \
	-g3 \
	-O2 \
	-pg \
	-no-pie \
	-fno-inline-functions \
	-fno-inline-functions-called-once \
	-fno-optimize-sibling-calls

# Debug builds enable trap and stack protector /w Leap and Cef enabled
CFLAGS_DEBUG = \
	-g3 \
	-O0 \
	-ftrapv \
	-fstack-protector-all \

CFLAGS_COMMON = \
	-I. \
	-Imodules/foundation/ \
	-fPIC \
	-fstrict-aliasing \
	-Wall \
	-Wextra \
	-Wundef \
	-Wshadow \
	-Wpointer-arith \
	-Wunreachable-code \
	-Wwrite-strings \
	-Winit-self \
	-MMD

CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_RELEASE)
LIB = bes-pkv.a

ifeq ($(PROFILE),1)
CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_PROFILE)
LIB = bes-pkv.a
endif

ifeq ($(DEBUG), 1)
CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
LIB = bes-pkv.a
endif

all: $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) -r -o $(LIB) $^

clean:
	rm -rf $(OBJS) $(DEPS) $(LIB)

.PHONY: clean

-include $(DEPS)
