# Build the standalone C verifier `verify_kat` against the unmodified vendored
# HAWK Round 2 reference C implementation.
#
# The HAWK reference's core .c files are identical across hawk256/hawk512/hawk1024;
# only `api.c` and `api.h` differ.  We use hawk512's directory for the core sources
# but DO NOT compile its `api.c` (which would hardcode logn=9).  Our own
# `verify_kat.c` calls `hawk_verify_finish` directly with a runtime logn.
#
# Run:
#     make
# Output:
#     ./verify_kat

ROOT      := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
HAWK_REF  := $(ROOT)/third_party/hawk-sign-submission/hawk-submission/Reference_Implementation/hawk512

CC        ?= cc
CFLAGS    ?= -O2 -Wall -Wextra -Wshadow -Wundef -std=c99
CPPFLAGS  += -I$(HAWK_REF)

CORE_SRCS := \
	$(HAWK_REF)/hawk_kgen.c \
	$(HAWK_REF)/hawk_sign.c \
	$(HAWK_REF)/hawk_vrfy.c \
	$(HAWK_REF)/ng_fxp.c \
	$(HAWK_REF)/ng_hawk.c \
	$(HAWK_REF)/ng_mp31.c \
	$(HAWK_REF)/ng_ntru.c \
	$(HAWK_REF)/ng_poly.c \
	$(HAWK_REF)/ng_zint31.c \
	$(HAWK_REF)/sha3.c

DRIVER_SRC := $(dir $(lastword $(MAKEFILE_LIST)))verify_kat.c

all: verify_kat

verify_kat: $(DRIVER_SRC) $(CORE_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(DRIVER_SRC) $(CORE_SRCS)

clean:
	rm -f verify_kat

.PHONY: all clean
