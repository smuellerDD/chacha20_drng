#
# Copyright (C) 2016 - 2017, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -fPIC -Os -std=gnu99
#Hardening
CFLAGS +=-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden
LDFLAGS +=-Wl,-z,relro,-z,now

# Change as necessary
PREFIX := /usr/local
# library target directory (either lib or lib64)
LIBDIR := lib

NAME := chacha20_drng_test
C_SRCS := ../chacha20_drng.c chacha20_drng_test.c
JENT_OBJS:=

############################### Jitter RNG Seed Source ########################

ifneq (, $(wildcard ../jitterentropy-base.c))
CFLAGS += -DJENT
JENT_CFLAGS := -Wextra -Wall -pedantic -fPIC -O0 -std=gnu99 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden
JENT_SRCS += ../jitterentropy-base.c
JENT_OBJS += ${JENT_SRCS:.c=.o}
endif

########################### Linux getrandom Seed Source #######################

CFLAGS += -DGETRANDOM

########################### /dev/random Seed Source #######################

#CFLAGS += -DDEVRANDOM

################################ END CONFIGURATION ############################

C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS) $(JENT_OBJS)

INCLUDE_DIRS := ../
LIBRARY_DIRS :=
LIBRARIES :=

CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

.PHONY: all scan clean distclean

all: $(NAME)

$(NAME): $(C_OBJS) $(JENT_OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

$(JENT_OBJS):
	$(CC) $(JENT_SRCS) -c -o $(JENT_OBJS) $(JENT_CFLAGS) $(LDFLAGS)

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

clean:
	@- $(RM) $(NAME)
	@- $(RM) $(OBJS)

distclean: clean
