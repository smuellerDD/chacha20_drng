#
# Copyright (C) 2014, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -fPIC -Os -std=gnu99
#Hardening
CFLAGS +=-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden
LDFLAGS +=-Wl,-z,relro,-z,now

# Change as necessary
PREFIX ?= /usr/local
# library target directory (either lib or lib64)
LIBDIR := lib

NAME := chacha20_drng
LIBMAJOR=$(shell grep '^\#define[ \t]*MAJVERSION' chacha20_drng.c | awk '{print $$3}')
LIBMINOR=$(shell grep '^\#define[ \t]*MINVERSION' chacha20_drng.c | awk '{print $$3}')
LIBPATCH=$(shell grep '^\#define[ \t]*PATCHLEVEL' chacha20_drng.c | awk '{print $$3}')
LIBVERSION := $(LIBMAJOR).$(LIBMINOR).$(LIBPATCH)
C_SRCS := chacha20_drng.c
JENT_OBJS:=

############################### Jitter RNG Seed Source ########################

ifneq (, $(wildcard jitterentropy-base.c))
CFLAGS += -DJENT
JENT_CFLAGS := -Wextra -Wall -pedantic -fPIC -O0 -std=gnu99 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden
JENT_SRCS += jitterentropy-base.c
JENT_OBJS += ${JENT_SRCS:.c=.o}

else
########################### Linux getrandom Seed Source #######################

CFLAGS += -DGETRANDOM

endif

########################### /dev/random Seed Source #######################

#CFLAGS += -DDEVRANDOM

################################ END CONFIGURATION ############################

C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS) $(JENT_OBJS)

INCLUDE_DIRS :=
LIBRARY_DIRS :=
LIBRARIES :=

CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

.PHONY: all scan install clean distclean

all: $(NAME)

$(NAME): $(C_OBJS) $(JENT_OBJS)
	$(CC) -shared -Wl,-soname,lib$(NAME).so.$(LIBMAJOR) -o lib$(NAME).so.$(LIBVERSION) $(OBJS) $(LDFLAGS)
	$(AR) -rcs lib$(NAME).a $(OBJS)

$(JENT_OBJS):
	$(CC) $(JENT_SRCS) -c -o $(JENT_OBJS) $(JENT_CFLAGS) $(LDFLAGS)

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

install:
	mkdir -p $(PREFIX)/$(LIBDIR)
	mkdir -p $(PREFIX)/include
	install -m 0755 lib$(NAME).a $(PREFIX)/$(LIBDIR)/
	install -m 0755 -s lib$(NAME).so.$(LIBVERSION) $(PREFIX)/$(LIBDIR)/
	$(RM) $(PREFIX)/$(LIBDIR)/lib$(NAME).so.$(LIBMAJOR)
	ln -s lib$(NAME).so.$(LIBVERSION) $(PREFIX)/$(LIBDIR)/lib$(NAME).so.$(LIBMAJOR)
	install -m 0644 chacha20_drng.h $(PREFIX)/include

man:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh man

maninstall:
	install -m 0644 doc/man/* $(PREFIX)/share/man/man3

html:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh html

pdf:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh pdf

ps:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh ps

clean:
	@- $(RM) $(OBJS) $(NAME)
	@- $(RM) lib$(NAME).a
	@- $(RM) lib$(NAME).so.$(LIBVERSION)
	@- doc/gendocs.sh clean

distclean: clean
