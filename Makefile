KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := kvwatch.o
kvwatch-objs := src/main.o src/store.o src/subs.o

EXTRA_CFLAGS += -I$(PWD)/include

USER_CFLAGS := -Wall -O2 -Iinclude -Ilib

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) lib/kvwatch_user.o tests/test_sub tests/test_set tests/test_stats

userlib:
	$(CC) $(USER_CFLAGS) -c lib/kvwatch_user.c -o lib/kvwatch_user.o

tests: userlib
	$(CC) $(USER_CFLAGS) lib/kvwatch_user.o tests/test_sub.c  -o tests/test_sub
	$(CC) $(USER_CFLAGS) lib/kvwatch_user.o tests/test_set.c  -o tests/test_set
	$(CC) $(USER_CFLAGS) lib/kvwatch_user.o tests/test_stats.c -o tests/test_stats
