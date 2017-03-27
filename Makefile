KVERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/${KVERSION}/build

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f kdbr_test
	rm -f cma_test

test:
	gcc kdbr_test.c -o kdbr_test
	gcc cross_memory_attach_test.c -o cma_test

clean_test:
	rm -f kdbr_test
	rm -f cma_test

.PHONY: modules modules_install clean clean_test
