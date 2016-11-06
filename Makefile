KVERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/${KVERSION}/build

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: modules modules_install clean
