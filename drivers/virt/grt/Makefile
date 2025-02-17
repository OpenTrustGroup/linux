# SPDX-License-Identifier: GPL-2.0-only
ifneq ($(KERNELRELEASE),)
# kbuild part
include Kbuild

else
obj-y += guest_memory/
obj-y += acrn/
obj-y += acrn_nbl/
obj-y += vhost/
obj-y += nebula_mailbox/
obj-y += vhost_adsp/
obj-y += vhost_dmabuf/
obj-y += vhost_gpio/
obj-y += spi_vhost/
obj-y += i2c_vhost/
obj-y += vhost_cmdq/
obj-y += power_service/
obj-y += samples/
obj-y += nebula_rtc/

## normal Makefile
#SUBDIRS := $(wildcard */.)
#
#.PHONY: all $(SUBDIRS)
#
## run make in each subdirectory
#all: $(SUBDIRS)
#	echo $(abspath $(lastword $(MAKEFILE_LIST)))
#
#$(SUBDIRS):
#	echo $(abspath $(lastword $(MAKEFILE_LIST)))
#	echo "KERNEL_SRC is $(KERNEL_SRC)"
##	$(MAKE) -C $@
#	$(MAKE) -C $(KERNEL_SRC) M=$(M) modules $(KBUILD_OPTIONS) KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)"


ifneq ($(wildcard $(KERNEL_SRC)/$(DEVICE_MODULES_REL_DIR)/Makefile.include),)
include $(KERNEL_SRC)/$(DEVICE_MODULES_REL_DIR)/Makefile.include
endif

$(info MAKE=$(MAKE) KERNEL_SRC=$(KERNEL_SRC) M=$(M) KBUILD_OPTIONS=$(KBUILD_OPTIONS) KBUILD_EXTRA_SYMBOLS=$(EXTRA_SYMBOLS))

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) modules $(KBUILD_OPTIONS) KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)"

modules_install:
	$(MAKE) M=$(M) -C $(KERNEL_SRC) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) clean

endif
