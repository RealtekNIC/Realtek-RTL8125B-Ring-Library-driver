# SPDX-License-Identifier: GPL-2.0-only
ifeq ($(KP_MODULE_ROOT),)
	KP_MODULE_ROOT=$(KERNEL_SRC)/$(M)
endif


M ?= $(shell pwd)

r8125-y	:= r8125_n.o \
		r8125_firmware.o \
		r8125_lib.o \
		r8125_ptp.o \
		r8125_rss.o \
		rtl_eeprom.o \
		rtltool.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

KBUILD_OPTIONS+=KBUILD_DTC_INCLUDE=$(KP_MODULE_ROOT)
KBUILD_OPTIONS+=CONFIG_R8125=m

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) modules $(KBUILD_OPTIONS)

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) clean
