sysdig-probe-y += main.o flags_table.o ppm_events.o ppm_fillers.o event_table.o syscall_table.o
obj-m += sysdig-probe.o
ccflags-y := 

KERNELDIR 		?= /lib/modules/$(shell uname -r)/build

TOP := $(shell pwd)
all:
	make -C $(KERNELDIR) M=$(TOP) modules
 
clean:
	make -C $(KERNELDIR) M=$(TOP) clean

install: all
	make -C $(KERNELDIR) M=$(TOP) modules_install
