sysdig-probe-y += main.o flags_table.o ppm_events.o ppm_fillers.o event_table.o syscall_table.o syscall_info_table.o
obj-m += sysdig-probe.o
ccflags-y := 
TOP := $(shell pwd)
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(TOP) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(TOP) clean

install: all
	make -C /lib/modules/$(shell uname -r)/build M=$(TOP) modules_install
