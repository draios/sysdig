ppm-y += main.o ppm_events.o ppm_fillers.o event_table.o syscall_table.o syscall_info_table.o
obj-m += ppm.o
ccflags-y := -D_DEBUG 
TOP := $(shell pwd)
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(TOP) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(TOP) clean

install: all
	make -C /lib/modules/$(shell uname -r)/build M=$(TOP) modules_install
