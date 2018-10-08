obj-m += firewall.o

#ccflags -y := -std=gnu99 -Wall -Werror -pedantic-errors

#firewall-y = fw.o

firewall-objs = fw.o netfilter_m.o rules_m.o log_m.o conn_m.o


all:
	make -C /lib/modules/3.2.0-37-generic-pae/build M=/home/fw/Desktop/hw5/module/ modules

clean:
	make -C /lib/modules/3.2.0-37-generic-pae/build M=/home/fw/Desktop/hw5/module/ clean
	
