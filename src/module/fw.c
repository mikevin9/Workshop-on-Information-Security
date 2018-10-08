#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/ctype.h>

#include "fw.h"
#include "netfilter_m.h"
#include "rules_m.h"
#include "log_m.h"
#include "conn_m.h"

MODULE_LICENSE("GPL");

static struct class *sysfs_class = NULL;


int init_module(void){ 
	
	int is_valid;
	
	printk(KERN_INFO "****************\n****************\n****************\n");
	// create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class)){
		return -1;
	}
	
	is_valid = netfilter_module_init();
	if(is_valid != 0){
		// no need to print error. already done in netfilter_module_init()
		class_destroy(sysfs_class);
		return -1;
	}
	
	is_valid = fw_rules_device_create(sysfs_class);
	if(is_valid != 0){
		// no need to print error. already done in fw_rules_device_create()
		netfilter_module_clean();
		class_destroy(sysfs_class);
		return -1;
	}
	
	is_valid = fw_log_device_create(sysfs_class);
	if(is_valid != 0){
		// no need to print error. already done in fw_log_device_create()
		netfilter_module_clean();
		fw_rules_device_clean(sysfs_class);
		class_destroy(sysfs_class);
		return -1;
	}

	is_valid = fw_conn_device_create(sysfs_class);
	if(is_valid != 0){
		// no need to print error. already done in fw_conns_device_create()
		netfilter_module_clean();
		fw_rules_device_clean(sysfs_class);
		fw_log_device_clean(sysfs_class);
		class_destroy(sysfs_class);
		return -1;
	}
		
	printk(KERN_INFO "module initiated successfully\n");	
	return 0;
} 

void cleanup_module(void){
	
	netfilter_module_clean();
	fw_rules_device_clean(sysfs_class);
	fw_log_device_clean(sysfs_class);
	fw_conn_device_clean(sysfs_class);
	class_destroy(sysfs_class);
	printk(KERN_INFO "module cleaned\n");
	printk(KERN_INFO "****************\n****************\n****************\n");
	printk(KERN_INFO "****************\n****************\n****************\n");
}
