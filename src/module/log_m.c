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

MODULE_LICENSE("GPL");

static int major_number;
//static struct class *sysfs_class = NULL;
static struct device *sysfs_device = NULL;
static log_row_t log_table[MAX_LOGS];
static int num_of_logs = 0;


static struct file_operations fops = {
	.owner = THIS_MODULE,
};

//sysfs device - first attribute implementation
ssize_t return_log_size(struct device *dev, struct device_attribute *attr, char *buf){	//sysfs display implementation

	return scnprintf(buf, PAGE_SIZE, "%d\n", num_of_logs);
}

//sysfs device - second attribute implementation
ssize_t display_log(struct device *dev, struct device_attribute *attr, char *buf){	//sysfs display implementation

	int log_num, count;
	char temp[FRAME_SIZE]; 
	char* buf_copy;
	
	temp[0] = '\0';
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		return -1;
		kfree(buf_copy);
	}
	
	for(log_num=0; log_num<MAX_LOGS-1; log_num++){
		if(log_table[log_num].is_valid != 0){
			
			// time
			sprintf(temp, "%lu", log_table[log_num].timestamp);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// src ip
			sprintf(temp, "%u", log_table[log_num].src_ip);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// dst ip
			sprintf(temp, "%u", log_table[log_num].dst_ip);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';

			// src port
			sprintf(temp, "%hu", log_table[log_num].src_port);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// dst port
			sprintf(temp, "%hu", log_table[log_num].dst_port);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// protocol
			sprintf(temp, "%hhu", log_table[log_num].protocol);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';

			// hooknum
			sprintf(temp, "%hhu", log_table[log_num].hooknum);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';

			// action
			sprintf(temp, "%hhu", log_table[log_num].action);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// reason
			sprintf(temp, "%d", log_table[log_num].reason);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// count
			sprintf(temp, "%u", log_table[log_num].count);
			strcat(buf_copy, temp);
			strcat(buf_copy, "\n");
			temp[0] = '\0';
		}
	}
	
	buf[0] = '\0';
	count = scnprintf(buf, PAGE_SIZE, "%s", buf_copy); 
	kfree(buf_copy);
	return count;
}

ssize_t clear_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs modify implementation

	int ret, log_line;
	char temp[1];
	temp[0] = '\0';
	
	ret = sscanf(buf, "%s", temp);
	if (ret != 1){
		printk(KERN_INFO "*** problam in reading data ***");
		return ret;
	}
	
	if (strlen(temp) != 1){
		printk(KERN_INFO "*** recived more then one char ***");
		return strlen(temp);
	}
	
	for (log_line=0; log_line<MAX_LOGS-1; log_line++){
		log_table[log_line].is_valid = 0;
	}
	num_of_logs = 0;
	return count;
}


static DEVICE_ATTR(log_size, S_IRWXO, return_log_size, NULL);
static DEVICE_ATTR(log_clear, S_IRWXO, display_log, clear_log);


int fw_log_device_create(struct class *sysfs_class){

	// create char device
	major_number = register_chrdev(0, "fw_log", &fops);
	if (major_number < 0){
		return -1;
	}
		
	/*
	// create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class)){
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}
	*/
	
	// create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, "fw" "_" "fw_log");	
	if (IS_ERR(sysfs_device)){
		//class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}
	
	// create 2 sysfs file attributes
	// fisrt file attribute
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr)){
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		//class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}
	// second file attribute
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_clear.attr)){
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
		//class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}
	
	printk(KERN_INFO "log module initiated successfully\n");	
	return 0;
}

void fw_log_device_clean(struct class *sysfs_class){
	
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
	//class_destroy(sysfs_class);
	unregister_chrdev(major_number, "fw_log");
	printk(KERN_INFO "log module cleaned\n");
}

void write_firewall_event_to_log(unsigned char protocol, unsigned int action, int hooknum, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, reason_t reason){
	
	struct timespec my_time; 
	int log_line, oldest_log_num = 0, repeating_log = 0; 
	unsigned long oldest_log;
	
	if(protocol == PROT_UDP){
		return;
	}
	
	getnstimeofday(&my_time);
	
	// check if identical log exists, if do, update it's time and count:
	for (log_line=0; log_line<MAX_LOGS-1; log_line++){

		// checking if this line in the table is valid 
		if (log_table[log_line].is_valid == 1){
			if( (log_table[log_line].protocol == protocol) && (log_table[log_line].action == action)\
				&& (log_table[log_line].src_ip == src_ip) && (log_table[log_line].dst_ip == dst_ip)\
				&& (log_table[log_line].src_port == src_port) && (log_table[log_line].dst_port == dst_port)\
				&& (log_table[log_line].reason == reason) ){
				log_table[num_of_logs].timestamp = my_time.tv_sec;
				log_table[log_line].count += 1;
				repeating_log = 1;
				break;
			}
		}
	}
				
	// need to insert a new log to the table:
	// check it there is still space in the table, and if so, insert
	if ((num_of_logs != MAX_LOGS) && !repeating_log){
		log_table[num_of_logs].is_valid = 1;
		log_table[num_of_logs].timestamp = my_time.tv_sec;
		log_table[num_of_logs].protocol = protocol;
		log_table[num_of_logs].action = action;
		log_table[num_of_logs].hooknum = hooknum;
		log_table[num_of_logs].src_ip = src_ip;
		log_table[num_of_logs].dst_ip = dst_ip;		
		log_table[num_of_logs].src_port = src_port; 
		log_table[num_of_logs].dst_port = dst_port; 
		log_table[num_of_logs].reason = reason;
		log_table[num_of_logs].count = 1;
		num_of_logs += 1;
	}
	
	// there is NO place in the log to write, so we need to write on the oldest
	else{
		oldest_log = log_table[0].timestamp;
		for (log_line = 0; log_line<MAX_LOGS-1; log_line++){
			if (oldest_log > log_table[log_line].timestamp){
				log_table[num_of_logs].timestamp = my_time.tv_sec;
				oldest_log_num = log_line;
			}
		}
		log_table[oldest_log_num].timestamp = my_time.tv_sec;
		log_table[oldest_log_num].protocol = protocol;
		log_table[oldest_log_num].action = action;
		log_table[oldest_log_num].hooknum = hooknum;
		log_table[oldest_log_num].src_ip = src_ip;
		log_table[oldest_log_num].dst_ip = dst_ip;		
		log_table[oldest_log_num].src_port = src_port; 
		log_table[oldest_log_num].dst_port = src_port; 
		log_table[oldest_log_num].reason = reason;
		log_table[oldest_log_num].count = 1;
	}
}

