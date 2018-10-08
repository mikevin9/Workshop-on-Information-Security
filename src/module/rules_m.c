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
#include "conn_m.h"
#include "log_m.h"

MODULE_LICENSE("GPL");

static int major_number;
//static struct class *sysfs_class = NULL;
static struct device *sysfs_device = NULL;
static rule_t rule_table[MAX_RULES];
static int fw_is_on = 0, num_of_rules = 0;



void insert_hardcoded_ruls(void);
unsigned int calculate_mask(unsigned int prefix_size);
char *strsep(char **s, const char *ct);
int is_all_digits(char *temp);


static struct file_operations fops = {
	.owner = THIS_MODULE,
};


//sysfs device - first attribute implementation
ssize_t check_if_on(struct device *dev, struct device_attribute *attr, char *buf){	//sysfs display implementation

	return scnprintf(buf, PAGE_SIZE, "%d\n", fw_is_on);
}

ssize_t turn_on_off(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs modify implementation

	int ret, command = -1;
	
	ret = sscanf(buf, "%d", &command);
	if(ret != 1){
		printk(KERN_INFO "*** problam in reading data ***");
		return ret;
	}
	if(command != 1 && command != 0){
		printk(KERN_INFO "*** input wasn't '0' or '1' ***");
		return ret;
	}
	
	if(fw_is_on && command){ // fw_is_on = 1, command = 1
		printk(KERN_INFO "*** fw already activated ***");
	}
	else if(!fw_is_on && !command){ // fw_is_on = 0, command = 0
		printk(KERN_INFO "*** fw already deactivated ***");
	}
	else if(fw_is_on && !command){ // fw_is_on = 1, command = 0		i.e deactivate fw
		fw_is_on = 0;
		printk(KERN_INFO "*** fw deactivated ***");
	}
	else{ //(!fw_is_on && command) // fw_is_on = 0, command = 1	i.e activate fw
		fw_is_on = 1;
		printk(KERN_INFO "*** fw activated ***");
	}
	
	return count;
}

//sysfs device - second attribute implementation
ssize_t display_num_of_rules(struct device *dev, struct device_attribute *attr, char *buf){	//sysfs display implementation

	return scnprintf(buf, PAGE_SIZE, "%d\n", num_of_rules);
}

ssize_t clear_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs modify implementation

	int ret, rule_num;
	char temp[1];
	temp[0] = '\0';
	
	ret = sscanf(buf, "%s", temp);
	if(ret != 1){
		printk(KERN_INFO "*** problam in reading data ***");
		return ret;
	}
	if(strlen(temp) != 1){
		printk(KERN_INFO "*** recived more then one char ***");
		return strlen(temp);
	}
	
	for(rule_num=0; rule_num<MAX_RULES-1; rule_num++){
		rule_table[rule_num].is_valid = 0;
	}
	
	num_of_rules = 0;
	clear_connections_table();
	return count;
}

//sysfs device - third attribute implementation
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf){	//sysfs display implementation

	int rule_num, count;
	char temp[FRAME_SIZE]; 
	char* buf_copy;
	
	temp[0] = '\0';
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		return -1;
		kfree(buf_copy);
	}

	for(rule_num=0; rule_num<MAX_RULES-1; rule_num++){
		if(rule_table[rule_num].is_valid != 0){
			// rule name
			strcat(buf_copy, rule_table[rule_num].rule_name);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// direction
			sprintf(temp, "%u", rule_table[rule_num].direction);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';

			// src ip
			sprintf(temp, "%u", rule_table[rule_num].src_ip);
			strcat(buf_copy, temp);
			strcat(buf_copy, "/");
			temp[0] = '\0';
			sprintf(temp, "%hhu", rule_table[rule_num].src_prefix_size);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// dst ip
			sprintf(temp, "%u", rule_table[rule_num].dst_ip);
			strcat(buf_copy, temp);
			strcat(buf_copy, "/");
			temp[0] = '\0';
			sprintf(temp, "%hhu", rule_table[rule_num].dst_prefix_size);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// protocol
			sprintf(temp, "%hhu", rule_table[rule_num].protocol);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// src port
			sprintf(temp, "%hu", rule_table[rule_num].src_port);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// dst port
			sprintf(temp, "%hu", rule_table[rule_num].dst_port);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// ack
			sprintf(temp, "%d", rule_table[rule_num].ack);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			
			// action
			sprintf(temp, "%d", rule_table[rule_num].action);
			strcat(buf_copy, temp);
			//strcat(buf_copy, " ");
			temp[0] = '\0';
			strcat(buf_copy, "\n");
		}
	}
	
	buf[0] = '\0';
	count = scnprintf(buf, PAGE_SIZE, "%s", buf_copy); 
	kfree(buf_copy);
	return count;
}

ssize_t load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){	//sysfs modify implementation

	int rule_num = 0, i;
	char *buf_copy, *temp;
	unsigned long temp_num;
	
	//buf_copy = kmalloc(PAGE_SIZE, GFP_KERNEL);
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		return -1;
		kfree(buf_copy);
	}
	strncpy(buf_copy, buf, PAGE_SIZE);
	
	temp = strsep(&buf_copy, " ");
	while (strlen(temp) > 0){		
		
		// rule name
		if (strlen(temp) > 20){
			printk(KERN_INFO "Invalid parameter passed 1, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		strcpy(rule_table[rule_num].rule_name, temp);
		
		// direction
		temp = strsep(&buf_copy, " ");
		if (strlen(temp) == 0 || strlen(temp) > 1 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 2, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].direction = (direction_t)temp_num;
		
		// src ip	
		temp = strsep(&buf_copy, "/");
		if (strlen(temp) == 0 || strlen(temp) > 10 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 3, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].src_ip = (__be32)temp_num;

		// src prefix
		temp = strsep(&buf_copy, " ");
		if(strlen(temp) > 2 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 4, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].src_prefix_size = (__u8)temp_num;
		rule_table[rule_num].src_prefix_mask = calculate_mask(rule_table[rule_num].src_prefix_size);

		// dst ip
		temp = strsep(&buf_copy, "/");
		if (strlen(temp) == 0 || strlen(temp) > 10 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 5, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].dst_ip = (__be32)temp_num;

		// dst prefix
		temp = strsep(&buf_copy, " ");
		if (strlen(temp) == 0 || strlen(temp) > 2 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 6, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].dst_prefix_size = (__u8)temp_num;
		rule_table[rule_num].dst_prefix_mask = calculate_mask(rule_table[rule_num].dst_prefix_size);
		
		// protocol
		temp = strsep(&buf_copy, " ");
		if (strlen(temp) == 0 || strlen(temp) > 3 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 7, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].protocol = (__u8)temp_num;
		
		// src port
		temp = strsep(&buf_copy, " ");
		if (strlen(temp) == 0 || strlen(temp) > 4 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 8, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].src_port = (__be16)temp_num;
		
		// dst port
		temp = strsep(&buf_copy, " ");
		if (strlen(temp) == 0 || strlen(temp) > 4 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 9, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].dst_port = (__be16)temp_num;
		
		// ack
		temp = strsep(&buf_copy, " ");
		if (strlen(temp) == 0 || strlen(temp) > 1 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 10, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].ack = (flag_t)temp_num;
		
		// decision
		temp = strsep(&buf_copy, "\r\n");
		if (strlen(temp) == 0 || strlen(temp) > 1 || !is_all_digits(temp)){
			printk(KERN_INFO "Invalid parameter passed 11, %d\n", rule_num);
			kfree(buf_copy);
			return -1;
		}
		kstrtoul(temp, 10, &temp_num);
		rule_table[rule_num].action = (__u8)temp_num;
		
		rule_table[rule_num].is_valid = 1;
		rule_num +=1;
		temp = strsep(&buf_copy, " ");
	}
	kfree(buf_copy);
	num_of_rules = rule_num;
	if (rule_num < (MAX_RULES-1)){
		for (i = rule_num; i< MAX_RULES-1; i++){
			rule_table[i].is_valid = 0;
		}
	}
	
	clear_connections_table();
	return count;
}


static DEVICE_ATTR(active, S_IRWXO, check_if_on, turn_on_off);
static DEVICE_ATTR(rules_size, S_IRWXO, display_num_of_rules, clear_rules);
static DEVICE_ATTR(rule_management, S_IRWXO, display_rules, load_rules);


int fw_rules_device_create(struct class *sysfs_class){
		
	//create char device
	major_number = register_chrdev(0, "fw_rules", &fops);
	if (major_number < 0){
		return -1;
	}
	
	/*	
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class)){
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	*/
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, "fw" "_" "fw_rules");	
	if (IS_ERR(sysfs_device)){
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	
	//create 3 sysfs file attributes
	//fisrt file attribute
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr)){
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	//second file attribute
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr)){
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	//third file attribute
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rule_management.attr)){
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	
	//insert_hardcoded_ruls();
	fw_is_on = 1;
	printk(KERN_INFO "rules module initiated successfully\n");		
	return 0;
}

void fw_rules_device_clean(struct class *sysfs_class){
		
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rule_management.attr);
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
	//class_destroy(sysfs_class);
	unregister_chrdev(major_number, "fw_rules");
	fw_is_on = 0;
	printk(KERN_INFO "rules module cleaned\n");
}

unsigned int check_packet_with_rules_table(unsigned int hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, prot_t protocol, direction_t direction, struct tcphdr *tcp_header){

	int rule_num;
			
	// check if firewall is on:
	if (!fw_is_on){
		write_firewall_event_to_log(protocol, NF_DROP, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_FW_INACTIVE);
		return NF_DROP;
	}
	
	// check in the rule table:
	for (rule_num=0; rule_num<MAX_RULES-1; rule_num++){
		
		// checking if current line in the table is valid
		if (rule_table[rule_num].is_valid == 1){
						
			// if line valid, check parameters that are relevent for all protocols
			if ((rule_table[rule_num].direction == DIRECTION_ANY || rule_table[rule_num].direction == direction)
				&& ((rule_table[rule_num].protocol == PROT_ANY || rule_table[rule_num].protocol == protocol)
					|| ((rule_table[rule_num].protocol == PROT_OTHER) && (protocol != PROT_ICMP) && (protocol != PROT_TCP)
						&& (protocol != PROT_UDP)))
				&& ((rule_table[rule_num].src_ip & rule_table[rule_num].src_prefix_mask) == (src_ip & rule_table[rule_num].src_prefix_mask))
				&& ((rule_table[rule_num].dst_ip & rule_table[rule_num].dst_prefix_mask) == (dst_ip & rule_table[rule_num].dst_prefix_mask))){				
					
				// next parameters are relevent only for TCP\UDP
				if ((rule_table[rule_num].src_port == src_port || rule_table[rule_num].src_port == PORT_ANY) 
					&& (rule_table[rule_num].dst_port == dst_port || rule_table[rule_num].dst_port == PORT_ANY)){
					
					// next parameter relevent only for TCP
					if (protocol == PROT_TCP){
						if (rule_table[rule_num].ack != tcp_header->ack && rule_table[rule_num].ack != FLAG_ANY){
							continue;
						}
						else if (tcp_header->fin && tcp_header->urg && tcp_header->psh){
							write_firewall_event_to_log(protocol, NF_DROP, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_XMAS_PACKET);
							return NF_DROP;
						}
						else{ // the packet matched a TCP rule
							write_firewall_event_to_log(protocol, rule_table[rule_num].action, hooknum, src_ip, dst_ip, src_port, dst_port, rule_num);
							if(rule_table[rule_num].action == NF_ACCEPT){
								if(hooknum == NF_INET_PRE_ROUTING){
									add_to_connections_table(src_ip, dst_ip, src_port, dst_port, rule_num);
									//printk(KERN_INFO "add to conn_tlb - src_ip:%d ;dst_ip:%d ;src_port:%d ;dst_port:%d \n", src_ip, dst_ip, src_port, dst_port);
								}
								else { // hooknum == NF_INET_LOCAL_OUT 
									add_to_connections_table(dst_ip, src_ip, dst_port, src_port, rule_num);
									//printk(KERN_INFO "add to conn_tlb - src_ip:%d ;dst_ip:%d ;src_port:%d ;dst_port:%d \n", dst_ip, src_ip, dst_port, src_port);
								}
							}
							return rule_table[rule_num].action;
						}
					}
					// the packet matched a UDP rule
					write_firewall_event_to_log(protocol, rule_table[rule_num].action, hooknum, src_ip, dst_ip, src_port, dst_port, rule_num);
					return rule_table[rule_num].action;
				}
				// the packet matched a ICMP rule
				write_firewall_event_to_log(protocol, rule_table[rule_num].action, hooknum, src_ip, dst_ip, src_port, dst_port, rule_num);
				return rule_table[rule_num].action;
			}
		}
	}
	// the packet didn't matched any rule
	write_firewall_event_to_log(protocol, NF_DROP, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_NO_MATCHING_RULE);
	return NF_DROP;
}

unsigned int kernel_check_is_on (void){
	return fw_is_on;
}

///===================
/// Utills part:
///===================

unsigned int calculate_mask(unsigned int prefix_size){
	
	int  div, mod, num = 256, num1 = 255;
	unsigned long result = 0;	
	
	div = (int)prefix_size / 8;
	mod = prefix_size % 8;
	if (div == 0){
		result = 0;
	}
	else if (div == 1){
		if (mod == 0){ result = (num1 * num * num * num); } 
		if (mod == 1){ result = (num1 * num * num * num) + 128; } 
		if (mod == 2){ result = (num1 * num * num * num) + 192; } 
		if (mod == 3){ result = (num1 * num * num * num) + 224; } 
		if (mod == 4){ result = (num1 * num * num * num) + 240; } 
		if (mod == 5){ result = (num1 * num * num * num) + 248; } 
		if (mod == 6){ result = (num1 * num * num * num) + 252; } 
		if (mod == 7){ result = (num1 * num * num * num) + 254; } 
	} 
	else if (div == 2){ 
		if (mod == 0){ result = (num1 * num * num * num) + (num1 * num * num); } 
		if (mod == 1){ result = (num1 * num * num * num) + (num1 * num * num) + 128; } 
		if (mod == 2){ result = (num1 * num * num * num) + (num1 * num * num) + 192; } 
		if (mod == 3){ result = (num1 * num * num * num) + (num1 * num * num) + 224; } 
		if (mod == 4){ result = (num1 * num * num * num) + (num1 * num * num) + 240; } 
		if (mod == 5){ result = (num1 * num * num * num) + (num1 * num * num) + 248; } 
		if (mod == 6){ result = (num1 * num * num * num) + (num1 * num * num) + 252; } 
		if (mod == 7){ result = (num1 * num * num * num) + (num1 * num * num) + 254; } 
	} 
	else if (div == 3){ 
		if (mod == 0){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num); } 
		if (mod == 1){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + 128; } 
		if (mod == 2){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + 192; } 
		if (mod == 3){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + 224; } 
		if (mod == 4){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + 240; } 
		if (mod == 5){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + 248; } 
		if (mod == 6){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + 252; } 
		if (mod == 7){ result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + 254; }		 
	} 
	else{ // div = 4 
		result = (num1 * num * num * num) + (num1 * num * num) + (num1 * num) + num1; 
	}	
	
	return result;
}

char *strsep(char **s, const char *ct){
	
	// source: http://elixir.free-electrons.com/linux/latest/source/lib/string.c#L589
	char *sbegin = *s;
	char *end;

	if (sbegin == NULL)
		return NULL;

	end = strpbrk(sbegin, ct);
	if (end)
		*end++ = '\0';
	*s = end;
	return sbegin;
}

int is_all_digits(char *temp){
	
	int i;
    for(i=0; i<strlen(temp); i++){
        if(!isdigit(*(temp+i))){
            return 0;
        }
    }
    return 1;
}

// insert hardcoded_ruls:
/*
void insert_hardcoded_ruls(){

	int a;
	 
	a = 0;	
	strcpy(rule_table[a].rule_name, "Default");
	rule_table[a].direction = DIRECTION_IN;
	rule_table[a].src_ip = 3112110634u;
	rule_table[a].src_prefix_mask = 3112108032u;
	rule_table[a].src_prefix_size = 32;
	rule_table[a].dst_ip = 3112110634u;
	rule_table[a].dst_prefix_mask = 3112108032u;
	rule_table[a].dst_prefix_size = 32;	
	rule_table[a].src_port = 1025; 
	rule_table[a].dst_port = 80; 
	rule_table[a].protocol = PROT_ANY;
	rule_table[a].ack = ACK_YES;
	rule_table[a].action = NF_ACCEPT;
	rule_table[a].is_valid = 1;

	a = 1;
	strcpy(rule_table[a].rule_name, "test");
	rule_table[a].direction = DIRECTION_ANY;
	rule_table[a].src_ip = 3112110622u;
	rule_table[a].src_prefix_mask = 3112100021u;
	rule_table[a].src_prefix_size = 32;
	rule_table[a].dst_ip = 3112110622u;
	rule_table[a].dst_prefix_mask = 3112100021u;
	rule_table[a].dst_prefix_size = 32;	
	rule_table[a].src_port = 80; 
	rule_table[a].dst_port = 80; 
	rule_table[a].protocol = PROT_TCP;
	rule_table[a].ack = ACK_NO;
	rule_table[a].action = NF_DROP;
	rule_table[a].is_valid = 1;
}
*/
	
