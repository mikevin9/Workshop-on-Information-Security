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
#include "log_m.h"

#define PRINT_CONDITION if(0)
//#define PRINT_CONDITION if(src_port != 8008 && dst_port != 8008 && src_port != 8088 && dst_port != 8088 && src_port != 21 && dst_port != 21)


MODULE_LICENSE("GPL");

static int major_number;
//static struct class *sysfs_class = NULL;
static struct device *sysfs_device = NULL;
static LIST_HEAD(list_of_connections); // struct list_head name = LIST_HEAD_INIT(name)
static __be32 ip_from_proxy;
static __be16 port_from_proxy;


void clear_connections_table(void);
void add_to_connections_table(unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, int rule_num);
char *strsep1(char **s, const char *ct);

static struct file_operations fops = {
	.owner = THIS_MODULE,
};

//sysfs device - first attribute implementation
ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf){ //sysfs display implementation
	
	conn_t *temp1_conn_list, *temp2_conn_list;
	struct timespec my_time; 	
	char temp[FRAME_SIZE]; 
	char* buf_copy;
	int count;
	
	temp[0] = '\0';
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		return -1;
		kfree(buf_copy);
	}
	
	getnstimeofday(&my_time);

	list_for_each_entry_safe(temp1_conn_list, temp2_conn_list, &list_of_connections, connection) {

		// check if current entry hasn't timed-out
		if(temp1_conn_list->timestamp + TIMEOUT < my_time.tv_sec){
			list_del(&(temp1_conn_list->connection));
			kfree(temp1_conn_list);
			continue;
		}
			
		// src ip
		sprintf(temp, "%u", temp1_conn_list->src_ip);
		strcat(buf_copy, temp);
		strcat(buf_copy, " ");
		temp[0] = '\0';

		// src port
		sprintf(temp, "%hu", temp1_conn_list->src_port);
		strcat(buf_copy, temp);
		strcat(buf_copy, " ");
		temp[0] = '\0';

		// dst ip
		sprintf(temp, "%u", temp1_conn_list->dst_ip);
		strcat(buf_copy, temp);
		strcat(buf_copy, " ");
		temp[0] = '\0';
			
		// dst port
		sprintf(temp, "%hu", temp1_conn_list->dst_port);
		strcat(buf_copy, temp);
		strcat(buf_copy, " ");
		temp[0] = '\0';
		
		// state
		sprintf(temp, "%d", temp1_conn_list->state);
		strcat(buf_copy, temp);
		strcat(buf_copy, " ");
		temp[0] = '\0';

		// time
		sprintf(temp, "%lu", temp1_conn_list->timestamp);
		strcat(buf_copy, temp);
		strcat(buf_copy, " ");
		temp[0] = '\0';
		
		// rule name
		sprintf(temp, "%d", temp1_conn_list->rule_num);
		strcat(buf_copy, temp);
		strcat(buf_copy, " ");
		temp[0] = '\0';
		//strcat(buf_copy, "\n");
	}
	
	buf[0] = '\0';
	count = scnprintf(buf, PAGE_SIZE, "%s", buf_copy); 
	kfree(buf_copy);
	return count;
}

ssize_t close_connection(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){ //sysfs modify implementation
	
	int size;
	char *buf_copy, *temp;
	conn_t *temp1_conn_list;
	__be32 ip;
	__be16 port;
	unsigned long temp_num;
	
	//buf_copy = kmalloc(PAGE_SIZE, GFP_KERNEL);
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		return -1;
		kfree(buf_copy);
	}
	
	if (count < PAGE_SIZE-1){
		size = count;
	}
	else{
		size = PAGE_SIZE-1;
	}

	snprintf(buf_copy, PAGE_SIZE, "%.*s", size, buf);
	temp = strsep(&buf_copy, " ");
	kstrtoul(temp, 10, &temp_num);
	ip = (__be32)temp_num;

	temp = strsep(&buf_copy, " ");
	kstrtoul(temp, 10, &temp_num);
	port = (__be16)temp_num; 

	kfree(buf_copy);	
	
	list_for_each_entry(temp1_conn_list, &list_of_connections, connection) {
		if (temp1_conn_list->src_ip == ip && temp1_conn_list->src_port == port){
			temp1_conn_list->state = CONNECTION_CLOSED;
			write_firewall_event_to_log('6', NF_DROP, NF_INET_PRE_ROUTING, ip, temp1_conn_list->dst_ip, port, temp1_conn_list->dst_port, REASON_ILLEGAL_VALUE);

		}
		if (temp1_conn_list->dst_ip == ip && temp1_conn_list->dst_port == port){
			temp1_conn_list->state = CONNECTION_CLOSED;
		}
		
		if (port == 20 && temp1_conn_list->src_ip == ip && temp1_conn_list->src_port == 21){
			temp1_conn_list->state = CONNECTION_CLOSED;
			write_firewall_event_to_log('6', NF_DROP, NF_INET_PRE_ROUTING, ip, temp1_conn_list->dst_ip, port, temp1_conn_list->dst_port, REASON_ILLEGAL_VALUE);

		}
		if (port == 20 && temp1_conn_list->dst_ip == ip && temp1_conn_list->dst_port == 21){
			temp1_conn_list->state = CONNECTION_CLOSED;
		}
	}
	return count;
}

//sysfs device - second attribute implementation
ssize_t send_conn_data_to_proxy(struct device *dev, struct device_attribute *attr, char *buf){ //sysfs display implementation
	
	conn_t *temp1_conn_list;
	char temp[FRAME_SIZE]; 
	char* buf_copy;
	int count;
	
	temp[0] = '\0';
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		return -1;
		kfree(buf_copy);
	}
		
	list_for_each_entry(temp1_conn_list, &list_of_connections, connection) {
		if (temp1_conn_list->src_ip == ip_from_proxy && temp1_conn_list->src_port == port_from_proxy && temp1_conn_list->state != CONNECTION_CLOSED){
			sprintf(temp, "%d", temp1_conn_list->dst_ip);
			strcat(buf_copy, temp);
			strcat(buf_copy, " ");
			temp[0] = '\0';
			sprintf(temp, "%d", temp1_conn_list->dst_port);
			strcat(buf_copy, temp);
			break;
		}
	}
	
	buf[0] = '\0';
	count = scnprintf(buf, PAGE_SIZE, "%s", buf_copy); 
	kfree(buf_copy);
	return count;
}

ssize_t recive_conn_data_from_proxy(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){ //sysfs modify implementation

	int rule_num = 0, size = 0;
	char *buf_copy, *temp;
	unsigned long temp_num;
	unsigned int src_ip, dst_ip, src_port, dst_port;
	conn_t *temp1_conn_list;

	//buf_copy = kmalloc(PAGE_SIZE, GFP_KERNEL);
	buf_copy = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (buf_copy == NULL){
		kfree(buf_copy);
		return -1;
	}
	
	if (count < PAGE_SIZE-1){
		size = count;
	}
	else{
		size = PAGE_SIZE-1;
	}
	snprintf(buf_copy, PAGE_SIZE, "%.*s", size, buf);
	temp = strsep(&buf_copy, " ");
	if (strcmp(temp, "B") == 0){

		temp = strsep(&buf_copy, " ");
		kstrtoul(temp, 10, &temp_num);
		src_ip = (unsigned int)temp_num;
		
		temp = strsep(&buf_copy, " ");
		kstrtoul(temp, 10, &temp_num);
		src_port = (unsigned int)temp_num;
		
		temp = strsep(&buf_copy, " ");
		kstrtoul(temp, 10, &temp_num);
		dst_ip = (unsigned int)temp_num;
		
		temp = strsep(&buf_copy, " ");
		kstrtoul(temp, 10, &temp_num);
		dst_port = (unsigned int)temp_num;
		
		list_for_each_entry(temp1_conn_list, &list_of_connections, connection) {
			if(temp1_conn_list->src_ip == src_ip && temp1_conn_list->src_port == 21){
				rule_num = temp1_conn_list->rule_num;
			}
		}
		
		PRINT_CONDITION
		printk(KERN_INFO "add to conn tlb - src_ip: %d, dst_ip: %d, src_port: %d, dst_port: %d, rule_num: %d\n", src_ip, dst_ip, src_port, dst_port, rule_num);
		add_to_connections_table(src_ip, dst_ip, src_port, dst_port, rule_num);
		add_to_connections_table(dst_ip, src_ip, dst_port, src_port, rule_num);
	}
	else {
		temp = strsep(&buf_copy, " ");
		kstrtoul(temp, 10, &temp_num);
		ip_from_proxy = (__be32)temp_num;

		temp = strsep(&buf_copy, " ");
		kstrtoul(temp, 10, &temp_num);
		port_from_proxy = (__be16)temp_num; 
	}

	kfree(buf_copy);
	return count;
}

static DEVICE_ATTR(conns, S_IRWXO , display_conns, close_connection);
static DEVICE_ATTR(proxy, S_IRWXO , send_conn_data_to_proxy, recive_conn_data_from_proxy);


int fw_conn_device_create(struct class *sysfs_class){
		
	//create char device
	major_number = register_chrdev(0, "fw_conns", &fops);
	if (major_number < 0){
		return -1;
	}

	/*	
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class)){
		unregister_chrdev(major_number, "fw_conns");
		return -1;
	}
	*/
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_CONNS), NULL, "fw" "_" "fw_conn_tab");	
	if (IS_ERR(sysfs_device)){
		//class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_conns");
		return -1;
	}
	
	//create 1'st sysfs file attribute
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_conns.attr)){
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		//class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_conns");
		return -1;
	}
	
	//create 2'ed sysfs file attribute
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_proxy.attr)){
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
		//class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_conns");
		return -1;
	}

	printk(KERN_INFO "connections module initiated successfully\n");	
	return 0;
}

void fw_conn_device_clean(struct class *sysfs_class){
		
	clear_connections_table();
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_proxy.attr);
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
	//class_destroy(sysfs_class);
	unregister_chrdev(major_number, "fw_conns");
	printk(KERN_INFO "connections module cleaned\n");
}

void check_packet_with_connections_table(unsigned int *is_existing_connection, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, unsigned short syn, unsigned short ack, unsigned short fin, unsigned short rst){
	
	struct timespec my_time;
	int known_connection = 0; 
	conn_t *temp1_conn_list, *temp2_conn_list;
	
	PRINT_CONDITION
	printk(KERN_INFO "check_pkt_with_conn - src: %d, dst: %d, protocol: 6 sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d\n", src_ip, dst_ip, src_port, dst_port, syn, ack, fin);
		
	getnstimeofday(&my_time);
	list_for_each_entry_safe(temp1_conn_list, temp2_conn_list, &list_of_connections, connection) {
		
		
		// check if current entry hasn't timed-out or this connection was terminated
		if(temp1_conn_list->timestamp + TIMEOUT < my_time.tv_sec || temp1_conn_list->state == CONNECTION_CLOSED){
			list_del(&(temp1_conn_list->connection));
			kfree(temp1_conn_list);
			continue;
		}
		
		if(temp1_conn_list->src_ip == src_ip && temp1_conn_list->dst_ip == dst_ip\
		 && temp1_conn_list->src_port == src_port && temp1_conn_list->dst_port == dst_port){
			
			// check if it's a RST
			if(rst == 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = CONNECTION_CLOSED;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "1 - new state is: CONNECTION_CLOSED\n");
			}			
			
			// check if it's a ftp-data SYN
			if(temp1_conn_list->state == EXPECTED_FTP_DATA_CONN && syn == 1 && fin != 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = SYN_SENT;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - 0 - new state is: SYN_SENT\n");
			}
			
			// check if it's a SYN-ACK
			else if (temp1_conn_list->state == SYN_SENT && syn == 1 && fin != 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = SYN_ACK_RECIVED;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - 1 - new state is: SYN_ACK_RECIVED\n");
			}
			// check if it's an ACK to a SYN-ACK
			else if (temp1_conn_list->state == SYN_ACK_RECIVED && syn != 1 && fin != 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = CONNECTION_ESTABLISHED;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - 2 - new state is: CONNECTION_ESTABLISHED\n");
			}
			// check if it's a FIN
			else if(temp1_conn_list->state == CONNECTION_ESTABLISHED && syn != 1 && fin == 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = FIN_ACK_WAIT;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - 3 - new state is: FIN_ACK_WAIT\n");
			}
			// check if it's a FIN (2) to a FIN (1)
			else if((temp1_conn_list->state == FIN_ACK_WAIT || temp1_conn_list->state == FIN_ACK_WAIT_2) && syn != 1 && fin == 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = FIN_ACK_RECIVED;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - 4 - new state is: FIN_ACK_RECIVED\n");
			}
			// check if it's an ACK to a FIN (1)
			else if(temp1_conn_list->state == FIN_ACK_WAIT && syn != 1 && fin != 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = FIN_ACK_WAIT_2;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - 4.1 - new state is: FIN_ACK_WAIT_2\n");
			}

			// check if it's an ACK to a FIN (2)
			else if(temp1_conn_list->state == FIN_ACK_RECIVED && syn != 1 && fin != 1){
				temp1_conn_list->timestamp = my_time.tv_sec;
				temp1_conn_list->state = CONNECTION_CLOSED;
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				known_connection = 1;
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - 5 - new state is: CONNECTION_CLOSED\n");
			}
			// check if it's part of an open connection
			else if(temp1_conn_list->state == CONNECTION_ESTABLISHED && syn != 1 && fin != 1){
				PRINT_CONDITION
				printk(KERN_INFO "check_pkt_with_conn - known1 - src: %d, dst: %d, protocol: 6 sPort: %d, dPort:%d, SYN=%d, ACK=1, FIN=%d\n", src_ip, dst_ip, src_port, dst_port, syn, fin);
				temp1_conn_list->timestamp = my_time.tv_sec;
				// no need to update state
				is_existing_connection[0] = NF_ACCEPT;
				is_existing_connection[1] = temp1_conn_list->rule_num;
				is_existing_connection[2] = 1;
				known_connection = 1;
			}
		}
	}
	
	if(!known_connection){
		PRINT_CONDITION
		printk(KERN_INFO "check_pkt_with_conn - unknown - src: %d, dst: %d, protocol: 6 sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d\n", src_ip, dst_ip, src_port, dst_port, syn, ack, fin);
		is_existing_connection[0] = NF_DROP;
		is_existing_connection[1] = REASON_ILLEGAL_STATE;
	}
}

void add_to_connections_table(unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, int rule_num){

	struct timespec my_time; 
	conn_t *new_connection;

	
	getnstimeofday(&my_time);
	//new_connection = kmalloc(sizeof(*new_connection), GFP_KERNEL);
	new_connection = kmalloc(sizeof(*new_connection), GFP_ATOMIC);
	//if(new_connection == NULL){
		//return -ENOMEM; // == -12 (Out of memory) 
	//}
	new_connection->src_ip = src_ip;
	new_connection->dst_ip = dst_ip;
	new_connection->src_port = src_port;
	new_connection->dst_port = dst_port;
	new_connection->state = SYN_SENT;
	if(src_port == 20 || dst_port == 20){
		new_connection->state = EXPECTED_FTP_DATA_CONN;
	}
	new_connection->timestamp = my_time.tv_sec;
	new_connection->rule_num = rule_num;
	
	//INIT_LIST_HEAD(&(new_connection->connection));
	list_add_tail(&(new_connection->connection), &list_of_connections);
	
}

__be32 get_real_ip(__be32 ip, __be16 port, int get_src, int get_dst){
	
	conn_t *temp1_conn_list;
	
	list_for_each_entry(temp1_conn_list, &list_of_connections, connection) {
		if (get_src == 1){
			if (temp1_conn_list->dst_ip == ip && temp1_conn_list->dst_port == port && temp1_conn_list->state != CONNECTION_CLOSED){
				return temp1_conn_list->src_ip;
			}
		}
		if (get_dst == 1){
			if (temp1_conn_list->src_ip == ip && temp1_conn_list->src_port == port && temp1_conn_list->state != CONNECTION_CLOSED){
				return temp1_conn_list->dst_ip;
			}
		}
	}
	return 0;
}

__be16 get_real_port(__be32 ip, __be16 port, int get_src, int get_dst){
	
	conn_t *temp1_conn_list;
	
	list_for_each_entry(temp1_conn_list, &list_of_connections, connection) {
		if (get_src == 1){
			if (temp1_conn_list->dst_ip == ip && temp1_conn_list->dst_port == port && temp1_conn_list->state != CONNECTION_CLOSED){
				return temp1_conn_list->src_port;
			}
		}
		if (get_dst == 1){
			if (temp1_conn_list->src_ip == ip && temp1_conn_list->src_port == port && temp1_conn_list->state != CONNECTION_CLOSED){
				return temp1_conn_list->dst_port;
			}
		}
	}
	return 0;
}

__be16 get_fake_port(__be32 ip, __be16 port){
	
	conn_t *temp1_conn_list;
	
	list_for_each_entry(temp1_conn_list, &list_of_connections, connection) {
		if (temp1_conn_list->src_ip == ip && temp1_conn_list->src_port == port && temp1_conn_list->state != CONNECTION_CLOSED){
			return temp1_conn_list->fake_port;
		}
	}
	return 0;
}

void update_fake_port(__be32 ip, __be16 port, __be16 fake_port){
	
	conn_t *temp1_conn_list;

	list_for_each_entry(temp1_conn_list, &list_of_connections, connection) {
		if (temp1_conn_list->src_ip == ip && temp1_conn_list->src_port == port && temp1_conn_list->state != CONNECTION_CLOSED){
			temp1_conn_list->fake_port = fake_port;
		}
	}
}


void clear_connections_table(void){
	
	conn_t *temp1_conn_list, *temp2_conn_list;
	list_for_each_entry_safe(temp1_conn_list, temp2_conn_list, &list_of_connections, connection) {
		list_del(&(temp1_conn_list->connection));
		kfree(temp1_conn_list);
	}
}

char *strsep1(char **s, const char *ct){
	
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

