#ifndef _RULE_H_
#define _RULE_H_


//sysfs device - first attribute implementation
ssize_t check_if_on(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t turn_on_off(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

//sysfs device - second attribute implementation
ssize_t display_num_of_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t clear_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

//sysfs device - third attribute implementation
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


int fw_rules_device_create (struct class *sysfs_class);

void fw_rules_device_clean (struct class *sysfs_class);

unsigned int check_packet_with_rules_table(unsigned int hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, prot_t protocol, direction_t direction, struct tcphdr *tcp_header);
//unsigned int check_packet_with_rules (unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out);

unsigned int kernel_check_is_on (void);

#endif
