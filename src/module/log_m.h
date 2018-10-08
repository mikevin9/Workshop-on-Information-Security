#ifndef _LOG_H_
#define _LOG_H_


//sysfs device - first attribute implementation
ssize_t return_log_size(struct device *dev, struct device_attribute *attr, char *buf);

//sysfs device - second attribute implementation
ssize_t display_log(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t clear_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

int fw_log_device_create(struct class *sysfs_class);

void fw_log_device_clean(struct class *sysfs_class);

void write_firewall_event_to_log(unsigned char protocol, unsigned int action, int hooknum, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, reason_t reason);

#endif
