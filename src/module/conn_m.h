#ifndef _CONN_H_
#define _CONN_H_

//static LIST_HEAD(list_of_connections); // struct list_head name = LIST_HEAD_INIT(name)


ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t return_host_to_proxy(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t recive_conn_data_from_proxy(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


int fw_conn_device_create(struct class *sysfs_class);

void fw_conn_device_clean(struct class *sysfs_class);

void check_packet_with_connections_table(unsigned int *is_existing_connaction, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, unsigned short syn, unsigned short ack, unsigned short fin, unsigned short rst);

void add_to_connections_table(unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, int rule_num);

__be32 get_real_ip(__be32 ip, __be16 port, int get_src, int get_dst);

__be16 get_real_port(__be32 ip, __be16 port, int get_src, int get_dst);

__be16 get_fake_port(__be32 ip, __be16 port);

void update_fake_port(__be32 ip, __be16 port, __be16 fake_port);

void clear_connections_table(void);

#endif
