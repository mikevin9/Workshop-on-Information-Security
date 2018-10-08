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
#include <net/tcp.h>


#include "fw.h"
#include "rules_m.h"
#include "log_m.h"
#include "conn_m.h"
// 167837953u = 10.1.1.1; 167838210u = 10.1.2.2; 
// 167837955u = 10.1.1.3; 167838211u = 10.1.2.3;
#define MY_GATEWAY 167837955u;
#define SMTP_PROXY_PORT 8006;
#define HTTP_PROXY_PORT 8007;
#define FTP21_PROXY_PORT_IN = 8008
#define FTP20_PROXY_PORT_IN = 8009

#define PRINT_CONDITION if(0)
//#define PRINT_CONDITION if(src_port != 8008 && dst_port != 8008 && src_port != 8088 && dst_port != 8088 && src_port != 21 && dst_port != 21)



MODULE_LICENSE("GPL");

static struct nf_hook_ops prerouting_hook_struct;
static struct nf_hook_ops output_hook_struct;

/*
static struct nf_hook_ops input_hook_struct, nf_hook_ops postrouting_hook_struct;

unsigned int input_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	prot_t protocol;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port;
	
	if (!skb){
		return NF_DROP;
	}	
	//ip_header = (struct iphdr*)skb_network_header(skb);
	if (skb_linearize(skb) != 0) {
		return NF_DROP;
	}
	ip_header = ip_hdr(skb);
	if (!ip_header){
		return NF_DROP;
	}
	src_ip = ntohl(ip_header->saddr); 
	dst_ip = ntohl(ip_header->daddr);
	protocol = ip_header->protocol;
	if (protocol != 6){
		return NF_ACCEPT;
	}
	
	tcp_header = (struct tcphdr*)(skb->data + ip_header->ihl * 4);
	src_port = ntohs(tcp_header->source);
	dst_port = ntohs(tcp_header->dest);
	
	//printk(KERN_INFO "in input func - src: %d, dst: %d, protocol: %d sPort: %d, dPort:%d, SYN=%d, ACK=%d\n", src_ip, dst_ip, protocol, src_port, dst_port, tcp_header->syn, tcp_header->ack);	
	return NF_ACCEPT;
}

unsigned int post_routing_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	prot_t protocol;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port;
	
	if (!skb){
		return NF_DROP;
	}	
	//ip_header = (struct iphdr*)skb_network_header(skb);
	if (skb_linearize(skb) != 0) {
		return NF_DROP;
	}
	ip_header = ip_hdr(skb);
	if (!ip_header){
		return NF_DROP;
	}
	src_ip = ntohl(ip_header->saddr); 
	dst_ip = ntohl(ip_header->daddr);
	protocol = ip_header->protocol;
	if (protocol != 6){
		return NF_ACCEPT;
	}
	
	tcp_header = (struct tcphdr*)(skb->data + ip_header->ihl * 4);
	src_port = ntohs(tcp_header->source);
	dst_port = ntohs(tcp_header->dest);
	
	//printk(KERN_INFO "in POSTrouting func - src: %d, dst: %d, protocol: %d sPort: %d, dPort:%d, SYN=%d, ACK=%d\n", src_ip, dst_ip, protocol, src_port, dst_port, tcp_header->syn, tcp_header->ack);	
	return NF_ACCEPT;
}
*/


unsigned int pre_routing_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	direction_t direction;
	prot_t protocol;
	__be32 src_ip, dst_ip;
	__be16 src_port = 0, dst_port = 0;
	int tcplen, is_valid, is_fake = 0;
	unsigned int is_existing_connection[3] = {0,0,0};
	
	
	if (!skb){
		return NF_DROP;
	}	
	//ip_header = (struct iphdr*)skb_network_header(skb);
	if (skb_linearize(skb) != 0){
		return NF_DROP;
	}
	ip_header = ip_hdr(skb);
	if (!ip_header){
		return NF_DROP;
	}
	src_ip = ntohl(ip_header->saddr); 
	dst_ip = ntohl(ip_header->daddr);
	protocol = ip_header->protocol;

	// identify the direction of the packet
	if ((src_ip & IN_NETWORK_MASK) == IN_NETWORK){
		direction = DIRECTION_IN;
	}
	else if ((dst_ip & IN_NETWORK_MASK) == IN_NETWORK){
		direction = DIRECTION_OUT;
	}
	else {
		direction = DIRECTION_ANY;
	}

	// enable localhost
	if (src_ip == 2130706433u && dst_ip == 2130706433u){ // 2130706433u == 127.0.0.1
		return NF_ACCEPT;
	}

	// check if firewall is on:
	if ((kernel_check_is_on()) != 1){
		write_firewall_event_to_log(protocol, NF_DROP, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_FW_INACTIVE);
		return NF_DROP;
	}

	// if protocol isn't TCP -> decide according to rule table
	if (protocol != PROT_TCP){ 
		return check_packet_with_rules_table(hooknum, src_ip, dst_ip, 0, 0, protocol, direction, NULL);
	}
	
	// protocol is TCP
	tcp_header = (struct tcphdr*)(skb->data + ip_header->ihl * 4);
	//tcp_header = (struct tcphdr*)(skb_transport_header(skb)+20); //for incoming packets use +20
	if (!tcp_header){
		return NF_DROP;
	}
	src_port = ntohs(tcp_header->source);
	dst_port = ntohs(tcp_header->dest);
	
	
	PRINT_CONDITION
	printk(KERN_INFO "in PRErouting - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	
	// if it's a TCP SYN packet (ACK=0), not from a ftp-data server - check with rule table	
	if (tcp_header->syn == 1 && tcp_header->ack == 0 && src_port != 20){
		is_valid = check_packet_with_rules_table(hooknum, src_ip, dst_ip, src_port, dst_port, protocol, direction, tcp_header);
		if (is_valid == 0) {
			PRINT_CONDITION
			printk(KERN_INFO "in PRErouting - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");				
			return NF_DROP;
		}
	}
	
	// it's a TCP packet with ACK=1 or a ftp-data server with SYN=1 - check with connections table
	else {
		check_packet_with_connections_table(is_existing_connection, src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
		write_firewall_event_to_log(protocol, is_existing_connection[0], hooknum, src_ip, dst_ip, src_port, dst_port, is_existing_connection[1]);
		if (is_existing_connection[2] != 1 && is_existing_connection[0] != NF_ACCEPT){	
			//return is_existing_connection[0];
			PRINT_CONDITION
			printk(KERN_INFO "in PRErouting - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");				
			return NF_DROP;
		}
	}
	
	PRINT_CONDITION
	printk(KERN_INFO "in PRErouting - decision: %d, established: %d\n", is_existing_connection[0], is_existing_connection[2]);
	
	if (tcp_header->source == htons(80)){	
		//changing of routing
		dst_ip = 167838211u; // 167838211u = 10.1.2.3
		dst_port = get_fake_port(src_ip, src_port);
		is_fake = 1;
		
		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake1 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);				
	}		

	else if (tcp_header->dest == htons(80)){	
		//changing of routing
		dst_ip = 167837955u;  // 167837955u = 10.1.1.3
		dst_port = 8007;
		is_fake = 1;

		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake2 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}

	else if (tcp_header->source == htons(21)){	
		//changing of routing
		dst_ip = 167838211u; // 167838211u = 10.1.2.3
		dst_port = get_fake_port(src_ip, src_port);
		is_fake = 1;

		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake3 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}		

	else if (tcp_header->dest == htons(21)){	
		//changing of routing
		dst_ip = 167837955u;  // 167837955u = 10.1.1.3
		dst_port = 8008; // FTP21_PROXY_PORT_IN
		is_fake = 1;

		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake4 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
	
	else if (tcp_header->source == htons(20)){	
		//changing of routing
		dst_ip = 167838211u; // 167838211u = 10.1.2.3
		dst_port = 8009; // FTP20_PROXY_PORT_IN
		is_fake = 1;

		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake5 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
	
	else if (tcp_header->dest == htons(20)){	
		//changing of routing
		dst_ip = 167837955u;  // 167837955u = 10.1.1.3
		dst_port = get_fake_port(src_ip, src_port);
		is_fake = 1;
				
		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake6 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
	
	else if (tcp_header->source == htons(25)){	
		//changing of routing
		dst_ip = 167838211u; // 167838211u = 10.1.2.3
		dst_port = get_fake_port(src_ip, src_port);
		is_fake = 1;

		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake7 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);				
	}		

	else if (tcp_header->dest == htons(25)){	
		//changing of routing
		dst_ip = 167837955u;  // 167837955u = 10.1.1.3
		dst_port = 8006;
		is_fake = 1;

		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - after fake8 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
	
	if (is_fake){
		ip_header->daddr = htonl(dst_ip); //change to my machine IP
		tcp_header->dest = htons(dst_port); //change to my proxy http server listening port
		//here start the fix of checksum for both IP and TCP
		tcplen = (skb->len - ((ip_header->ihl)<< 2));
		tcp_header->check = 0;
		tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
		skb->ip_summed = CHECKSUM_NONE; //stop offloading
		ip_header->check = 0;
		ip_header->check = ip_fast_csum((u8*)ip_header, ip_header->ihl);

		PRINT_CONDITION
		printk(KERN_INFO "in PRErouting - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");				
		return NF_ACCEPT;
	}
	
	//return is_existing_connection[0];
	PRINT_CONDITION
	printk(KERN_INFO "in PRErouting - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");				
	return NF_DROP;
}

unsigned int output_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	direction_t direction;
	prot_t protocol;
	__be32 src_ip, dst_ip;
	__be16 src_port = 0, dst_port = 0;
	int tcplen, is_valid, is_faked = 0, temp_fake_port = 0;
	unsigned int is_existing_connection[3] = {0,0,0};
		
	
	if (!skb){
		return NF_DROP;
	}	
	//ip_header = (struct iphdr*)skb_network_header(skb);
	if (skb_linearize(skb) != 0){
		return NF_DROP;
	}
	ip_header = ip_hdr(skb);
	if (!ip_header){
		return NF_DROP;
	}
	src_ip = ntohl(ip_header->saddr); 
	dst_ip = ntohl(ip_header->daddr);
	protocol = ip_header->protocol;

	// identify the direction of the packet
	if ((src_ip & IN_NETWORK_MASK) == IN_NETWORK){
		direction = DIRECTION_IN;
	}
	else if ((dst_ip & IN_NETWORK_MASK) == IN_NETWORK){
		direction = DIRECTION_OUT;
	}
	else {
		direction = DIRECTION_ANY;
	}
		
	// enable localhost
	if (src_ip == 2130706433u && dst_ip == 2130706433u){ // 2130706433u == 127.0.0.1
		return NF_ACCEPT;
	}

	// check if firewall is on:
	if ((kernel_check_is_on()) != 1){
		write_firewall_event_to_log(protocol, NF_DROP, hooknum, src_ip, dst_ip, src_port, dst_port, REASON_FW_INACTIVE);
		return NF_DROP;
	}

	// if protocol isn't TCP -> decide according to rule table
	if (protocol != PROT_TCP){ 
		return check_packet_with_rules_table(hooknum, src_ip, dst_ip, 0, 0, protocol, direction, NULL);
	}
	
	// protocol is TCP
	tcp_header = (struct tcphdr*)(skb->data + ip_header->ihl * 4);
	//tcp_header = (struct tcphdr*)(skb_transport_header(skb));
	if (!tcp_header){
		return NF_DROP;
	}
	src_port = ntohs(tcp_header->source);
	dst_port = ntohs(tcp_header->dest);
	
	PRINT_CONDITION
	printk(KERN_INFO "in output - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);	
	
	if (tcp_header->source == htons(8007)){	// HTTP_PROXY_PORT_IN
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 0, 1);
		src_port = get_real_port(dst_ip, dst_port, 0, 1);
		is_faked = 1;
				
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake1 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
		
	else if (tcp_header->dest == htons(80)){	
		temp_fake_port = src_port;
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 1, 0);
		src_port = get_real_port(dst_ip, dst_port, 1, 0);
		is_faked = 1;
			
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake2 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
	
	else if (tcp_header->source == htons(8008)){ // FTP21_PROXY_PORT_IN
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 0, 1);
		src_port = get_real_port(dst_ip, dst_port, 0, 1);
		is_faked = 1;
				
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake3 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
		
	else if (tcp_header->dest == htons(21)){
		temp_fake_port = src_port;
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 1, 0);
		src_port = get_real_port(dst_ip, dst_port, 1, 0);
		is_faked = 1;
			
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake4 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}

	else if (tcp_header->source == htons(8009)){ // FTP20_PROXY_PORT_IN	
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 0, 1);
		src_port = get_real_port(dst_ip, dst_port, 0, 1);
		is_faked = 1;
		
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake5 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
	
	else if (tcp_header->source == htons(8006)){ // SMTP_PROXY_PORT_IN
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 0, 1);
		src_port = get_real_port(dst_ip, dst_port, 0, 1);
		is_faked = 1;
				
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake6 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
		
	else if (tcp_header->dest == htons(25)){	
		temp_fake_port = src_port;
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 1, 0);
		src_port = get_real_port(dst_ip, dst_port, 1, 0);
		is_faked = 1;
			
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake7 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
		
	else { // FTP20_PROXY_PORT_OUT
		update_fake_port(dst_ip, dst_port, src_port);
		//changing of routing
		src_ip = get_real_ip(dst_ip, dst_port, 1, 0);
		src_port = get_real_port(dst_ip, dst_port, 1, 0);
		is_faked = 1;
					
		PRINT_CONDITION
		printk(KERN_INFO "in output - after fake8 - src: %d, dst: %d, sPort: %d, dPort:%d, SYN=%d, ACK=%d, FIN=%d, RST=%d\n", src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
	}
	
	if (is_faked){
		ip_header->saddr = htonl(src_ip); //change to real IP
		tcp_header->source = htons(src_port); //change to real port
		//here start the fix of checksum for both IP and TCP
		tcplen = (skb->len - ((ip_header->ihl)<< 2));
		tcp_header->check = 0;
		tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
		skb->ip_summed = CHECKSUM_NONE; //stop offloading
		ip_header->check = 0;
		ip_header->check = ip_fast_csum((u8*)ip_header, ip_header->ihl);
	}
	
	// if it's a TCP SYN packet (ACK=0), not from a ftp-data server - check with rule table	
	if (tcp_header->syn == 1 && tcp_header->ack == 0 && src_port != 20){
		is_valid = check_packet_with_rules_table(hooknum, src_ip, dst_ip, src_port, dst_port, protocol, direction, tcp_header);
		if (is_valid == 0) {
			PRINT_CONDITION
			printk(KERN_INFO "in output - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");
			return NF_DROP;
		}
		update_fake_port(dst_ip, dst_port, temp_fake_port);
		
		PRINT_CONDITION
		printk(KERN_INFO "in output - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");
		return NF_ACCEPT; 
	}

	// it's a TCP packet with ACK=1 or a ftp-data server with SYN=1 - check with connections table
	else{
		if(tcp_header->source == htons(80) || tcp_header->source == htons(21) || tcp_header->dest == htons(20) || tcp_header->source == htons(20) || tcp_header->source == htons(25)){ // switch original directions
			//printk(KERN_INFO "in output func - dst 80/21/20/25 OR src 20");
			check_packet_with_connections_table(is_existing_connection, dst_ip, src_ip, dst_port, src_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
			write_firewall_event_to_log(protocol, is_existing_connection[0], hooknum, dst_ip, src_ip, dst_port, src_port, is_existing_connection[1]);
		}
		else {
			//printk(KERN_INFO "in output func - dst NOT 80/21/20/25 AND src NOT 20");
			check_packet_with_connections_table(is_existing_connection, src_ip, dst_ip, src_port, dst_port, tcp_header->syn, tcp_header->ack, tcp_header->fin, tcp_header->rst);
			write_firewall_event_to_log(protocol, is_existing_connection[0], hooknum, src_ip, dst_ip, src_port, dst_port, is_existing_connection[1]);
		}
		PRINT_CONDITION
		printk(KERN_INFO "in output - desicion: %d, established: %d\n", is_existing_connection[0], is_existing_connection[2]);
		if (is_existing_connection[2] != 1 && is_existing_connection[0] != NF_ACCEPT){	
			//return is_existing_connection[0];
			PRINT_CONDITION
			printk(KERN_INFO "in output - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");
			return NF_DROP;
		}
		PRINT_CONDITION
		printk(KERN_INFO "in output - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");
		return NF_ACCEPT;
	}
	
	PRINT_CONDITION
	printk(KERN_INFO "in output - DONEEEEEEEEEEEEEEEEEEEEEEEE\n");
	return NF_DROP;
}

int register_to_hooks(void){
	
	int register_hook_prerouting, register_hook_output;
	//int register_hook_postrouting, register_hook_input;
	
	
	// register to prerouting hook
	prerouting_hook_struct.hook = pre_routing_hook_func;
	prerouting_hook_struct.hooknum = NF_INET_PRE_ROUTING;
	prerouting_hook_struct.pf = PF_INET;
	prerouting_hook_struct.priority = 1;
	register_hook_prerouting = nf_register_hook(&prerouting_hook_struct);	
	if(register_hook_prerouting != 0){
		printk(KERN_INFO "couldn't hook to NF_IP_PRE_ROUTING\n");
		return -1;
	}
	
	// register to output hook
	output_hook_struct.hook = output_hook_func;
	output_hook_struct.hooknum = NF_INET_LOCAL_OUT;
	output_hook_struct.pf = PF_INET;
	output_hook_struct.priority = 2;
	register_hook_output = nf_register_hook(&output_hook_struct);	
	if(register_hook_output != 0){
		printk(KERN_INFO "couldn't hook to NF_INET_LOCAL_OUT\n");
		nf_unregister_hook(&prerouting_hook_struct);
		return -1;
	}
	
	/*
	// register to postrouting hook
	postrouting_hook_struct.hook = post_routing_hook_func;
	postrouting_hook_struct.hooknum = NF_INET_LOCAL_OUT;
	postrouting_hook_struct.pf = PF_INET;
	postrouting_hook_struct.priority = 3;
	register_hook_postrouting = nf_register_hook(&postrouting_hook_struct);	

	// register to input hook
	input_hook_struct.hook = input_hook_func;
	input_hook_struct.hooknum = NF_INET_LOCAL_IN;
	input_hook_struct.pf = PF_INET;
	input_hook_struct.priority = 4;
	register_hook_input = nf_register_hook(&input_hook_struct);	
`	*/

	return 0;
}

void unregister_from_hooks(void){
	
	nf_unregister_hook(&prerouting_hook_struct);
	nf_unregister_hook(&output_hook_struct);
	
	//nf_unregister_hook(&postrouting_hook_struct);
	//nf_unregister_hook(&input_hook_struct);
}


int netfilter_module_init(void){ 
	
	int is_valid;
			
	is_valid = register_to_hooks();
	if(is_valid != 0){
		// no need to print error. already done in register_to_hooks()
		return -1;
	}
	
	printk(KERN_INFO "netfilter module initiated successfully\n");	
	return 0;
} 

void netfilter_module_clean(void){
	
	unregister_from_hooks();
	printk(KERN_INFO "netfilter module cleaned\n");
}

