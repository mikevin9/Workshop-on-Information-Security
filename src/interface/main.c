#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <limits.h>
#include <fcntl.h> 
#include <time.h> 

#define PAGE_SIZE 4096
#define LINE_LENGTH 90

void print_int_as_ip(char* temp);
void show_log(int fd);
void show_rules(int fd);
int load_rules(int fd, char* path);
void show_conn_table(int fd);


int main(int argc, char *argv[]){
	
	int fd, ret;
	
	if(argc == 1){
		printf("No command was entered\n");
		return -1;
	}
	
	// activate firewall
	if (strcmp(argv[1], "activate") == 0){
		fd = open("/sys/class/fw/fw_fw_rules/active", O_RDWR);
		if(fd < 0){
			printf("Error in openning fw_rules/active - %s\n",strerror(errno));
			close(fd);
			return -1;
		}
		ret = write(fd, "1", strlen("1"));
		if(ret <= 0){
			printf("Problem with writing to module\n");
			close(fd);
			return -1;
		}
	}
	
	// deactivate firewall
	else if (strcmp(argv[1], "deactivate") == 0){
		fd = open("/sys/class/fw/fw_fw_rules/active", O_RDWR);
		if(fd < 0){
			printf("Error in openning fw_rules/active - %s\n",strerror(errno));
			close(fd);
			return -1;
		}
		ret = write(fd, "0", strlen("0"));
		if(ret <= 0){
			printf("Problem with writing to module\n");
			close(fd);
			return -1;
		}
	}
	
	//show firewall rules
	else if (strcmp(argv[1], "show_rules") == 0){
		fd = open("/sys/class/fw/fw_fw_rules/rule_management", O_RDWR);
		if(fd < 0){
		printf("Error in openning fw_rules/rule_management - %s\n",strerror(errno));
			close(fd);
			return -1;
		}
		show_rules(fd);	
	}
	
	// clear firewall rules
	else if (strcmp(argv[1], "clear_rules") == 0){
		fd = open("/sys/class/fw/fw_fw_rules/rules_size", O_RDWR);
		if(fd < 0){
			printf("Error in openning fw_rules/rules_size - %s\n",strerror(errno));
			close(fd);
			return -1;
		}
		ret = write(fd, "c", strlen("c"));
		if(ret <= 0){
			printf("Problem with writing to module\n");
			close(fd);
			return -1;
		}
	}
	
	// load firewall rules
	else if (strcmp(argv[1], "load_rules") == 0){
		if(argv[2] == NULL){
			printf("Missing address to rules file\n");
			return -1;
		}
		fd = open("/sys/class/fw/fw_fw_rules/rule_management", O_RDWR);
		if(fd < 0){
			printf("Error in openning fw_rules/rule_management - %s\n",strerror(errno));
			close(fd);
			return -1;
		}
		int is_valid = load_rules(fd, argv[2]);
		if (is_valid == -1){
			close(fd);
			return -1;
		}
	}
	
	// show firewall connactions table
	else if (strcmp(argv[1], "show_connections_table") == 0){
		//fd = open("/sys/class/fw/fw_fw_conn_tab/show_conn_table", O_RDONLY);
		fd = open("/sys/class/fw/fw_fw_conn_tab/conns", O_RDONLY);
		if(fd < 0){
			printf("Error in openning fw_conn_tab/show_conn_table, %s\n",strerror(errno));
			return -1;
		}
		show_conn_table(fd);
	}
	
	// show firewall log
	else if (strcmp(argv[1], "show_log") == 0){
		fd = open("/sys/class/fw/fw_fw_log/log_clear", O_RDWR);
		if(fd < 0){
			printf("Error in openning fw_rules/log_clear, %s\n",strerror(errno));
			return -1;
		}
		show_log(fd);
	}
	
	// clear firewall log
	else if (strcmp(argv[1], "clear_log") == 0){
		fd = open("/sys/class/fw/fw_fw_log/log_clear", O_RDWR);
		if(fd < 0){
			printf("Error in openning fw_rules/log_clear, %s\n",strerror(errno));
			return -1;
		}
		if(argv[2] != NULL && strlen(argv[2]) > 1){
			printf("Given argument is longer then on char\n");
			close(fd);
			return -1;
		}
		ret = write(fd, "c", strlen("c"));
		if(ret <= 0){
			printf("Problem with writing to module\n");
			close(fd);
			return -1;
		}
	}
	
	else {
		printf("Non recognizable command entered\n");
		return -1;
	}
	
	close(fd);
	return 0;
}

void show_log(int fd){
	
	int ret;
	char log_from_fw[PAGE_SIZE], *temp = NULL;
	struct tm *locale_time;
	time_t timep; 
	log_from_fw[0] = '\0';
	
	ret = read(fd, log_from_fw, PAGE_SIZE);
	if(ret == 0){
		printf("No loges stored\n");
		return;
	}
	//printf("%s\n", log_from_fw);
	printf("timestamp\t\tsrc ip\t\t\tdst ip\t\t\ts_port d_port protocol hooknum action reason count\n");	
	temp = strtok(log_from_fw, " ");
	while (temp != NULL){

		timep = strtol(temp ,NULL , 10);
		locale_time = localtime(&timep);
		printf("%d/%d/%d %d:%d:%d\t", locale_time->tm_mday, (locale_time->tm_mon+1),\
		 (locale_time->tm_year+1900), locale_time->tm_hour, locale_time->tm_min, locale_time->tm_sec);
					
		// src ip
		temp = strtok(NULL, " ");
		print_int_as_ip(temp);
		printf("\t");
		
		// dst ip
		temp = strtok(NULL, " ");
		print_int_as_ip(temp);
		printf("\t");
		
		// src port
		temp = strtok(NULL, " ");
		printf("%s\t", temp);

		// dst port
		temp = strtok(NULL, " ");
		printf("%s\t", temp);
		
		// protocol
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1") == 0){
			printf("ICMP\t");
		}
		else if(strcmp(temp,"6") == 0){
			printf("TCP\t");
		}
		else if(strcmp(temp,"17") == 0){
			printf("UDP\t");
		}
		else if(strcmp(temp,"255") == 0){
			printf("OTHER\t");
		}
		else{ // if(strcmp(temp,"143") == 0)
			printf("ANY\t");
		}

		// hooknum
		temp = strtok(NULL, " ");
		printf("%s\t", temp);
		
		// action
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1") == 0 ){
			printf("ACCEPT\t");
		}
		else{
			printf("DROP\t");
		}
		
		// reason
		temp = strtok(NULL, " ");
		if(strcmp(temp,"-1") == 0){
			printf("FW_INACTIVE\t");
		}
		else if(strcmp(temp,"-2") == 0){
			printf("NO_MATCHING_RULE\t");
		}
		else if(strcmp(temp,"-4") == 0){
			printf("XMAS_PACKET\t");
		}
		else if(strcmp(temp,"-6") == 0){
			printf("ILLEGAL_VALUE\t");
		}
		else if(strcmp(temp,"-8") == 0){
			printf("ILLEGAL_STATE\t");
		}		
		else{
			printf("%s\t", temp);
		}
		
		// count
		temp = strtok(NULL, "\r\n");
		printf("%s\n", temp);
		
		// get next line
		temp = strtok(NULL, " ");
	}
}

void show_rules(int fd){
	
	int ret;
	char rules_from_fw[PAGE_SIZE], *temp = NULL;
	rules_from_fw[0] = '\0';
	
	ret = read(fd, rules_from_fw, PAGE_SIZE);
	if(ret == 0){
		printf("No rules stored\n");
	}
		
	temp = strtok(rules_from_fw, " ");
	while (temp != NULL){

		// rule name
		printf("%s\t", temp);
		
		// direction	
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1")==0){
			printf("DIRECTION_IN\t");
		}
		else if(strcmp(temp,"2")==0){
			printf("DIRECTION_OUT\t");
		}
		else{
			printf("DIRECTION_ANY\t");
		}
		
		// src ip	
		temp = strtok(NULL, "/");
		print_int_as_ip(temp);
		temp = strtok(NULL, " ");
		printf("/%s\t", temp);
		
		// dst ip	
		temp = strtok(NULL, "/");
		print_int_as_ip(temp);
		temp = strtok(NULL, " ");
		printf("/%s\t", temp);
		
		// protocol	
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1") == 0){
			printf("PROT_ICMP\t");
		}
		else if(strcmp(temp,"6") == 0){
			printf("PROT_TCP\t");
		}
		else if(strcmp(temp,"17") == 0){
			printf("PROT_UDP\t");
		}
		else if(strcmp(temp,"255") == 0){
			printf("PROT_OTHER\t");
		}
		else{
			printf("PROT_ANY\t");
		}			
		
		// src port	
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1023") < 0){
			printf("PORT_ANY\t");
		}
		else{
			printf("PORT_ABOVE_1023\t");
		}

		// dst port	
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1023") < 0){
			printf("PORT_ANY\t");
		}
		else{
			printf("PORT_ABOVE_1023\t");
		}
		
		// ack		
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1") == 0){
			printf("ACK_NO\t");
		}
		if(strcmp(temp,"2") == 0){
			printf("ACK_YES\t");
		}
		else{
			printf("ACK_ANY\t");
		}
		
		// decision	
		temp = strtok(NULL, "\r\n");
		if(strcmp(temp,"1") == 0){
			printf("ACCEPT\n");
		}
		else{
			printf("DROP\n");
		}
		
		// get next line
		temp = strtok(NULL, " ");
	}
}

int load_rules(int fd, char* path){
	
	int ret, line_num = 0;
	unsigned int ip_int, ip_int_t;
	FILE * fp;
    char *temp, *temp1, *sub1, *sub2;
    ssize_t read_t = 0, total_read = 0;
    char buf[LINE_LENGTH*50], line[LINE_LENGTH+1], fullPath[100], temp2[11];
    buf[0] = '\0', line[0] = '\0', fullPath[0] = '\0', temp2[0] = '\0';


	strcpy(fullPath, "./");
	fullPath[strlen("./")] = '\0';
	
	strcat(fullPath, path);
	fullPath[strlen(fullPath)] = '\0';
	
    fp = fopen(fullPath, "r");
    if (fp == NULL){
        printf("Couldn't open the file - %s\n", strerror(errno));
        return -1;
	}
	
	while (fgets(line, LINE_LENGTH, fp) != NULL) {
        temp = strtok_r(line, " ", &sub1);
        if(strlen(temp) > 20){
			printf("Problem 1 in line %d of file\n", line_num);
			return -1;
		}
        strcat(buf, temp);
        strcat(buf, " ");
        read_t = sizeof(temp);
        
        // direction
        temp = strtok_r(NULL, " ", &sub1);
        if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}	
		else if(strcmp(temp, "in") == 0){
			strcat(buf, "1");
		}
		else if(strcmp(temp, "out") == 0){
			strcat(buf, "2");
		}
		else if(strcmp(temp, "any") == 0){
			strcat(buf, "3");
		}
		else{
			printf("Problem 2 in line %d of file\n", line_num);
			return -1;
		}
		strcat(buf, " ");
        read_t = read_t + sizeof("0  ");
        
        // src ip
        temp = strtok_r(NULL, " ", &sub1);
		if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}
        else if(strcmp(temp, "any") == 0){
			strcat(buf, "0/0 ");
			read_t = read_t + sizeof("0/0 ");
		}
		else{
			ip_int_t = 0;
			ip_int = 0;
			temp1 = strtok_r(temp, ".", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += (ip_int_t * 256 * 256 * 256);
			temp1 = strtok_r(NULL, ".", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += (ip_int_t * 256 * 256);
			temp1 = strtok_r(NULL, ".", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += (ip_int_t * 256);
			temp1 = strtok_r(NULL, "/", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += ip_int_t;
			sprintf(temp2, "%u", ip_int);
			strcat(buf, temp2);
			read_t = read_t + sizeof(temp2);
			temp2[0] = '\0';
			temp1 = strtok_r(NULL, " ", &sub2);
			if(strlen(temp1)>2){
				printf("Problem 2.1.1 in line %d of file\n", line_num);
				return -1;
			}
			strcat(buf, "/");
			strcat(buf, temp1);
			read_t = read_t + sizeof(temp1);
			strcat(buf, " ");
			read_t = read_t + sizeof("/ ");
		}

		// dst ip
		temp = strtok_r(NULL, " ", &sub1);
		if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}
		else if(strcmp(temp, "any") == 0){
			strcat(buf, "0/0 ");
			read_t = read_t + sizeof("0/0 ");
		}
		else{
			ip_int_t = 0;
			ip_int = 0;
			temp1 = strtok_r(temp, ".", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += (ip_int_t * 256 * 256 * 256);
			temp1 = strtok_r(NULL, ".", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += (ip_int_t * 256 * 256);
			temp1 = strtok_r(NULL, ".", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += (ip_int_t * 256);
			temp1 = strtok_r(NULL, "/", &sub2);
			ip_int_t = strtol(temp1 ,NULL , 10);
			ip_int += ip_int_t;
			sprintf(temp2, "%u", ip_int);
			strcat(buf, temp2);
			read_t = read_t + sizeof(temp2);
			temp2[0] = '\0';
			temp1 = strtok_r(NULL, " ", &sub2);
			if(strlen(temp1)>2){
				printf("Problem 2.1.2 in line %d of file\n", line_num);
				return -1;
			}
			strcat(buf, "/");
			strcat(buf, temp1);
			read_t = read_t + sizeof(temp1);
			strcat(buf, " ");
			read_t = read_t + sizeof("/ ");
		}
		
		// protocol
		temp = strtok_r(NULL, " ", &sub1);
		if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}
		else if((strcmp(temp, "icmp") == 0)  || (strcmp(temp, "ICMP") == 0)){
			strcat(buf, "1");
			read_t = read_t + sizeof("1 ");
		}
		else if((strcmp(temp, "tcp") == 0) || (strcmp(temp, "TCP") == 0)){
			strcat(buf, "6");
			read_t = read_t + sizeof("6 ");
		}
		else if((strcmp(temp, "udp") == 0) || (strcmp(temp, "UDP") == 0)){
			strcat(buf, "17");
			read_t = read_t + sizeof("17 ");
		}
		else if(strcmp(temp, "other") == 0){
			strcat(buf, "255");
			read_t = read_t + sizeof("255 ");
		}
		else if(strcmp(temp, "any") == 0){
			strcat(buf, "143");
			read_t = read_t + sizeof("143 ");
		}
		else{
			printf("Problam 3 in line %d of file\n", line_num);
			return -1;
		}
		strcat(buf, " ");       
		read_t = read_t + sizeof(" ");
        
        // src port
        temp = strtok_r(NULL, " ", &sub1);
        if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}
		else if(strcmp(temp, "any") == 0){
			strcat(buf, "0");
			read_t = read_t + sizeof("0");
		}
		else if(strcmp(temp, ">1023") == 0){
			strcat(buf, "1023");
			read_t = read_t + sizeof("1023");
		}
		else if(strlen(temp) <= 4){
			strcat(buf, temp);
			read_t = read_t + sizeof(temp);
		}
		else{
			printf("Problem 4 in line %d of file\n", line_num);
			return -1;
		}
        strcat(buf, " ");
        read_t = read_t + sizeof(" ");
        
        // dst port
        temp = strtok_r(NULL, " ", &sub1);
        if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}
		else if(strcmp(temp, "any") == 0){
			strcat(buf, "0");
			read_t = read_t + sizeof("0");
		}
		else if(strcmp(temp, ">1023") == 0){
			strcat(buf, "1023");
			read_t = read_t + sizeof("1023");
		}
		else if(strlen(temp) <= 4){
			strcat(buf, temp);
			read_t = read_t + sizeof(temp);
		}
		else{
			printf("Problem 5 in line %d of file\n", line_num);
			return -1;
		}
        strcat(buf, " ");
        read_t = read_t + sizeof(" ");
        
        // ack
        temp = strtok_r(NULL, " ", &sub1);
        if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}
		else if(strcmp(temp, "no") == 0){
			strcat(buf, "1");
		}
		else if(strcmp(temp, "yes") == 0){
			strcat(buf, "2");
		}
		else if(strcmp(temp, "any") == 0){
			strcat(buf, "3");
		}
		else{
			printf("Problem 6 in line %d of file\n", line_num);
			return -1;
		}
		strcat(buf, " ");
        read_t = read_t + sizeof("0 ");
        
        // decision
        temp = strtok_r(NULL, "\r\n", &sub1);
		if(temp == NULL){
			printf("Missing arguments in line %d of file\n", line_num);
			return -1;
		}
        else if(strcmp(temp, "drop") == 0){
			strcat(buf, "0");
		}
		else if(strcmp(temp, "accept") == 0){
			strcat(buf, "1");
		}
		else{
			printf("Problem 7 in line %d of file\n", line_num);
			return -1;
		}
		strcat(buf, "\n");
        read_t = read_t + sizeof("0\n");
        
        // if there are more "words" in line then there is a problem with the table
        temp = strtok_r(NULL, " ", &sub1);
        if(temp == NULL){
			break;
		}
        else if(strlen(temp) > 1){
			printf("Problem 8 in line %d of file\n", line_num);
			return -1;
		}
		line_num += 1;
        total_read += read_t;
    }
    fclose(fp);
    	
	ret = write(fd, buf, total_read); //total_read
	if(ret < 0){
		printf("Problam in sending the data to the kernel - %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

void show_conn_table(int fd){
	
	int ret;
	struct tm *locale_time;
	time_t timep; 
	char conns_from_fw[PAGE_SIZE], *temp = NULL;
	conns_from_fw[0] = '\0';
	
	ret = read(fd, conns_from_fw, PAGE_SIZE);
	if(ret == 0){
		printf("No connections stored\n");
	}
	else {
		printf("src ip\t\ts_port\tdst ip\t\td_port\tstate\t\t\ttimestamp\t\trule #\n");
	}
	temp = strtok(conns_from_fw, " ");
	while (temp != NULL){
		
		// src ip	
		print_int_as_ip(temp);
		
		// src port	
		temp = strtok(NULL, " ");
		printf("%s\t", temp);
		
		// dst ip	
		temp = strtok(NULL, " ");
		print_int_as_ip(temp);
		
		// dst port	
		temp = strtok(NULL, " ");
		printf("%s\t", temp);
		
		// state	
		temp = strtok(NULL, " ");
		if(strcmp(temp,"1") == 0){
			printf("SYN_SENT\t\t");
		}
		else if(strcmp(temp,"2") == 0){
			printf("SYN_ACK_RECIVED\t\t");
		}
		else if(strcmp(temp,"3") == 0){
			printf("CONNECTION_ESTABLISHED\t");
		}
		else if(strcmp(temp,"4") == 0){
			printf("FIN_ACK_WAIT\t\t");
		}
		else if(strcmp(temp,"5") == 0){
			printf("FIN_ACK_WAIT_2\t\t");
		}
		else if(strcmp(temp,"6") == 0){
			printf("FIN_ACK_RECIVED\t\t");
		}
		else if(strcmp(temp,"7") == 0){
			printf("CONNECTION_CLOSED\t");
		}
		else if(strcmp(temp,"8") == 0){
			printf("EXPECTED_FTP_DATA_CONN\t");
		}
		
		// time
		temp = strtok(NULL, " ");
		timep = strtol(temp ,NULL , 10);
		locale_time = localtime(&timep);
		printf("%d/%d/%d %d:%d:%d\t", locale_time->tm_mday, (locale_time->tm_mon+1),\
		 (locale_time->tm_year+1900), locale_time->tm_hour, locale_time->tm_min, locale_time->tm_sec);

		// rule name
		temp = strtok(NULL, " ");
		printf("%s\n", temp);
		
		// get next line
		temp = strtok(NULL, " ");
	} 
}

void print_int_as_ip(char* temp){
	
	// source: https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
	
	unsigned int num = (unsigned int)strtoll(temp, NULL, 10);
	unsigned char bytes[4];
    bytes[0] = num & 0xFF;
    bytes[1] = (num >> 8) & 0xFF;
    bytes[2] = (num >> 16) & 0xFF;
    bytes[3] = (num >> 24) & 0xFF; 
	printf("%hhu.%hhu.%hhu.%hhu\t", bytes[3], bytes[2], bytes[1], bytes[0]);
}
