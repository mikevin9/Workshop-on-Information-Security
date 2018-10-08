#ifndef _FW_H_
#define _FW_H_


// TCP states we will work with
typedef enum {
	SYN_SENT					= 1,
	SYN_ACK_RECIVED				= 2,
	CONNECTION_ESTABLISHED		= 3,
	FIN_ACK_WAIT				= 4,
	FIN_ACK_WAIT_2				= 5,
	FIN_ACK_RECIVED				= 6,
	CONNECTION_CLOSED			= 7,
	EXPECTED_FTP_DATA_CONN		= 8,
} conn_stat_t;

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
	REASON_ILLEGAL_STATE		 = -8,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)
#define MAX_LOGS		(1000)  // i added this
#define MAX_PORT_NUMBER	(49151) // i added this
#define TIMEOUT			(25) // i added this
#define IN_NETWORK_MASK	(4294967040u) // i added this = 255.255.255.0
#define IN_NETWORK		(167837952u) // i added this = 10.1.1.0

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 1,
	MINOR_LOG      = 2,
	MINOR_CONNS    = 3,
} minor_t;

typedef enum {
	FLAG_NO 	= 0x01,
	FLAG_YES 	= 0x02,
	FLAG_ANY 	= FLAG_NO | FLAG_YES,
} flag_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;


// rule table entry
typedef struct {
	int 			is_valid;			// i added this
	char 			rule_name[20];		// names will be no longer than 20 chars
	direction_t 	direction;
	__be32			src_ip;
	__be32			src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    		src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above (the field is redundant - easier to print)
	__be32			dst_ip;
	__be32			dst_prefix_mask; 	// as above
	__u8    		dst_prefix_size; 	// as above	
	__be16			src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16			dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8			protocol; 			// values from: prot_t
	flag_t			ack; 				// values from: flag_t
	__u8			action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// log table entry
typedef struct {
	int				is_valid;		// i added this
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule #index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;


// connection table entry
typedef struct {
	__be32			src_ip;
	__be32			dst_ip;
	__be16			src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16			dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8			state;
	unsigned long  	timestamp;   	  	// time of creation/update
	int 			rule_num;
	__be16			fake_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	struct list_head connection;
} conn_t;

#endif
