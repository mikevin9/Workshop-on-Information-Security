#ifndef _NF_H_
#define _NF_H_


unsigned int forward_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));	

unsigned int input_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

unsigned int output_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

int register_to_hooks(void);

void unregister_from_hooks(void);


int netfilter_module_init(void);

void netfilter_module_clean(void);

#endif
