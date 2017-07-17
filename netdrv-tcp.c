#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>

#include<linux/workqueue.h>
#include<linux/in.h>
#include<linux/inet.h>
#include<linux/socket.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include<linux/tcp.h>
#include<net/sock.h>
#include<linux/netdevice.h>
#include<linux/kthread.h>
//time_start
#include<linux/delay.h>
#include<linux/timer.h>
#include<linux/timex.h>
#include<linux/rtc.h>
//time_end

MODULE_LICENSE("Dual BSD/GPL");

static struct net_device *netdev = NULL; // 包含网络设备的属性描述和操作接口
#define IF_NAME "eth0"
#define  SRC_MAC  {0Xfe, 0XE0, 0X4D, 0X8B, 0X3C, 0XD7} // 源MAC地址
#define  DST_MAC  {0Xb8, 0X70, 0xf4, 0Xa7, 0X44, 0Xf6} // 目的MAC地址
static  int num = 0;
static  int times = 20;
static volatile int check = 0;
static char *DIP = "192.168.1.167"; // 目标IP
static int DPORT = 80;              // 目标端口
static char *SIP = "5.5.5.5";       // 源IP
static int  SPORT = 0;              // 源端口
struct socket *sock;
int data_len = 0; 
struct timex txc;
struct rtc_time tm;

module_param(num, int, S_IRUSR);
module_param(times, int, S_IRUSR);
module_param(DIP, charp, S_IRUSR);
module_param(data_len, int, S_IRUSR);
module_param(DPORT, int, S_IRUSR);

static void sock_init(void) {
	struct ifreq ifr; // 用来配置ip地址，激活接口，配置MTU等接口信息的
	sock_create_kern(PF_INET, SOCK_DGRAM, 0, &sock); // 在内核中创建socket结构体，用来控制eth
	strcpy(ifr.ifr_ifrn.ifrn_name, IF_NAME);
	kernel_sock_ioctl(sock, SIOCSIFNAME, (unsigned long)&ifr);
}

static struct sk_buff* create_skb(int Rsip /* Fake Source IP */ ) {
	struct sk_buff *skb = NULL;
	struct net *net = NULL;
	struct ethhdr *eth_header = NULL;
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;

	__be32 dip = in_aton(DIP); // __be32 无符号32bit整形
	__be32 sip = in_aton(SIP);
	u16 expand_len = 16;
	u32 skb_len;
	u8 dst_mac[ETH_ALEN] = DST_MAC; // ETH_ALEN 6 以太网地址大小
	u8 src_mac[ETH_ALEN] = SRC_MAC;
    
	/* construct skb */
	sock_init();  
	net = sock_net((const struct sock*)sock->sk);
	netdev = dev_get_by_name(net, IF_NAME); // 获取设备指针
 
	skb_len = LL_RESERVED_SPACE(netdev) + sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len + expand_len;

	skb = dev_alloc_skb(skb_len); // 用于分配套接字缓冲区，以GFP_ATOMIC为优先级
	if (!skb) {
		pr_emerg("Failed while create the packet.\n"); // printk KERN_EMERG
		return NULL; 
	}

	/*     Dev     */
	skb_reserve(skb, LL_RESERVED_SPACE(netdev)); // 对于一个空缓冲区，可以调整缓冲区的头部，会将skb->data和skb->tail同时后移len
	skb->dev = netdev;
	skb->pkt_type = PACKET_OTHERHOST;	// 发往其他主机的包，PACKET_HOST是发往本机的包
	skb->protocol = htons(ETH_P_IP);	// 发送IP数据包
	skb->ip_summed = CHECKSUM_NONE;		// 传输层自己计算校验和
	skb->priority = 0;

	/*      MAC     */
	pr_emerg("the size of struct ethhdr is: %ld\n", sizeof(struct ethhdr));
	eth_header = (struct ethhdr* )skb_push(skb, sizeof(struct ethhdr)); // 在缓冲区开头增加数据
	memcpy(eth_header->h_dest, dst_mac, ETH_ALEN); // 目的MAC地址
	memcpy(eth_header->h_source, src_mac, ETH_ALEN); // 源MAC地址
	eth_header->h_proto = htons(ETH_P_IP); // 网络层用的协议类型 IP协议

	/*      IP      */
	skb_set_network_header(skb, sizeof(struct ethhdr));
	skb_put(skb, sizeof(struct iphdr)); // 在缓冲区尾部增加
	ip_header = ip_hdr(skb); 
	ip_header->version = 4; // 版本号
	ip_header->ihl = sizeof(struct iphdr) >> 2; // 首部长度表示20字节
	ip_header->tos = 0;     // 区分服务（不使用）
	ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20 + data_len); // 总长度：首部和数据之和的长度
	ip_header->id = 67;     // 标识
	ip_header->frag_off = 0x0; // 标志和片偏移
	ip_header->ttl = 0x40;  // 生存时间
	ip_header->protocol = IPPROTO_TCP; // 协议
	ip_header->check = 0;   // 首部校验和
	ip_header->daddr = dip; // 源IP
	ip_header->saddr = sip; // 目的IP
	/*      TCP     */
	skb_set_transport_header(skb, sizeof(struct iphdr) + sizeof(struct ethhdr));
	skb_put(skb, sizeof(struct tcphdr) + 20);
	tcp_header = tcp_hdr(skb);
 
  tcp_header->source = htons(SPORT);// 源端口号
  tcp_header->dest = htons(DPORT);  // 目的端口号
  tcp_header->seq = 0;              // 序号
  tcp_header->ack_seq = 0;          // 确认号
  tcp_header->doff = 10;            // TCP首部大小
  tcp_header->res1 = 0;             // 保留字段
  tcp_header->urg = 0;              // 紧急
  tcp_header->ack = 0;              // 确认
  tcp_header->psh = 0;              // 推送
  tcp_header->rst = 0;              // 复位
  tcp_header->syn = 1;              // 同步
  tcp_header->fin = 0;              // 终止
  tcp_header->ece = 0;              // 用途不明
  tcp_header->cwr = 0;              // 用途不明
  tcp_header->check = 0;            // 校验和
  tcp_header->urg_ptr = 0;          // 紧急指针   

  /*      CHECK   */
  skb->csum=0;
  skb->csum=skb_checksum(skb,ip_header->ihl*4,skb->len-ip_header->ihl*4,0);
  ip_header->check=ip_fast_csum(ip_header,ip_header->ihl);
  tcp_header->check=csum_tcpudp_magic(ip_header->saddr,ip_header->daddr,skb->len-ip_header->ihl*4,IPPROTO_TCP,skb->csum);
  /*    complete   */
  return skb; 
}



static int try1(void *arg);
static int try2(void *arg);
static int try3(void *arg);
static struct task_struct *xmit_thread[3]={NULL,NULL,NULL};
static struct completion start_done[3]; // 用于内核同步
static volatile u32 xmit_stop[3]={0x0,0x0,0x0};
static volatile u32 STOP=0;
static struct sk_buff_head pkt_xmit1;


static int try1(void *arg){
   struct sk_buff *skb = NULL; // 套接字缓冲区，用于在Linux网络子系统中的各层之间传递数据
   struct sk_buff *skb_t = NULL;
   struct iphdr* ip_header = NULL; // ip_hdr(skb); IP数据包的描述结构体
   struct tcphdr* tcp_header = NULL; // tcp_hdr(skb);

   skb = create_skb(0);
   complete(&start_done[0]); // 用于唤醒一个等待该完成量的进程
   ip_header = ip_hdr(skb);
   tcp_header = tcp_hdr(skb);

   while (!STOP) {
      local_irq_disable(); // 设置当前CPU的中断屏蔽位（屏蔽当前CPU上的中断）
      //ip_header->saddr++;
      //skb->csum=skb_checksum(skb,ip_header->ihl*4,skb->len-ip_header->ihl*4,0);
      //ip_header->check=ip_fast_csum(ip_header,ip_header->ihl);
      //tcp_header->check=csum_tcpudp_magic(ip_header->saddr,ip_header->daddr,skb->len-ip_header->ihl*4,IPPROTO_TCP,skb->csum);
      skb_t = skb_copy(skb, GFP_ATOMIC);
      
      if (skb_t != NULL)
        if (dev_queue_xmit(skb_t) == 0) // 网络协议接口层函数，发送数据包
          num++;
      local_irq_enable(); // 开启CPU中断
   }
   xmit_stop[0] = 1;
   return 0;
}

static int try2(void *arg){
   
   int sip = -2147483648;//the minimum number is IP:0.0.0.128
   complete(&start_done[1]);
   
   struct sk_buff *skb = NULL;
   struct sk_buff *skb_t = NULL;
   struct iphdr* ip_header = NULL;//ip_hdr(skb);
   struct tcphdr* tcp_header = NULL;// tcp_hdr(skb);

   skb = create_skb(sip);
   ip_header = ip_hdr(skb);
   tcp_header = tcp_hdr(skb);

  while(!STOP){
          local_irq_disable();
          ip_header->saddr++;
          skb->csum=csum_partial(skb->data,skb->len,0);
          ip_header->check=ip_fast_csum(ip_header,ip_header->ihl);
          tcp_header->check=csum_tcpudp_magic(ip_header->saddr,ip_header->daddr,skb->len-ip_header->ihl*4,IPPROTO_TCP,skb->csum);
          skb_t = skb_copy(skb,GFP_ATOMIC);
          
          if(skb_t != NULL)
           if(dev_queue_xmit(skb_t) == 0)
             num++;
          local_irq_enable();
          
    }
	  xmit_stop[1]=1;
	  return 0;
}

static int try3(void *arg){
   int sip = 2147483647;//IP: 255.255.255.127
   complete(&start_done[2]);
   
   struct sk_buff *skb = NULL;
   struct sk_buff *skb_t = NULL;
   struct iphdr* ip_header = NULL;//ip_hdr(skb);
   struct tcphdr* tcp_header = NULL;// tcp_hdr(skb);

   skb = create_skb(sip);
   ip_header = ip_hdr(skb);
   tcp_header = tcp_hdr(skb);

  while(!STOP){
          local_irq_disable();
          ip_header->saddr--;
          skb->csum=csum_partial(skb->data,skb->len,0);
          ip_header->check=ip_fast_csum(ip_header,ip_header->ihl);
          tcp_header->check=csum_tcpudp_magic(ip_header->saddr,ip_header->daddr,skb->len-ip_header->ihl*4,IPPROTO_TCP,skb->csum);
          skb_t = skb_copy(skb,GFP_ATOMIC);
         if(skb_t != NULL)
            if(dev_queue_xmit(skb_t) == 0)
             num++;
          local_irq_enable();
          
    }
	xmit_stop[2]=1;
	return 0;
}

static int __init send_init(void){
	int sum = num * times;
	int i=0;

	printk(KERN_ALERT "testmod kernel module load!\n");

	skb_queue_head_init(&pkt_xmit1); // 获取sk_buff_head结构体中的自旋锁
	//skb_queue_head_init(&pkt_xmit2);
	for (i = 0; i < 3; i++)
		init_completion(&start_done[i]);
 
 	xmit_thread[0] = kthread_create(try1, NULL, " ");
	xmit_thread[1] = kthread_create(try2, NULL, " ");
	xmit_thread[2] = kthread_create(try3, NULL, " ");

	for (i = 0;i<1;i++){
	  if (IS_ERR(xmit_thread[i])) {
  	    xmit_thread[i] = NULL;
  	    pr_err("try%d thread create occur error.\n",i);
  	    return 0;
  	  } else {
    	pr_emerg("try%d create success.\n",i+1);
    	wake_up_process(xmit_thread[i]);
    	wait_for_completion(&start_done[i]);
   	    pr_emerg("try%d thread worker success.\n",i+1);
      }
    }

	for(sum=0;sum<times;sum++){
	   msleep(1000);
	}
	   STOP=1;
	pr_emerg("end of the running start!\nThe num is : %d\n",num);
	while(!xmit_stop[0]/*||!xmit_stop[1]||!xmit_stop[2]*/)
		msleep(120);
	pr_emerg("The End.\n");
	msleep(100);
 	return 0;
}

static void __exit send_exit(void){
	struct sk_buff *skb_t = NULL;
	skb_t = skb_dequeue(&pkt_xmit1);
	while (skb_t != NULL) {
	  kfree_skb(skb_t); // 释放套接字缓冲区
	  skb_t = __skb_dequeue(&pkt_xmit1);
	}
	sock_release(sock);
	dev_put(netdev); // 取消dev_get_by_name获取的设备引用
	printk(KERN_ALERT "\ntestmod kernel module removed!\n");
}

module_init(send_init);
module_exit(send_exit);
