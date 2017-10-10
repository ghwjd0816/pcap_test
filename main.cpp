#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define SIZE_OF_ETHERNET 14
#define SIZE_OF_IPV4 20
#define SIZE_OF_TCP 20

struct libnet_ethernet_hdr
{
	u_int8_t ether_dhost[ETHER_ADDR_LEN];
	u_int8_t ether_shost[ETHER_ADDR_LEN];
	u_int16_t ether_type;
};

#define ETHERTYPE_IP 0x0800

struct libnet_ipv4_hdr
{
	u_int8_t ip_hl:4,      /* header length */
	          ip_v:4;      /*version*/
	u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
        u_int16_t ip_len;         /* total length */
        u_int16_t ip_id;          /* identification */
        u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
        u_int8_t ip_ttl;          /* time to live */
        u_int8_t ip_p;            /* protocol */
        u_int16_t ip_sum;         /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
        u_int16_t th_sport;       /* source port */
        u_int16_t th_dport;       /* destination port */
        u_int32_t th_seq;          /* sequence number */
        u_int32_t th_ack;          /* acknowledgement number */

        u_int8_t th_x2:4,         /* (unused) */
                th_off:4;        /* data offset */
	u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
        u_int16_t th_win;         /* window */
	u_int16_t th_sum;         /* checksum */
	u_int16_t th_urp;         /* urgent pointer */
};

void print_mac(u_int8_t*mac)
{
  printf("%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

int main(int argc, char* argv[]) {

  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  dev = pcap_lookupdev(errbuf);
  if(dev==NULL){
    printf("Can't find device\n");
    return -1;
  }
  printf("Device Name : %s\n",dev);  
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    struct libnet_ethernet_hdr *ethernet;
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr *tcp;

    ethernet = (struct libnet_ethernet_hdr*)packet;
    printf("\nSRC MAC : ");
    print_mac(ethernet->ether_shost);
    printf("\nDST MAC : ");
    print_mac(ethernet->ether_dhost);
    printf("\nETHERTYPE = 0x%04X" ,ntohs(ethernet->ether_type));
    if(ntohs(ethernet->ether_type) != ETHERTYPE_IP)
    {
      printf("\nEther type is not IP\n");
      continue;
    }
    ip = (struct libnet_ipv4_hdr*)(packet + SIZE_OF_ETHERNET);
    printf("\nSRC IP : %s",inet_ntoa(ip->ip_src));
    printf("\nDST IP : %s",inet_ntoa(ip->ip_dst));
    printf("\nIP_P : %d",ip->ip_p);

    if(ip->ip_p != 0x06)
    {
      printf("\nIP protocol is not TCP\n");
      continue;
    }
    tcp = (struct libnet_tcp_hdr*)(ip + SIZE_OF_IPV4);
    printf("\nSRC PORT : %d",ntohs(tcp->th_sport));
    printf("\nDST PORT : %d\n",ntohs(tcp->th_dport));
    
    int bytes = 16;
    char * data = (char*)(tcp + SIZE_OF_TCP);
    for(int i=0;i<bytes;i++)printf("%X",data[i]);
    printf("\n%u bytes captured\n", header->len);
  }

  pcap_close(handle);
  return 0;
}
