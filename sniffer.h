#ifndef __LIB_SNIFFER
#define __LIB_SNIFFER

#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdlib.h>


struct ip_packet_trace{
  char sourceIP[INET_ADDRSTRLEN];
  char destIP[INET_ADDRSTRLEN];
};

struct tcp_packet_trace{
  struct ip_packet_trace ip_trace;
  uint16_t sourcePort;
  uint16_t destPort;
  uint32_t seq_num;
  uint32_t ack_num;
  char flag_syn;
  char flag_ack;
  char flag_fin;
  uint32_t payload_len;
};

struct udp_packet_trace{
  struct ip_packet_trace ip_trace;
  uint16_t sourcePort;
  uint16_t destPort;
};


// TODO: should use bitmap
enum proto_type{
  PROTOTYPE_ETH=1,
  PROTOTYPE_IP,
  PROTOTYPE_TCP,
  PROTOTYPE_UDP,
  PROTOTYPE_ICMP,
  PROTOTYPE_HTTP,
  PROTOTYPE_TLS
};

struct packet_record{
  struct pcap_pkthdr pcap_hdr;
  unsigned long idx;
  enum proto_type type;
  union trace{
    struct ip_packet_trace ip_trace;
    struct tcp_packet_trace tcp_trace;
    struct udp_packet_trace udp_trace;
  }trace;
  char packet[];
};

pcap_t *init_device();
void my_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void sniffer_ip_handler(char* raw, uint64_t raw_l);
void sniffer_arp_handler(char* raw, uint64_t raw_l);
void sniffer_tcp_handler(char* raw, struct ip_packet_trace* ip_trace, uint64_t raw_l);
void sniffer_udp_handler(char* raw, struct ip_packet_trace* ip_trace, uint64_t raw_l);
void sniffer_icmp_handler(char* raw, struct ip_packet_trace* ip_trace, uint64_t raw_l);
void sniffer_http_handler(char* raw, struct tcp_packet_trace* tcp_trace, uint64_t raw_l);
void sniffer_general_tcp_handler(char* raw, struct tcp_packet_trace* tcp_trace, uint64_t raw_l);
void sniffer_tls_handler(char* raw, struct tcp_packet_trace* tcp_trace, uint64_t raw_l);
void filter_entry(enum proto_type proto, char* sourceIP, char* destIP, uint16_t sourcePort, uint16_t destPort, struct packet_record* filterd[]);
void filter_output(enum proto_type proto, struct packet_record* p);
int trace_tcp_stream(unsigned long idx);
void show_packet_content(unsigned long idx);


unsigned long p_cnt;
struct packet_record* packets[MAX_SNIFF_PACKET_NR];
#endif