#ifndef __SNIFFER_GLOBAL_CONFIG
#define __SNIFFER_GLOBAL_CONFIG

#define MAX_SNIFF_PACKET_NR 10000
#define MAX_DEVICE_NR 20

struct global_config{
  int verbose;
  int max_packet_sniff;
};


#endif