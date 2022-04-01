#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "config.h"
#include "text-ui.h"
#include "sniffer.h"

unsigned long p_cnt;
struct packet_record* packets[MAX_SNIFF_PACKET_NR];
char sniffer_log[MAX_SNIFFER_LOG_LEN];

pcap_t *init_device(){
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp, *device;
  char devs[MAX_DEVICE_NR][100];
  char* dev;
  printf("[+] scanning for devices...");
  if(pcap_findalldevs(&alldevsp, errbuf)){
    printf("[-] find device error %s\n", errbuf);
    exit(1);
  }
  printf("done\n");
  int idx = 0;
  for(device = alldevsp; device != NULL; device = device->next){
    if(device->name) strcpy(devs[idx], device->name);
    printf("\t[ %d ] %s - %s\n", idx++, device->name, device->description);
  }
  idx--;

  int u_idx = 0;
getin:
  printf("[ + ] input the device index: ");
  scanf("%d", &u_idx);
  if(u_idx > idx){puts("[-] no such device"); goto getin;};
  dev = devs[u_idx];
  pcap_t* handle = pcap_create(dev, errbuf);
  if(!handle){printf("[-] open device:%s failed %s\n", dev, errbuf);goto getin;};

  pcap_set_immediate_mode(handle, 1);
  if(pcap_set_snaplen(handle, 2048)) printf("[-] error when setting snaplen: %s\n", pcap_geterr(handle));
  if(pcap_set_timeout(handle, 20)) printf("[-] error when setting timeout: %s\n", pcap_geterr(handle));
  if(pcap_set_promisc(handle, 1)) printf("[-] error when setting primisc: %s\n", pcap_geterr(handle));
  pcap_activate(handle);
  return handle;
}

int main(){
  
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = init_device();
  
  struct global_config cfg;
  cfg.max_packet_sniff = MAX_SNIFF_PACKET_NR;
  cfg.verbose = 1;
  init_global_parameter(&cfg);
  

  init_text_ui();

  
  if(pcap_loop(handle, cfg.max_packet_sniff, my_pcap_handler, NULL))
    printf("[-] error when sniffing %s\n", pcap_geterr(handle));
  p_cnt++;

  return 0;
}

void my_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
  const struct ether_header* eth_header;
  uint64_t packet_l = h->caplen;
  p_cnt++;

  packets[p_cnt] = malloc(sizeof(struct packet_record) + packet_l);
  memcpy(&packets[p_cnt]->pcap_hdr, h, sizeof(struct pcap_pkthdr));
  memcpy(&packets[p_cnt]->packet, bytes, packet_l);
  packets[p_cnt]->type = PROTOTYPE_ETH;
  packets[p_cnt]->idx = p_cnt;

  eth_header = (struct ether_header*)bytes;
  // pass the whole packet to the next layer in case we need it
  switch(ntohs(eth_header->ether_type)){
    case ETHERTYPE_IP:
      sniffer_ip_handler((char*)bytes, packet_l);break;
    case ETHERTYPE_ARP:
      sniffer_arp_handler((char*)bytes, packet_l);break;
    default:
      memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
      sprintf(sniffer_log, "[*] [ %lu ] unknown ETHER packet received: %s -> %s\n", p_cnt, 
        ether_ntoa((struct ether_addr*)&eth_header->ether_shost), 
        ether_ntoa((struct ether_addr*)&eth_header->ether_dhost));
      sniffer_log_print(sniffer_log);
      break;
  }

  return;
}

void sniffer_arp_handler(char* raw, uint64_t raw_l){
  const struct ether_header* eth_header;
  eth_header = (struct ether_header*)raw;
  memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
  sprintf(sniffer_log, "[*] [ %lu ] arp: %s -> %s\n", p_cnt, 
    ether_ntoa((struct ether_addr*)&eth_header->ether_shost), 
    ether_ntoa((struct ether_addr*)&eth_header->ether_dhost));
  sniffer_log_print(sniffer_log);
  return;
}

void sniffer_ip_handler(char* raw, uint64_t raw_l){
  raw += 14;
  raw_l -= 14;
  const struct ip* ip_header;
  uint16_t ip_header_l;
  char* ip_payload;
  uint64_t ip_payload_l;
  char sourceIP[INET_ADDRSTRLEN];
  char destIP[INET_ADDRSTRLEN];
  struct ip_packet_trace trace;

  ip_header = (struct ip*)raw;
  ip_header_l = (*(uint32_t*)ip_header & 0x0f) * 4;
  ip_payload = raw + ip_header_l;
  ip_payload_l = raw_l - ip_header_l;
  inet_ntop(AF_INET, &(ip_header->ip_src), sourceIP, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_header->ip_dst), destIP, INET_ADDRSTRLEN);
  strcpy(trace.sourceIP, sourceIP);
  strcpy(trace.destIP, destIP);

  memcpy(&packets[p_cnt]->trace, &trace, sizeof(struct ip_packet_trace));
  packets[p_cnt]->type = PROTOTYPE_IP;

  // pass the IP payload to next layer only
  switch(ip_header->ip_p){
    case IPPROTO_TCP:
      sniffer_tcp_handler(ip_payload, &trace, ip_payload_l);break;
    case IPPROTO_UDP:
      sniffer_udp_handler(ip_payload, &trace, ip_payload_l);break;
    case IPPROTO_ICMP:
      sniffer_icmp_handler(ip_payload, &trace, ip_payload_l);break;
    default:
      memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
      sprintf(sniffer_log, "[-] [ %lu ] unkown IP packet received: %s -> %s\n", p_cnt, sourceIP, destIP);break;
      sniffer_log_print(sniffer_log);
  }
}

void sniffer_tcp_handler(char* raw, struct ip_packet_trace* ip_trace, uint64_t raw_l){
  struct tcphdr* tcp_header;
  uint8_t tcp_header_l;
  char* payload_p;
  uint64_t payload_l;
  uint16_t sourcePort, destPort;
  struct tcp_packet_trace trace;

  tcp_header = (struct tcphdr*)raw;
  tcp_header_l = ((*(uint8_t*)((uint64_t)tcp_header + 12) & 0xF0) >> 4) * 4;
  payload_p = (char*)((uint64_t)tcp_header + tcp_header_l);
  payload_l = raw_l - tcp_header_l;
  sourcePort = ntohs(tcp_header->source);
  destPort = ntohs(tcp_header->dest);
  memcpy(&trace.ip_trace, ip_trace, sizeof(struct ip_packet_trace));
  trace.sourcePort = sourcePort;
  trace.destPort = destPort;
  trace.seq_num = tcp_header->th_seq;
  trace.ack_num = tcp_header->th_ack;
  trace.payload_len = payload_l;
  trace.flag_syn = tcp_header->syn;
  trace.flag_ack = tcp_header->ack;
  trace.flag_fin = tcp_header->fin;
  
  memcpy(&packets[p_cnt]->trace, &trace, sizeof(struct tcp_packet_trace));
  packets[p_cnt]->type = PROTOTYPE_TCP;

  if(sourcePort == 80 || destPort == 80){
    sniffer_http_handler(payload_p, &trace, payload_l);
  }else if(sourcePort == 443 || destPort == 443){
    sniffer_tls_handler(payload_p, &trace, payload_l);
  }else{
    sniffer_general_tcp_handler(payload_p, &trace, payload_l);
  }

}

void sniffer_udp_handler(char* raw, struct ip_packet_trace* ip_trace, uint64_t raw_l){
  struct udphdr* p = (struct udphdr*)raw;
  struct udp_packet_trace trace;
  memcpy(&trace, ip_trace, sizeof(struct ip_packet_trace));
  trace.sourcePort = p->source;
  trace.destPort = p->dest;

  memcpy(&packets[p_cnt]->trace, &trace, sizeof(struct udp_packet_trace));
  packets[p_cnt]->type = PROTOTYPE_UDP;

  memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
  sprintf(sniffer_log, "[*] [ %lu ] udp: %s:%hu -> %s:%hu\n",
          p_cnt,
          ip_trace->sourceIP, trace.sourcePort,
          ip_trace->destIP, trace.destPort);
  sniffer_log_print(sniffer_log);
  return;
}

void sniffer_icmp_handler(char* raw, struct ip_packet_trace* ip_trace, uint64_t raw_l){
  packets[p_cnt]->type = PROTOTYPE_ICMP;
  memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
  sprintf(sniffer_log, "[*] [ %lu ] icmp: %s -> %s\n",
          p_cnt,
          ip_trace->sourceIP, 
          ip_trace->destIP);
  sniffer_log_print(sniffer_log);
  return;
}


void sniffer_tls_handler(char* raw, struct tcp_packet_trace* tcp_trace, uint64_t raw_l){
  packets[p_cnt]->type = PROTOTYPE_TLS;
  memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
  sprintf(sniffer_log, "[*] [ %lu ] tls: %s:%hu -> %s:%hu\n",
          p_cnt,
          tcp_trace->ip_trace.sourceIP, 
          tcp_trace->sourcePort, 
          tcp_trace->ip_trace.destIP, 
          tcp_trace->destPort);
  sniffer_log_print(sniffer_log);
  return;
}

void sniffer_general_tcp_handler(char* raw, struct tcp_packet_trace* tcp_trace, uint64_t raw_l){
  memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
  sprintf(sniffer_log, "[*] [ %lu ] tcp: %s:%hu -> %s:%hu\n",
          p_cnt,
          tcp_trace->ip_trace.sourceIP, 
          tcp_trace->sourcePort, 
          tcp_trace->ip_trace.destIP, 
          tcp_trace->destPort);
  sniffer_log_print(sniffer_log);
  return;
}

void sniffer_http_handler(char* raw, struct tcp_packet_trace* tcp_trace, uint64_t raw_l){
  packets[p_cnt]->type = PROTOTYPE_HTTP;
  memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
  sprintf(sniffer_log, "[*] [ %lu ] http: %s:%hu -> %s:%hu\n",
          p_cnt,
          tcp_trace->ip_trace.sourceIP, 
          tcp_trace->sourcePort, 
          tcp_trace->ip_trace.destIP, 
          tcp_trace->destPort);
  sniffer_log_print(sniffer_log);
  return;
}

void filter_entry(enum proto_type proto, char* sourceIP, char* destIP, uint16_t sourcePort, uint16_t destPort, struct packet_record* filterd[]){
  // struct packet_record* filterd[p_cnt];
  struct packet_record* p;
  memcpy(filterd, packets, 8 * p_cnt);

  // filter protocol
  for(int i=1;i<p_cnt;i++){
    p = filterd[i];
    if(!p) continue;
    if(p->type != proto) filterd[i] = NULL;
  }

  // filter source address
  if(sourceIP){
    for(int i=1;i<p_cnt;i++){
      p = filterd[i];
      if(!p) continue;
      if(strcmp(p->trace.ip_trace.sourceIP, sourceIP)) filterd[i] = NULL;
    }
  }

  // filter dest address
  if(destIP){
    for(int i=1;i<p_cnt;i++){
      p = filterd[i];
      if(!p) continue;
      if(strcmp(p->trace.ip_trace.destIP, destIP)) filterd[i] = NULL;
    }
  }

  // filter source Port
  if(proto != PROTOTYPE_ICMP){
    if(sourcePort){
      for(int i=1;i<p_cnt;i++){
        p = filterd[i];
        if(!p) continue;
        if(p->trace.tcp_trace.sourcePort != sourcePort) filterd[i] = NULL;
      }
    }

    // filter dest port
    if(destPort){
      for(int i=1;i<p_cnt;i++){
        p = filterd[i];
        if(!p) continue;
        if(p->trace.tcp_trace.destPort != destPort) filterd[i] = NULL;
      }
    }
  }
}

void filter_output(enum proto_type proto, struct packet_record* p){
  if(!p) return;
  memset(sniffer_log, 0, MAX_SNIFFER_LOG_LEN);
  switch(proto){
    case PROTOTYPE_TCP:
      sprintf(sniffer_log, "[*] [ %lu ] tcp: %s:%hu -> %s:%hu\n",
          p->idx,
          p->trace.tcp_trace.ip_trace.sourceIP, p->trace.tcp_trace.sourcePort,
          p->trace.tcp_trace.ip_trace.destIP, p->trace.tcp_trace.destPort);
      break;

    case PROTOTYPE_HTTP:
      sprintf(sniffer_log, "[*] [ %lu ] http: %s:%hu -> %s:%hu\n",
        p->idx,
        p->trace.tcp_trace.ip_trace.sourceIP, p->trace.tcp_trace.sourcePort,
        p->trace.tcp_trace.ip_trace.destIP, p->trace.tcp_trace.destPort);
      break;

    case PROTOTYPE_TLS:
      sprintf(sniffer_log, "[*] [ %lu ] tls: %s:%hu -> %s:%hu\n",
        p->idx,
        p->trace.tcp_trace.ip_trace.sourceIP, p->trace.tcp_trace.sourcePort,
        p->trace.tcp_trace.ip_trace.destIP, p->trace.tcp_trace.destPort);
      break;

    case PROTOTYPE_UDP:
      sprintf(sniffer_log, "[*] [ %lu ] udp: %s:%hu -> %s:%hu\n",
        p->idx,
        p->trace.udp_trace.ip_trace.sourceIP, p->trace.udp_trace.sourcePort,
        p->trace.udp_trace.ip_trace.destIP, p->trace.udp_trace.destPort);
      break;

    case PROTOTYPE_ICMP:
      sprintf(sniffer_log, "[*] [ %lu ] icmp: %s -> %s\n",
        p->idx,
        p->trace.ip_trace.sourceIP,
        p->trace.ip_trace.destIP);
      break;

    default:
      sprintf(sniffer_log, "[--] WTF in filter_output()");
      break;
  }

  sniffer_log_print(sniffer_log);
  return;
}

int trace_tcp_stream(unsigned long idx){
  // sanity check of the packet
  struct packet_record* p = packets[idx];
  if(p->type != PROTOTYPE_TCP && p->type != PROTOTYPE_TLS && p->type != PROTOTYPE_HTTP){puts("[-] not a tcp packet, reselect");return -1;}

  // filter out packets of the same ip and port
  struct packet_record* filterd1[p_cnt];
  memset(filterd1, 0, 8 * p_cnt);
  filter_entry(p->type, p->trace.tcp_trace.ip_trace.sourceIP, p->trace.tcp_trace.ip_trace.destIP,
                p->trace.tcp_trace.sourcePort, p->trace.tcp_trace.destPort, (struct packet_record**)&filterd1);
  struct packet_record* filterd2[p_cnt];
  memset(filterd2, 0, 8 * p_cnt);
  filter_entry(p->type, p->trace.tcp_trace.ip_trace.destIP, p->trace.tcp_trace.ip_trace.sourceIP,
                p->trace.tcp_trace.destPort, p->trace.tcp_trace.sourcePort, (struct packet_record**)&filterd2);
  struct packet_record* filterd[p_cnt];
  memset(filterd, 0, 8 * p_cnt);
  for(int i=1;i<p_cnt;i++){
    filterd[i] = (struct packet_record*)((uint64_t)filterd1[i] | (uint64_t)filterd2[i]);
  }

  // find each SYN packet and FIN packet index then check if idx is in between
  unsigned long cur_syn_idx=0, stream_syn_idx=0;
  for(unsigned long i=1;i<p_cnt;i++){
    if(!packets[i]) continue;
    if(packets[i]->trace.tcp_trace.flag_syn && !packets[i]->trace.tcp_trace.flag_ack){
      cur_syn_idx = i;
    }

    if(cur_syn_idx <= idx){
      stream_syn_idx = cur_syn_idx;
      continue;
    }else{
      break;
    }
  }

  if(cur_syn_idx == stream_syn_idx) cur_syn_idx = p_cnt;

  for(unsigned long i=stream_syn_idx;i<cur_syn_idx;i++){
    filter_output(p->type, filterd[i]);
  }

  return 0;
}

void show_packet_content(unsigned long idx){
  if(idx >= MAX_SNIFF_PACKET_NR){sniffer_log_print("[-] index out of range");return;}
  struct packet_record* p = packets[idx];
  if(!p) {sniffer_log_print("[-] no such packet"); return;}

  char* ctnt = p->packet;
  uint64_t packet_l = p->pcap_hdr.caplen;


  for(uint64_t i=0;i<packet_l;i++){
    if(ctnt[i] > 32 && ctnt[i] < 127){
      sprintf(sniffer_log, "%c", ctnt[i]);
    }else{
      sprintf(sniffer_log, ".");
    }
  }
}