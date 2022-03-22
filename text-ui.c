#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "sniffer.h"
#include "text-ui.h"


char* cmd_info = "\n[ + ] input a command\n"
                 "\t[ * ] filt - set packet filter\n"
                 "\t[ * ] trace - trace a tcp stream\n"
                 "\t[ * ] quit - quit sniffer\n"
                 "\t[ * ] save - save packets to file\n"
                 "\t[ * ] continue - continue sniffing\n"
                 "\t[ * ] show - show content of a packet\n"
                 "[ + ] command: ";


void init_global_parameter(struct global_config* cfg){
  printf("[ + ] verbose level(default 1):");
  if(!scanf("%d", &cfg->verbose)) cfg->verbose = 1;
  printf("[ + ] max packets to capture(default %u):", MAX_SNIFF_PACKET_NR);
  if(!scanf("%d", &cfg->max_packet_sniff)) cfg->max_packet_sniff = MAX_SNIFF_PACKET_NR;
  return;
}

void sigint_handler(int arg){
  char cmdline[100];
  size_t cmdline_l = 0;
getin:
  printf("%s", cmd_info);
  memset(cmdline, 0, 100);
  read(0, cmdline, 100);
  if(!strncmp(cmdline, "quit", 4)){
    exit(0);
  }else if(!strncmp(cmdline, "continue", 8)){
    return;
  }else if(!strncmp(cmdline, "trace", 5)){
    do_tcp_stream_trace(cmdline);
    goto getin;
  }else if(!strncmp(cmdline, "filt", 4)){
    do_packet_filt(cmdline);
    goto getin;
  }else if(!strncmp(cmdline, "show", 4)){
    do_packet_show(cmdline);
    goto getin;
  }else if(!strncmp(cmdline, "save", 4)){
    do_packet_save(cmdline);
  }else{
    puts("[ - ] wrong command");
    goto getin;
  }
}

int do_tcp_stream_trace(char* cmdline){
  cmdline += 6;
  unsigned long idx = (unsigned long)atol(cmdline);
  return trace_tcp_stream(idx);
}

// filt tcp 192.168.1.1 192.168.1.2 80 40000
void do_packet_filt(char* cmdline){
  char cmdline_buf[100];
  strcpy(cmdline_buf, cmdline);
  char param[6][50];
  int i=0;
  char delim[2] = " ";
  char* token;
  token = strtok(cmdline_buf, delim);
  while(token){
    strcpy(param[i++], token);
    token = strtok(NULL, delim);
  }

  char *sourceIP, *destIP;
  uint16_t sourcePort, destPort;
  enum proto_type proto;
  if(strcmp(param[0], "filt")){puts("[--] should not happen");exit(1);}
  if(!strcmp(param[1], "tcp")) proto = PROTOTYPE_TCP;
  else if(!strcmp(param[1], "udp")) proto = PROTOTYPE_UDP;
  else if(!strcmp(param[1], "icmp")) proto = PROTOTYPE_ICMP;
  else if(!strcmp(param[1], "tls")) proto = PROTOTYPE_TLS;
  else if(!strcmp(param[1], "http")) proto = PROTOTYPE_HTTP;
  else{
    printf("[-] trace %s is not implemented\n", param[1]);
    return;
  }
  if(!strcmp(param[2], "0")){
    sourceIP = NULL;
  }
  if(!strcmp(param[3], "0")){
    destIP = NULL;
  }
  sourcePort = (uint16_t)atoi(param[4]);
  destPort = (uint16_t)atoi(param[5]);

  struct packet_record* filterd[MAX_SNIFF_PACKET_NR];
  memset(filterd, 0, 8 * MAX_SNIFF_PACKET_NR);
  filter_entry(proto, sourceIP, destIP, sourcePort, destPort, (struct packet_record**)&filterd);
  for(unsigned long i=1;i<MAX_SNIFF_PACKET_NR;i++){
    filter_output(proto, filterd[i]);
  }
  return;
}

void do_packet_show(char* cmdline){
  cmdline += 5;
  unsigned long idx = (unsigned long)atol(cmdline);
  show_packet_content(idx);
  return;
}

void do_packet_save(char* cmdline){
  puts("[--] to be implemented");
  return;
}

void init_text_ui(){
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  signal(SIGINT, sigint_handler);
}

