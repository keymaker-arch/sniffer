#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ncurses.h>

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
                 "\t[ * ] check - check received packets\n"
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
  wprintw(stdscr, "%s", cmd_info);
  refresh();
  memset(cmdline, 0, 100);
  getnstr(cmdline, 100);
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
  }else if(!strncmp(cmdline, "check", 5)){
    do_packet_check();
    clear();
    goto getin;
  }else{
    wprintw(stdscr, "[ - ] wrong command");
    refresh();
    goto getin;
  }
}

void do_packet_check(){
  WINDOW *pad = newpad(MAX_SNIFF_PACKET_NR, COLS);
  struct packet_record* p;
  for(unsigned long i=1;i<p_cnt;i++){
    p = packets[i];
    switch(p->type){
      case PROTOTYPE_TCP:
        wprintw(pad, "[*] [ %lu ] tcp: %s:%hu -> %s:%hu\n",
            p->idx,
            p->trace.tcp_trace.ip_trace.sourceIP, p->trace.tcp_trace.sourcePort,
            p->trace.tcp_trace.ip_trace.destIP, p->trace.tcp_trace.destPort);
        break;

      case PROTOTYPE_HTTP:
        wprintw(pad, "[*] [ %lu ] http: %s:%hu -> %s:%hu\n",
          p->idx,
          p->trace.tcp_trace.ip_trace.sourceIP, p->trace.tcp_trace.sourcePort,
          p->trace.tcp_trace.ip_trace.destIP, p->trace.tcp_trace.destPort);
        break;

      case PROTOTYPE_TLS:
        wprintw(pad, "[*] [ %lu ] tls: %s:%hu -> %s:%hu\n",
          p->idx,
          p->trace.tcp_trace.ip_trace.sourceIP, p->trace.tcp_trace.sourcePort,
          p->trace.tcp_trace.ip_trace.destIP, p->trace.tcp_trace.destPort);
        break;

      case PROTOTYPE_UDP:
        wprintw(pad, "[*] [ %lu ] udp: %s:%hu -> %s:%hu\n",
          p->idx,
          p->trace.udp_trace.ip_trace.sourceIP, p->trace.udp_trace.sourcePort,
          p->trace.udp_trace.ip_trace.destIP, p->trace.udp_trace.destPort);
        break;

      case PROTOTYPE_ICMP:
        wprintw(pad, "[*] [ %lu ] icmp: %s -> %s\n",
          p->idx,
          p->trace.ip_trace.sourceIP,
          p->trace.ip_trace.destIP);
        break;

      case PROTOTYPE_ETH:
        wprintw(pad, "[*] [ %lu ] eth\n",
          p->idx
          );
        break;

      default:
        wprintw(pad, "[*] [ %lu ] unkown packet\n", p_cnt);
        break;
    }
  }

  clear();
  mvwprintw(stdscr, 0, COLS/2-8, "PRESS q to RETURN");
  int chr;
  int cur_line = 0;
  prefresh(pad, cur_line, 0, 1, 0, LINES-1, COLS);
  refresh();
  while((chr = wgetch(stdscr)) != 'q'){
    switch(chr){
      case KEY_UP:
        if(cur_line - 1 >= 0) cur_line--;
        break;
      case KEY_DOWN:
        if(cur_line + 1 <= p_cnt) cur_line++;
        break;
      case 'q':
        goto out;
      default:
        break;
    }
    prefresh(pad, cur_line, 0, 1, 0, LINES-1, COLS);
  }

out:
  return;
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
  if(strcmp(param[0], "filt")){wprintw(stdscr, "[--] should not happen");refresh();exit(1);}
  if(!strcmp(param[1], "tcp")) proto = PROTOTYPE_TCP;
  else if(!strcmp(param[1], "udp")) proto = PROTOTYPE_UDP;
  else if(!strcmp(param[1], "icmp")) proto = PROTOTYPE_ICMP;
  else if(!strcmp(param[1], "tls")) proto = PROTOTYPE_TLS;
  else if(!strcmp(param[1], "http")) proto = PROTOTYPE_HTTP;
  else{
    wprintw(stdscr, "[-] trace %s is not implemented\n", param[1]);
    refresh();
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
  wprintw(stdscr, "[--] to be implemented");
  refresh();
  return;
}

void do_quit(){
  endwin();
}

void init_text_ui(){
  initscr();
  cbreak();
  keypad(stdscr, TRUE);
  scrollok(stdscr, TRUE);
  atexit(do_quit);

  signal(SIGINT, sigint_handler);
}


void sniffer_log_print(char* log){
  wprintw(stdscr, log);
  refresh();
  return;
}
