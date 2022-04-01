#ifndef __LIB_TEXT_UI
#define __LIB_TEXT_UI

#include "config.h"


void init_global_parameter(struct global_config* cfg);
void sigint_handler(int arg);
void init_text_ui();
int do_tcp_stream_trace(char* cmdline);
void do_packet_filt(char* cmdline);
void do_packet_show(char* cmdline);
void do_packet_save(char* cmdline);
void do_packet_check(void);
void sniffer_log_print(char* log);
#endif