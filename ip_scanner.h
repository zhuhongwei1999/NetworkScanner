//
// Created by zhuhongwei on 3/10/20.
//

#ifndef NETWORKSCANNER_IP_SCANNER_H
#define NETWORKSCANNER_IP_SCANNER_H

#include <ifaddrs.h>
#include <arpa/inet.h>



ifaddrs* get_iface_list();
void print_info(ifaddrs* if_list, int start, int end);
#endif //NETWORKSCANNER_IP_SCANNER_H
