//
// Created by zhuhongwei on 3/10/20.
//
#include <cstdio>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ip_scanner.h"
#include "port_scanner.h"

// Get all interfances.
ifaddrs* get_iface_list(){
    struct ifaddrs *ifList;
    int is_iface = getifaddrs(&ifList);

    if (is_iface < 0){
        return NULL;
    }
    else{
        return ifList;
    }
}

void print_info(ifaddrs* if_list, int start, int end){
    struct sockaddr_in *sin = NULL;
    struct ifaddrs *ifa = NULL;
    // Print interface information.
    printf("iface\t\t\tip\t\t\t\t\t\tmask\n");
    for (ifa = if_list; ifa != NULL; ifa = ifa->ifa_next){
        if(ifa->ifa_addr->sa_family == AF_INET){
            printf("%s", ifa->ifa_name);
            sin = (struct sockaddr_in *)ifa->ifa_addr;
            printf("%24s", inet_ntoa(sin->sin_addr));
            sin = (struct sockaddr_in *)ifa->ifa_netmask;
            printf("%24s\n", inet_ntoa(sin->sin_addr));
        }
    }

    // Get local network from IP and mask.
    for (ifa = if_list; ifa != NULL; ifa = ifa->ifa_next){
        if(ifa->ifa_addr->sa_family == AF_INET){
            int fd;
            struct ifreq ifr;
            struct in_addr in;
            char *host;
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            ifr.ifr_addr.sa_family = AF_INET;
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
            ioctl(fd, SIOCGIFADDR, &ifr);
            unsigned int ip = htonl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
            ioctl(fd, SIOCGIFNETMASK, &ifr);
            unsigned int mask = htonl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
            int maskip = ip & mask;
            int negmask = (int)~(mask);

            // traverse ports of local host.
            if(strcmp(ifa->ifa_name, "lo") == 0){
                strcpy(host, "127.0.0.1");
                for (int p = start; p <= end; p++){
                    if (scan_port(host, p) == 0)
                        printf("%s:%d Connect success.\n", host, p);
                }
            }

            // Traverse ports from other hosts.
            else{
                for (int i=1; i<negmask; i++){
                    in.s_addr = ntohl(maskip+i);
                    host = inet_ntoa(in);
                    for (int p = start; p <= end; p++){
                        if (scan_port(host, p) == 0)
                            printf("%s:%d Connect success.\n", host, p);
                    }
                }
            }
        }
    }
}