#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include "port_scanner.h"
#include "ip_scanner.h"

int main(int argc, char *argv[])
{
    char *host;
    int start, end;
    if(argc < 2){
        printf("Format error");
        return 1;
    }

    else{
        struct sockaddr_in s;
        host = argv[1];
        if(argc == 4){
            start = atoi(argv[2]);
            end = atoi(argv[3]);
        }

        if(strcmp(argv[1], "-all") == 0){
            print_info(get_iface_list(), start, end);
        }

        else{
            // Check validity of IPv4
            if(inet_pton(AF_INET, host, &s) != 1){
                fprintf(stderr, "Host address error %s\n", host);
                return 1;
            }

            for(int p=start; p<=end; p++){
                if (scan_port(host, p) == 0)
                    printf("%s:%d Connect success.\n", host, p);
                else{
                    fprintf(stderr, "%s:%d Connect timeout.\n", host, p);
                }
            }
        }
    }

    return 0;
}
