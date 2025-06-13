#ifndef ANALIZATOR_H
#define ANALIZATOR_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <iostream>
#include <map>
#include <sys/ioctl.h>

#define PROMISC_ON  1
#define PROMISC_OFF 0

struct ifparam {
    __u32 ip;
    __u32 mask;
    int mtu;
    int index;
};

extern struct ifparam ifp;

int getifconf(const char* intf, struct ifparam* ifp, int mode);
int getsock_recv(int index);
void alert(const std::string& message);

#endif
