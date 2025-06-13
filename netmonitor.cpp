#include "analizator.h"
#include <chrono>
#include <thread>

struct ifparam ifp;

const float MAX_BANDWIDTH_MB = 100.0;
const int MAX_PACKETS_PER_SEC = 1000;
const int MAX_CONNECTIONS = 500;

long total_packets = 0;
long tcp_packets = 0;
std::map<std::pair<uint32_t, uint16_t>, bool> active_connections;

void alert(const std::string& message) {
    std::cerr << "[!] ПРЕВЫШЕНИЕ: " << message << std::endl;
}

int getifconf(const char* intf, struct ifparam* ifp, int mode) {
    int fd;
    struct ifreq ifr;
    struct sockaddr_in* sa;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, intf, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(fd);
        return -1;
    }
    sa = (struct sockaddr_in*)&ifr.ifr_addr;
    ifp->ip = sa->sin_addr.s_addr;

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("SIOCGIFNETMASK");
        close(fd);
        return -1;
    }
    sa = (struct sockaddr_in*)&ifr.ifr_netmask;
    ifp->mask = sa->sin_addr.s_addr;

    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        perror("SIOCGIFMTU");
        close(fd);
        return -1;
    }
    ifp->mtu = ifr.ifr_mtu;

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(fd);
        return -1;
    }
    ifp->index = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        close(fd);
        return -1;
    }

    if (mode == PROMISC_ON) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int getsock_recv(int index) {
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = index;

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

int main() {
    signal(SIGINT, [](int) { 
        getifconf("enp0s3", &ifp, PROMISC_OFF);
        exit(0);
    });

    if (getifconf("enp0s3", &ifp, PROMISC_ON) < 0) {
        std::cerr << "Ошибка настройки интерфейса!" << std::endl;
        return -1;
    }

    std::cout << "IP: " << inet_ntoa(*(struct in_addr*)&ifp.ip) << std::endl;
    std::cout << "Маска: " << inet_ntoa(*(struct in_addr*)&ifp.mask) << std::endl;
    std::cout << "MTU: " << ifp.mtu << std::endl;
    std::cout << "Индекс: " << ifp.index << std::endl;

    int sock = getsock_recv(ifp.index);
    if (sock < 0) {
        std::cerr << "Ошибка создания сокета!" << std::endl;
        return -1;
    }

    unsigned char buffer[ETH_FRAME_LEN];
    struct ethhdr* eth;
    struct iphdr* iph;
    struct tcphdr* tcph;

    while (true) {
        int len = recv(sock, buffer, sizeof(buffer), 0);
        if (len <= 0) continue;

        eth = (struct ethhdr*)buffer;
        iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        if (iph->version != 4) continue;

        total_packets++;

        if (iph->protocol == IPPROTO_TCP) {
            tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iph->ihl*4);
            tcp_packets++;

            auto conn = std::make_pair(iph->saddr, tcph->source);
            active_connections[conn] = true;

            if (active_connections.size() > MAX_CONNECTIONS) {
                alert("Превышено количество TCP-соединений!");
            }
        }

        static auto last_time = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_time).count() >= 1) {
            float pps = total_packets;
            float mbps = (pps * ifp.mtu * 8) / 1e6;

            if (mbps > MAX_BANDWIDTH_MB) {
                alert("Превышена пропускная способность!");
            }
            if (pps > MAX_PACKETS_PER_SEC) {
                alert("Превышена частота пакетов!");
            }

            std::cout << "Пакетов/сек: " << pps << " | TCP: " << tcp_packets 
                      << " | Соединений: " << active_connections.size() << std::endl;

            total_packets = 0;
            tcp_packets = 0;
            active_connections.clear();
            last_time = now;
        }
    }

    close(sock);
    return 0;
}
