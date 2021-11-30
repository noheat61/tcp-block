#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iso646.h>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"
using namespace std;

string block_message = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
Mac my_mac;

struct IpTcpHdr final
{
    EthHdr ethHdr_;
    IpHdr ipHdr_;
    TcpHdr tcpHdr_;
};

// strnstr 코드는 인터넷에서 복사함
char *strnstr(const char *big, const char *little, uint32_t len)
{
    uint32_t i;
    uint32_t temp;
    i = 0;
    while (big[i] && i < len)
    {
        temp = 0;
        if (little[temp] == big[i + temp])
        {
            while (little[temp] && big[i + temp])
            {
                if (little[temp] != big[i + temp] || (i + temp) >= len)
                    break;
                temp++;
            }
            if (little[temp] == '\0')
                return (&((char *)big)[i]);
        }
        i++;
    }
    return (NULL);
}

Mac get_my_MAC(const char *ifr)
{
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in *sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "Fail to get interface IP address - socket() failed\n");
        exit(-1);
    }
    strcpy(ifrq.ifr_name, ifr);

    // get_mac
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifrq) < 0)
    {
        perror("ioctl() SIOCGIFHWADDR error");
        exit(-1);
    }
    Mac mac_tmp;
    memcpy(&mac_tmp, ifrq.ifr_hwaddr.sa_data, Mac::SIZE);
    return mac_tmp;
}
bool check_packet(IpTcpHdr *packet, const char *pattern, int len)
{
    if (ntohs(packet->ethHdr_.type_) not_eq EthHdr::Ip4)
        return false;
    if (packet->ipHdr_.ip_protocol not_eq IpHdr::Tcp)
        return false;

    int header_len = sizeof(EthHdr) + packet->ipHdr_.hdr_len * 4 + packet->tcpHdr_.offset() * 4;
    int payload_len = len - header_len;
    const char *payload = (const char *)packet + header_len;

    if (strnstr(payload, pattern, payload_len) == NULL)
        return false;
    return true;
}

uint16_t ipchecksum(IpHdr *packet)
{
    uint32_t checksum = 0;
    uint16_t *cur = (uint16_t *)packet;

    for (int i = 0; i < sizeof(IpHdr) / 2; i++)
        checksum += (uint32_t)ntohs(*cur++);

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    return ~(uint16_t)checksum;
}
uint16_t tcpchecksum(IpHdr *ip, TcpHdr *tcp)
{
    uint32_t checksum = 0;

    // pseudo header
    uint32_t sip = ntohl(ip->sip_);
    checksum += ((sip & 0xFFFF0000) >> 16) + (sip & 0x0000FFFF);
    uint32_t tip = ntohl(ip->tip_);
    checksum += ((tip & 0xFFFF0000) >> 16) + (tip & 0x0000FFFF);
    checksum += (uint32_t)ip->ip_protocol;
    uint32_t tcp_len = (uint32_t)ntohs(ip->total_len) - (uint32_t)ip->hdr_len * 4;
    checksum += tcp_len;

    // tcp header
    uint16_t *cur = (uint16_t *)tcp;
    for (int i = 0; i < tcp_len / 2; i++)
        checksum += (uint32_t)ntohs(*cur++);

    if (tcp_len % 2) //홀수일 때 처리
        checksum += (uint32_t)(*(uint8_t *)cur) << 8;

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    return ~(uint16_t)checksum;
}

void send_forward(pcap_t *handle, IpTcpHdr *original, uint32_t header_len)
{
    IpTcpHdr *packet = (IpTcpHdr *)malloc(header_len);
    memcpy(packet, original, header_len);

    // original packet에서 변경된 점만 수정
    // Ethernet
    packet->ethHdr_.smac_ = my_mac;

    // ip
    packet->ipHdr_.total_len = htons((uint16_t)sizeof(IpHdr) + (uint16_t)sizeof(TcpHdr));
    packet->ipHdr_.ip_checksum = 0;
    packet->ipHdr_.ip_checksum = htons(ipchecksum(&packet->ipHdr_));

    // tcp
    packet->tcpHdr_.offset_reserved = (sizeof(TcpHdr) >> 2) << 4;
    packet->tcpHdr_.flags = TcpHdr::Rst | TcpHdr::Ack;
    uint32_t data_len = (uint32_t)ntohl(original->ipHdr_.total_len) - (uint32_t)original->ipHdr_.hdr_len * 4 - (uint32_t)original->tcpHdr_.offset() * 4;
    packet->tcpHdr_.seq = htonl(ntohl(original->tcpHdr_.seq) + data_len);

    packet->tcpHdr_.checksum = 0;
    packet->tcpHdr_.checksum = htons(tcpchecksum(&packet->ipHdr_, &packet->tcpHdr_));

    // send
    int res = pcap_sendpacket(handle, (const u_char *)packet, header_len);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
    free(packet);
}
void send_backward(pcap_t *handle, IpTcpHdr *original, uint32_t header_len)
{
    IpTcpHdr *packet = (IpTcpHdr *)malloc(header_len + block_message.size() + 1);
    memcpy(packet, original, header_len);

    // original packet에서 변경된 점만 수정
    // Ethernet
    packet->ethHdr_.smac_ = my_mac;
    packet->ethHdr_.dmac_ = original->ethHdr_.smac_;

    // ip
    packet->ipHdr_.total_len = htons((uint16_t)sizeof(IpHdr) + (uint16_t)sizeof(TcpHdr) + (uint16_t)block_message.size());
    packet->ipHdr_.ip_ttl = 128;
    packet->ipHdr_.sip_ = original->ipHdr_.tip_;
    packet->ipHdr_.tip_ = original->ipHdr_.sip_;
    packet->ipHdr_.ip_checksum = 0;
    packet->ipHdr_.ip_checksum = htons(ipchecksum(&packet->ipHdr_));

    // tcp
    packet->tcpHdr_.sport_ = original->tcpHdr_.dport_;
    packet->tcpHdr_.dport_ = original->tcpHdr_.sport_;
    packet->tcpHdr_.offset_reserved = ((uint8_t)sizeof(TcpHdr) >> 2) << 4;
    packet->tcpHdr_.flags = TcpHdr::Fin | TcpHdr::Ack;
    uint32_t data_len = (uint32_t)ntohl(original->ipHdr_.total_len) - (uint32_t)original->ipHdr_.hdr_len * 4 - (uint32_t)original->tcpHdr_.offset() * 4;
    packet->tcpHdr_.seq = original->tcpHdr_.ack;
    packet->tcpHdr_.ack = htonl(ntohl(original->tcpHdr_.seq) + data_len);

    packet->tcpHdr_.checksum = 0;
    packet->tcpHdr_.checksum = htons(tcpchecksum(&packet->ipHdr_, &packet->tcpHdr_));

    // payload
    strcpy((char *)packet + header_len, block_message.c_str());

    // send
    int res = pcap_sendpacket(handle, (const u_char *)packet, header_len + block_message.size() + 1);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
    free(packet);
}

int main(int argc, char *argv[])
{
    //매개변수 확인(3개여야 함)
    if (argc not_eq 3)
    {
        printf("syntax : tcp-block <interface> <pattern>\n");
        printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
        return -1;
    }

    // pcap_open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }

    // attacker(me)의 mac 주소 알아내기
    my_mac = get_my_MAC(argv[1]);
    // printf("attacker_mac: %s\n", string(my_mac).c_str());

    while (1)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        // reply 수신
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        // match 확인
        IpTcpHdr *Tcppacket = (IpTcpHdr *)packet;
        if (not check_packet(Tcppacket, argv[2], header->caplen))
            continue;
        printf("matched!\n");

        // packet 만들고 송신
        int header_len = sizeof(EthHdr) + Tcppacket->ipHdr_.hdr_len * 4 + Tcppacket->tcpHdr_.offset() * 4;
        send_forward(handle, Tcppacket, header_len);
        send_backward(handle, Tcppacket, header_len);
    }

    pcap_close(handle);
    return 0;
}