#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<time.h>

#define ETHER_ADDR_LEN 6

struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip
{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	#define IP_RF 0x8000
	#define IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src,ip_dst;
};

struct sniff_udp
{
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_len;
	u_short udp_sum;
};


struct sniff_tcp {
	u_short tcp_sport;				//source port
	u_short tcp_dport;				//destination port
	u_int th_seq;					//sequence number
	u_int th_ack;					//acknowledgement number
	u_char  th_offx2;				//data offset, rsvd
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;					//window
	u_short th_sum;					//checksum
	u_short th_urp;					//urgent pointer
};

/*
struct pcap_pkthdr { 
    struct timeval ts; // time stamp  
    bpf_u_int32 caplen; // length of portion present  
    bpf_u_int32 len; // length this packet (off wire)  
};
*/

pcap_t *handle = NULL;
const u_char *pktStr = NULL;
struct pcap_pkthdr *header = NULL;

int main(int argc,char** argv){

    char errbuf[PCAP_ERRBUF_SIZE]={0};
    const char *filename = argv[1];

    //打開檔案
    handle = pcap_open_offline(filename, errbuf);
    if(!handle){
        fprintf(stderr,"error :%s",errbuf);
        exit(1);
    }
    //printf("open %s\n",filename);

    //從cmd取得過濾條件
    char filter[128] = "";
    if(argc > 2) {
        int i;
        for(i=2;i<argc;i++){   
            strcat(filter,argv[i]);
            strcat(filter," ");
        }
    }
    printf("filter: %s\n",filter);

    //編譯過濾條件 這樣才可以使用
    struct bpf_program fcode;
    if(-1 == pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }

    //開始抓封包
    while(1){
        int ret = pcap_next_ex(handle, &header, &pktStr);

        //沒封包可以抓了跳出迴圈
        if(ret == -2){
            printf("No more packet from file\n");
            break;
        }
        else{

            //如果過濾後發現不合會回傳0
            if(pcap_offline_filter(&fcode, header, pktStr) == 0){
                printf("這個封包不合過濾條件\n");
                continue;
            }

            //ip的封包 長度20
            if( 0x0008 == ((struct sniff_ethernet*)(pktStr))->ether_type ){

                time_t local_tv_sec;
                struct tm *lt;
                char timestr[80];

                local_tv_sec = header->ts.tv_sec;
	            lt = localtime(&local_tv_sec);
	            strftime(timestr, sizeof(timestr), "%b %d %Y, %X", lt);

                printf("Time: %s\n", timestr);
                printf("len: %d bytes\n", header->len );

                // 14 bytes 是ethernet的header的長度
                printf("src address: %s\n",inet_ntoa( ((struct sniff_ip*)(pktStr+14))->ip_src ));
                printf("dst address: %s\n",inet_ntoa( ((struct sniff_ip*)(pktStr+14))->ip_dst ));

                //udp的封包處理
                if( 0x11==((struct sniff_ip*)(pktStr+14))->ip_p ){
                    
                    // 20 bytes 是ip封包的長度
                    printf("src port: %d\n",ntohs(((struct sniff_udp*)(pktStr+14+20))->udp_sport) );
                    printf("dst port: %d\n",ntohs(((struct sniff_udp*)(pktStr+14+20))->udp_dport) );
                    printf("protocal: UDP\n");
                }
                //tcp的封包處理
                else if( 0x06==((struct sniff_ip*)(pktStr+14))->ip_p ){
                    printf("src port: %d\n",ntohs(((struct sniff_tcp*)(pktStr+14+20))->tcp_sport) );
                    printf("dst port: %d\n",ntohs(((struct sniff_tcp*)(pktStr+14+20))->tcp_dport) );
                    printf("protocal: TCP\n");
                }
                //ICMP的封包處理
                else if( 0x01==((struct sniff_ip*)(pktStr+14))->ip_p ){
                    printf("protocal: ICMP\n");
                }
                //IP的封包處理
                else if( 0x04==((struct sniff_ip*)(pktStr+14))->ip_p ){
                    printf("protocal: IP\n");
                }
                else{
                    printf("protocal: 其他\n");
                }
            }//end 判斷是不是ip的if
            
            //不是ip的封包會執行這邊
            else{
                printf("不是IP封包的路過\n");
            }
        }
        printf("\n\n");
        
    }//end while
    return 0;
}