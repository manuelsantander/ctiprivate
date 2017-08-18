
#define APP_NAME		"modbuscti"
#define APP_DESC		"Modbus CTI program using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2017 Escuela Superior de Guerra"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct regis {
	struct in_addr ip_addr;
	char permission;
};


struct hmi_list {
	struct in_addr hmiaddr;
	u_char ether_shost[ETHER_ADDR_LEN];
	char permission;
	u_short count;
	u_short wrabnormal;
	struct hmi_list *next;
};
struct hmi_list *initial=NULL,*current;
struct hmi_list *rinitial=NULL,*rcurrent,*rtemp;


/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
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
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

u_char *print_ether(u_char *ether_shost){
    static u_char final[2000]="\0";
    sprintf(final,"%02X:%02X:%02X:%02X:%02X:%02X",
    ether_shost[0],
    ether_shost[1],
    ether_shost[2],
    ether_shost[3],
    ether_shost[4],
    ether_shost[5]);
    return final;
};


/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}


void writeregcount(u_short temp)
{
    if (initial->hmiaddr.s_addr == temp){
        initial->wrabnormal++;
        printf("Escribi wabnormal %i\n",initial->wrabnormal);
    }

    else if (initial->next->hmiaddr.s_addr == temp){
            initial->next->wrabnormal++;
            printf("Escribi wabnormal %i\n",initial->next->wrabnormal);
    }
}


int readonly(u_short temp)
{
    if (initial->hmiaddr.s_addr == temp){
       if (initial->permission == 'w'){
        return 0;
       }
    } else {
            if (initial->next->hmiaddr.s_addr == temp){
                if (initial->next->permission == 'w') {
                return 0;
                }
            }
    }
    if (initial->hmiaddr.s_addr == temp) {
        if (initial->permission == 'r') {
            return 1;
        }
    } else {
            if (initial->next->hmiaddr.s_addr == temp){
                if (initial->next->permission == 'r') {
                return 1;
                }
            }
        }
    return 0;
}



void print_page()
{
    char temp[100]="\0";
    FILE *fp=fopen("/var/www/html/index.html","w+");
    fputs("<html>\n<head>\n<meta http-equiv=\"refresh\" content=\"5\">\n<title> Modbus CTI sensor </title>\n</head>\n<body>\n<p><b>Main configuration data: </b></p>\n<table border=1>\n",fp);
    fputs("<tr><th>HMI IP Address</th><th>Privilege</th><th>Ethernet address</th><th>Packet count</th><th>Write operations</th></tr>\n",fp);
    fputs("<tr><td>",fp);
    if (initial->permission == 'w'){
        fputs(inet_ntoa(initial->hmiaddr),fp);
        fputs("</td><td>RW</td><td>",fp);
    }
    else {
        if (initial->permission == 'r'){
            fputs(inet_ntoa(initial->hmiaddr),fp);
            fputs("</td><td>RO</td><td>",fp);
        }
    }
    fputs(print_ether(initial->ether_shost),fp);
    fputs("</td><td>",fp);
    sprintf(temp,"%d",initial->count);
    fputs(temp,fp);
    bzero(temp,100);
    fputs("</td><td>",fp);
    if (initial->permission == 'r'){
        fputs("0</td></tr>\n",fp);
    } else {
        if (initial->permission == 'w'){
            sprintf(temp,"%d",initial->wrabnormal);
            fputs(temp,fp);
            bzero(temp,100);
            fputs("</td></tr>\n",fp);
        }
    }
    fputs("<tr><td>",fp);
    if (initial->next->permission == 'w'){
        fputs(inet_ntoa(initial->next->hmiaddr),fp);
        fputs("</td><td>RW</td><td>",fp);
    }
    else {
        if (initial->next->permission == 'r'){
            fputs(inet_ntoa(initial->next->hmiaddr),fp);
            fputs("</td><td>RO</td><td>",fp);
        }
    }
    fputs(print_ether(initial->next->ether_shost),fp);
    fputs("</td><td>",fp);
    sprintf(temp,"%d",initial->next->count);
    fputs(temp,fp);
    bzero(temp,100);
    fputs("</td><td>",fp);
    if (initial->next->permission == 'r'){
        fputs("0</td></tr>\n",fp);
    } else {
        if (initial->next->permission == 'w'){
            sprintf(temp,"%d",initial->next->wrabnormal);
            fputs(temp,fp);
            bzero(temp,100);
            fputs("</td></tr>\n",fp);
        }
    }
    fputs("</table>\n<p><b>Rogue HMI Detected:</b></p>\n<table border=1>\n",fp);
    fputs("<tr><th>Rogue HMI IP Address</th><th>Ethernet address</th><th>Packet count</th></tr>\n",fp);
    rcurrent=rinitial;
    if (rcurrent != NULL){
        while (rcurrent != NULL){
            fputs("<tr><td>",fp);
            fputs(inet_ntoa(rcurrent->hmiaddr),fp);
            fputs("</td><td>",fp);
            fputs(print_ether(rcurrent->ether_shost),fp);
            fputs("</td><td>",fp);
            sprintf(temp,"%d",rcurrent->count);
            fputs(temp,fp);
            bzero(temp,100);
            fputs("</td></tr>",fp);
            rcurrent=rcurrent->next;
        }
    } else printf("rcurrent es nulo para escribir\n");
    fputs("</table>\n</body>\n</html>\n",fp);
    fclose(fp);
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    struct hmi_list *rsearch;

	static int count = 1;                   /* packet counter */
    int executed=0;

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if ((int)tcp->th_flags==2){
        if (initial->hmiaddr.s_addr==ip->ip_src.s_addr){
            initial->count++;
        } else if (initial->next->hmiaddr.s_addr==ip->ip_src.s_addr){
            initial->next->count++;
        }

            if ((initial->hmiaddr.s_addr!=ip->ip_src.s_addr)||(initial->next->hmiaddr.s_addr!=ip->ip_src.s_addr)){
                if (rinitial == NULL){
                    rinitial=malloc(sizeof (struct hmi_list));
                    rinitial->count=0;
                    rcurrent=rinitial;
                } else {
                    rtemp=malloc(sizeof(struct hmi_list));
                    rtemp->count=0;
                    if (rcurrent == NULL) rcurrent=rinitial;
                    rcurrent->next=rtemp;
                    rcurrent=rtemp;
                }
                rcurrent->hmiaddr.s_addr=ip->ip_src.s_addr;
                bcopy(ethernet->ether_shost, rcurrent->ether_shost,ETHER_ADDR_LEN);
                rcurrent->count++;
                rcurrent->next=NULL;
            }

    }

    if ((int)payload[7]==1){
        if (initial->hmiaddr.s_addr==ip->ip_src.s_addr){
                initial->count++;
            } else {
                if (initial->next->hmiaddr.s_addr==ip->ip_src.s_addr){
                    initial->next->count++;
                }
                if (ntohs(tcp->th_sport) != 502){
                    printf("No soy lectura puerto fuente 502\n");
                    if ((initial->hmiaddr.s_addr!=ip->ip_src.s_addr)||(initial->next->hmiaddr.s_addr!=ip->ip_src.s_addr)){
                        printf("No estoy en la lista de validos\n");
                        if (rinitial == NULL){
                            printf("Acabo de crear inicial rogue lectura\n");
                            rinitial=malloc(sizeof (struct hmi_list));
                            rcurrent=rinitial;
                            rcurrent->hmiaddr.s_addr=ip->ip_src.s_addr;
                            bcopy(ethernet->ether_shost, rcurrent->ether_shost,ETHER_ADDR_LEN);
                            rcurrent->count++;
                            rcurrent->next=NULL;
                        } else {
                            rsearch=rinitial;
                            while (rsearch != NULL){
                                printf("Estoy buscando desde el inicial rogue lectura\n");
                                if (rsearch->hmiaddr.s_addr == ip->ip_src.s_addr){
                                    executed=1;
                                    rsearch->count++;
                                    rsearch=NULL;
                                } else rsearch=rsearch->next;
                            }
                            if (executed == 0){
                                rtemp=malloc(sizeof(struct hmi_list));
                                rtemp->count=0;
                                rcurrent->next=rtemp;
                                rcurrent=rtemp;
                                rcurrent->hmiaddr.s_addr=ip->ip_src.s_addr;
                                bcopy(ethernet->ether_shost, rcurrent->ether_shost,ETHER_ADDR_LEN);
                                rcurrent->count++;
                                rcurrent->next=NULL;
                            } else printf("Lo encontre y lo aumente\n");
                        }

                    }
                }
        }
    }

    if ((int)payload[7]==15){
        printf("Soy paquete de escritura\n");
        if (ntohs(tcp->th_sport) != 502){
            if ((initial->hmiaddr.s_addr == ip->ip_src.s_addr) || (initial->next->hmiaddr.s_addr == ip->ip_src.s_addr)){
                if (!readonly(ip->ip_src.s_addr)){
                    if (initial->permission == 'w'){
                        initial->wrabnormal++;
                    } else initial->next->wrabnormal++;
                }
            } else if (rinitial == NULL){
                            rinitial=malloc(sizeof (struct hmi_list));
                            rcurrent=rinitial;
                            rcurrent->hmiaddr.s_addr=ip->ip_src.s_addr;
                            bcopy(ethernet->ether_shost, rcurrent->ether_shost,ETHER_ADDR_LEN);
                            rcurrent->count++;
                            rcurrent->next=NULL;
                        } else {
                            rsearch=rinitial;
                            executed=0;
                            while (rsearch != NULL){
                                if (rsearch->hmiaddr.s_addr == ip->ip_src.s_addr){
                                    executed=1;
                                    rsearch->count++;
                                    rsearch=NULL;
                                } else rsearch=rsearch->next;
                            }
                            if (executed == 0){
                                rtemp=malloc(sizeof(struct hmi_list));
                                rtemp->count=0;
                                rcurrent->next=rtemp;
                                rcurrent=rtemp;
                                rcurrent->hmiaddr.s_addr=ip->ip_src.s_addr;
                                bcopy(ethernet->ether_shost, rcurrent->ether_shost,ETHER_ADDR_LEN);
                                rcurrent->count++;
                                rcurrent->next=NULL;
                            }
                }

        }
        }




print_page();
return;
}

void populate_servers()
{
    struct regis registro;
    FILE *fp=fopen("permissions.dat","rb");
    if (!fp){
        perror("fopen");
        exit(-1);
    }
    initial=malloc(sizeof(struct hmi_list));
    current=initial;
    current->next=malloc(sizeof(struct hmi_list));
    current->next->next=NULL;
    fread(&registro,sizeof(registro),1,fp);
	current->hmiaddr.s_addr=registro.ip_addr.s_addr;
	current->count=0;
	current->next->count=0;
	current->permission=registro.permission;
    fread(&registro,sizeof(registro),1,fp);
	current->next->hmiaddr.s_addr=registro.ip_addr.s_addr;
	current->next->permission=registro.permission;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp and port 502";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
    populate_servers();
	/* now we can set our callback function */
	while (1) pcap_loop(handle, 1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

