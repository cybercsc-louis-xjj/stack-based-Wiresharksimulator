#ifndef PHEADER_H_INCLUDED
#define PHEADER_H_INCLUDED
/*
*
*/
#define ETHER_ADDR_LEN 6 /* ethernet address */
#define ETHERTYPE_IP 0x0800 /* ip protocol */
#define TCP_PROTOCAL 0x0600 /* tcp protocol */
#define BUFFER_MAX_LENGTH 65536 /* buffer max length */
#define true 1  /* define true */
#define false 0 /* define false */

/*
* define struct of ethernet header , ip address , ip header and tcp header
*/
/* ethernet header */

typedef struct ether_header {
    u_char ether_shost[ETHER_ADDR_LEN]; /* source ethernet address, 8 bytes */
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet addresss, 8 bytes */
    u_short ether_type;                 /* ethernet type, 16 bytes */
}ether_header;

/* four bytes ip address */
typedef struct ip_address {
    u_char byte[4];
}ip_address;

/* ipv4 header */
typedef struct ip_header {
    u_char ver_ihl;         /* version and ip header length */
    u_char tos;             /* type of service */
    u_short tlen;           /* total length */
    u_short identification; /* identification */
    u_short flags_fo;       // flags and fragment offset
    u_char ttl;             /* time to live */
    u_char proto;           /* protocol */
    u_short crc;            /* header checksum */
    ip_address saddr;       /* source address */
    ip_address daddr;       /* destination address */
    u_int op_pad;           /* option and padding */
}ip_header;

/* tcp header */
typedef struct tcp_header {
    u_short th_sport;         /* source port */
    u_short th_dport;         /* destination port */
    u_int th_seq;             /* sequence number */
    u_int th_ack;             /* acknowledgement number */
    //u_short th_len_resv_code; /* datagram length and reserved code */
    u_char th_len;
    u_char flags;
    u_short th_window;        /* window */
    u_short th_sum;           /* checksum */
    u_short th_urp;           /* urgent pointer */
}tcp_header;

typedef struct tls_header{
    u_char tls_type;
    u_short tls_ver;
    u_short tls_hd_len;
}tls_header;

typedef struct tls_hs_hd{
    u_char hs_type;
    u_char hs_reserved;
    u_short hs_len;
    u_short hs_ver;
    u_char random[32];
}tls_hs_hd;

typedef struct ext_header{
    u_short ext_type;
    u_short ext_len;
}ext_hd;

typedef struct sni_header{
    u_short sni_ls_len;
    u_char sni_type;
    u_short sni_len;
    u_char sni[0];
}sni_hd;
typedef struct pdu_header{
    long payload_hd;//offset
    int payload_len;
    u_int seq;
    bool operator <(const pdu_header &other)const{
        return seq<other.seq;
    }
}pdu_hd;
#endif // PHEADER_H_INCLUDED
