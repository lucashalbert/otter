/* adapted from p0f v 1.8.3 and sniffex.c */
#include <sys/types.h>

#define	TCPOPT_EOL		0
#define	TCPOPT_NOP		1
#define	TCPOPT_MAXSEG		2
#define TCPOPT_WSCALE   	3
#define TCPOPT_SACKOK   	4
#define TCPOPT_TIMESTAMP        8

#define EXTRACT_16BITS(p) \
        ((u16)*((u8 *)(p) + 0) << 8 | \
        (u16)*((u8 *)(p) + 1))
#define GET16(p) \
        ((u16)*((u8 *)(p) + 0) << 8 | \
        (u16)*((u8 *)(p) + 1))

#define IP_DF   0x4000	/* dont fragment flag */
#define IP_MF   0x2000	/* more fragments flag */

#define IP_VER4           0x04

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
/* Stupid ECN flags: */
#define TH_ECE  0x40
#define TH_CWR  0x80

#define MAXOPT   	16

typedef u_int8_t u8;
typedef u_int16_t u16;
typedef u_int32_t u32;

/* ARP Header, (assuming Ethernet+IPv4)            */ 
//#define ARP_REQUEST 1   /* ARP Request             */ 
//#define ARP_REPLY 2     /* ARP Reply               */ 
//struct arphdr { 
//    u_int16_t htype;    /* Hardware Type           */ 
//    u_int16_t ptype;    /* Protocol Type           */ 
//    u8 hlen;        /* Hardware Address Length */ 
//    u8 plen;        /* Protocol Address Length */ 
//    u_int16_t oper;     /* Operation Code          */ 
//    u8 sha[6];      /* Sender hardware address */ 
//    u8 spa[4];      /* Sender IP address       */ 
//    u8 tha[6];      /* Target hardware address */ 
//    u8 tpa[4];      /* Target IP address       */ 
//};

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6 
struct ethhdr{
        u8  dhost[ETHER_ADDR_LEN];    /* destination host address */
        u8  shost[ETHER_ADDR_LEN];    /* source host address */
        u16 type;                     /* IP? ARP? RARP? etc */
};
// This might change with q-tags (vlans)
#define SIZE_ETHERNET 14

struct iphdr {
  u8  ihl;
  u8  tos;		/* type of service */
  u16 tot_len;		/* total length */
  u16 id;		/* identification */
  u16 off;		/* fragment offset field */
  u8  ttl;		/* time to live */
  u8  protocol;		/* protocol */
  u16 check;		/* checksum */
  u8  saddr[4]; 
  u8  daddr[4];         /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ihl) & 0x0f)

#define SIZE_TCP 20
struct tcphdr {
	u16	sport;			/* source port */
	u16	dport;			/* destination port */
	u32	seq;			/* sequence number */
	u32	ack;			/* acknowledgement number */
	u8	x2:4, doff:4;
	u8	flags;
	u16	win;			/* window */
	u16	cksum;			/* checksum */
	u16	urp;			/* urgent pointer */
};

#define MAX_TCP_OPT 24

struct fprint {
   u8  ipver;				// IP Version
   u8  ittl;				// Initial TimeToLive
   u8  olen;				// Length of IP options
   u16 tot;				// total length
   u16 mss;				// Maximum Segment Size (TCP)
   u16 wsize;				// Window Size (TCP)
   u8  scale;				// Window Scaling Factor (TCP)
   u8  olayout[MAX_TCP_OPT];		// TCP Option Layout
   u32 quirks;				// Assorted Quirks
   u32 tstamp;
};

#define MOD_NONE	0
#define MOD_CONST	1
#define MOD_MSS		2
#define MOD_MTU		3

#define QUIRK_PAST      0x00000001 /* P */
#define QUIRK_ZEROID	0x00000002 /* Z */
#define QUIRK_IPOPT	0x00000004 /* I */
#define QUIRK_URG	0x00000008 /* U */ 
#define QUIRK_X2	0x00000010 /* X */ 
#define QUIRK_ACK	0x00000020 /* A */ 
#define QUIRK_T2	0x00000040 /* T */
#define QUIRK_FLAGS	0x00000080 /* F */
#define QUIRK_DATA	0x00000100 /* D */
#define QUIRK_BROKEN	0x00000200 /* ! */
#define QUIRK_RSTACK	0x00000400 /* K */
#define QUIRK_SEQEQ	0x00000800 /* Q */
#define QUIRK_SEQ0      0x00001000 /* 0 */
