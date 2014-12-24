/*
Name: otter.c
Description: Passive OS filtering and IDS system
Authors: Paul Brennan
         Lucas Halbert
Adapted from p0f v 0.8.4
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/types.h>
//#include <netinet/in.h>
#include <pcap.h>
//#include <arpa/inet.h>
//#include <signal.h>
//#include <unistd.h>
#include <time.h>
#include <sqlite3.h>
//only special lib
//don't forget to include the otter
#include "otter.h"
#define MAXFPS 5000
#define FPBUF  150
#define INBUF  1024
#define TTLDW  30

#ifndef VER
#  define VER "(?)"
#endif /* !VER */

// I added these!!!
#define CAPB 150
#define PROMISC 1
#define Q_SIZE = 250
char *db=NULL, *script=NULL;	//global variables
int timer=30;

void parser(u_char *opts, const struct pcap_pkthdr *header, const u_char *packet);
int sql_query(char host_ip[20], char host_mac[20], int packet_type, char fingerprint[40]);
//void die_nicely();

int main(int argc, char *argv[]) { //arguments are for later...
   pcap_t *pstream; // packet stream
   char *intface = NULL; // capturing interface, db_file, and pcap_filter
   char errbuf[PCAP_ERRBUF_SIZE]; // error buffer

   bpf_u_int32 mask;            // subnet mask
   bpf_u_int32 net;            // ip
   int netnum, num_options;

   /**********   Options & arguments   **********/
   if(argc <= 1) 
      printf("Setting Defaults\n");
   else {
      for(num_options=1; num_options < argc; num_options++) {
	     if(strcmp(argv[num_options],"-d")==0) {
		    if(argv[num_options+1]==NULL) {
			   printf("empty option -d\n");
			   return -1;
			}
			else {
			   //printf("argv[%d] = %s\n",num_options, argv[num_options+1]);
			   db=strdup(argv[num_options+1]);
			   printf("DB: %s\n",db);
			}
		 }
		 else if(strcmp(argv[num_options],"-s")==0) {
		    if(argv[num_options+1]==NULL) {
			   printf("Empty Option: -s\n");
			   return -1;
			}
			else {
			   //printf("argv[%d] = %s\n",num_options, argv[num_options+1]);
			   script=strdup(argv[num_options+1]);
			   printf("Script: %s\n",script);
			}
		 }
                 else if(strcmp(argv[num_options],"-t")==0) {
		    if(argv[num_options+1]==NULL) {
	               printf("Empty Option: -t\n");
	               return -1;
		    }
		    else {
	               timer=atoi(argv[num_options+1]);
	               printf("Script Timer: %d\n",timer);
	            }
	         }
		 else if(strcmp(argv[num_options],"-i")==0) {
		    if(argv[num_options+1]==NULL) {
		       printf("empty option -i\n");
	               return -1;
	            }
	            else {
	               intface=strdup(argv[num_options+1]);
	               printf("Interface: %s\n",intface);
	            }
		 }
		 else if(strcmp(argv[num_options],"-h")==0) {
			printf("Usage: -d \"db file\" -i \"interface\" -s \"script\" -t \"timer\" -h \"help\"\n\n");
			return 0;
		 }
	  }
   }

   
/*  
   signal(SIGINT,&die_nicely);
   signal(SIGTERM,&die_nicely);
*/
   // find us an interface
   if (intface== NULL)
      intface = pcap_lookupdev(errbuf);
   if (intface== NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      fprintf(stderr, "I guess we'll just capture on all interfaces then!\n");
      return -1;
   }
   if (db == NULL)
      db="/var/db/otterdb.sqlite3";
   if (script == NULL)
      script="./run_me.sh";
/*
   not a bad idea
   if (!intface) intface=pcap_lookupdev(errbuf);
   if (!intface) { intface="lo"; }
*/

/* get network number and mask associated with capture device */
   if (pcap_lookupnet(intface, &net, &mask, errbuf) == -1) {
      fprintf(stderr, "Couldn't get netmask for device %s: %s\n", intface, errbuf);
      net = 0;
      mask = 0;
   }
   u8 ipnet[4];
   //form readable ip address
   netnum=ntohl(net);
   ipnet[3]=(u8)netnum;
   ipnet[2]=(u8)(netnum>>8);
   ipnet[1]=(u8)(netnum>>16);
   ipnet[0]=(u8)(netnum>>24);
   //count mask bits set
   for(netnum=0; mask; mask >>=1)
      netnum += mask & 1;
   char filts[60];
   sprintf(filts, "tcp[tcpflags] & tcp-syn != 0 and src net %d.%d.%d.%d/%d", ipnet[0], ipnet[1], ipnet[2], ipnet[3], netnum);
   printf("pcap filter: %s\n", filts);
   struct bpf_program filtp;   // compiled filter

   //open packet stream from interface, # bytes to capture per packet, promiscous?
   //wait 100ms before sending to errbuf 
   if ((pstream=pcap_open_live(intface, CAPB, PROMISC, 100, errbuf))==NULL) {
      fprintf(stderr, "OH NOES! Stream failed to open: %s\n", errbuf);
      exit(1);
   }

   // make the filter
   if (pcap_compile(pstream, &filtp, filts, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filts, pcap_geterr(pstream));
      exit(1);
   }

   // apply the filter
   if (pcap_setfilter(pstream, &filtp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n", filts, pcap_geterr(pstream));
      exit(1);
   }

   // send pstream to parser, never end (-1), no options (NULL)
   pcap_loop(pstream, -1, &parser, NULL); 
   //for completeness
   return 0;
}

void parser(u_char *opts, const struct pcap_pkthdr *header, const u_char *packet)
{
   const struct ethhdr *ethernet;
   const struct iphdr *internet;
   const struct tcphdr *tranctl;

   int size_ip;
   int i;
   struct fprint fp;
   u32 *ip_opts;

// line up all the pointers to the packet's fields
   ethernet = (struct ethhdr*)(packet);
// We'll probably need something to account for q-tags
   internet = (struct iphrd*)(packet + SIZE_ETHERNET);
   size_ip = IP_HL(internet);
   if (size_ip < 5) { 
      fprintf(stderr, "Short IP head lenght: %u bytes\n", size_ip*4); 
   }
   tranctl  = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip*4);

/***********  finger printing attempt  ***********/
   fp.ipver = IP_VER4;
   fp.ittl = internet->ttl;
   fp.olen = (size_ip*4) - 20;
   fp.wsize = ntohs(tranctl->win);
   fp.tot = ntohs(internet->tot_len);
   //fp.wsize = tranctl->win;
   fp.mss = 0;
   fp.quirks = 0;

// Quirk Counter
   if (size_ip > 5) fp.quirks |= QUIRK_IPOPT;
   if (tranctl->seq == tranctl->ack) fp.quirks |= QUIRK_SEQEQ;
   if (tranctl->flags & ~(TH_SYN|TH_ACK|TH_RST|TH_ECE|TH_CWR)) fp.quirks |= QUIRK_FLAGS;

   u32 ilen;
   u8* opt_ptr;
   u8* end_ptr = header->len + packet;
   int opcount = 0;
   u8  bork = 0;
   ilen=((tranctl->doff) << 2) - SIZE_TCP;    //sizeof(tranctl); 
   
   opt_ptr = (u8*)(tranctl+1);
   while (ilen >0) {
      ilen--;
      switch (*(opt_ptr++)){
         case TCPOPT_EOL:
            //End Of opt List
            fp.olayout[opcount] = TCPOPT_EOL;
            opcount++;
            if (ilen) fp.quirks |= QUIRK_PAST;
            ilen = 0;
            break;
         case TCPOPT_NOP:
            fp.olayout[opcount] = TCPOPT_NOP;
            opcount++;
            break;
         case TCPOPT_SACKOK: 
            fp.olayout[opcount] = TCPOPT_SACKOK;
            opcount++; ilen--; opt_ptr++;
            break;
         case TCPOPT_MAXSEG: 
            if (opt_ptr + 3 > end_ptr) { bork=1; ilen=0;}
            else {
               fp.olayout[opcount] = TCPOPT_MAXSEG;
               fp.mss = GET16(opt_ptr+1);
               opcount++; ilen -= 3; opt_ptr +=3;
            }
            break;
         case TCPOPT_WSCALE: 
            if (opt_ptr + 2 > end_ptr) { bork=1; ilen=0;}
            else{
               fp.olayout[opcount] = TCPOPT_WSCALE;
               fp.scale = *(u8 *)(opt_ptr+1);
               opcount++; ilen -= 2; opt_ptr +=2;
            }
            break;
         case TCPOPT_TIMESTAMP:
            if (opt_ptr + 9 > end_ptr) { bork=1; ilen=0; }
            else{
            fp.olayout[opcount] = TCPOPT_TIMESTAMP;
            memcpy(&fp.tstamp, opt_ptr+5, 4);
            if (fp.tstamp) fp.quirks |= QUIRK_T2;
     
            memcpy(&fp.tstamp, opt_ptr+1, 4);
            fp.tstamp = ntohl(fp.tstamp);
            opcount++; ilen -= 9; opt_ptr +=9;
            }
            break;
         default:
            if (opt_ptr + 1 > end_ptr) { bork=1; ilen=0; }
            fp.olayout[opcount] = *(opt_ptr-1);
            fp.olen = (int)(*opt_ptr-1);
            if (fp.olen > 32 || (fp.olen<0)) { bork=1; ilen=0; }
                opcount++; ilen -= fp.olen; opt_ptr += fp.olen;
            break;
      }
      if (opcount > MAXOPT) { bork=1; ilen=0; }
      if (ilen > 0 && opt_ptr >= end_ptr) { bork=1; ilen=0;}
   }
   if (bork) fp.quirks |= QUIRK_BROKEN;
   if (tranctl->ack) fp.quirks |= QUIRK_ACK;
   if (tranctl->urp) fp.quirks |= QUIRK_URG;
   //if (tcph->_x2) fp.quirks |= QUIRK_X2;
   if (!internet->id)  fp.quirks |= QUIRK_ZEROID;

   
   
   // convert ip and mac to type string
   char dhost_mac[20], shost_mac[20], dhost_ip[20], shost_ip[20], fingerprint[50];
   int packet_type=0;    //0=syn packet 1=ack packet

   if (fp.mss && fp.wsize && !(fp.wsize % fp.mss)) {
      sprintf(fingerprint, "S%d",fp.wsize/fp.mss);
   } else if (fp.wsize && !(fp.wsize % 1460)) {
      sprintf(fingerprint, "S%d",fp.wsize/1460);
   } else if (fp.mss && fp.wsize && !(fp.wsize % (fp.mss+40))) {
      sprintf(fingerprint, "T%d", fp.wsize/(fp.mss+40));
   } else if (fp.wsize && !(fp.wsize % 1500)) {
      sprintf(fingerprint, "T%d", fp.wsize/1500);
   } else if (fp.wsize == 12345) {
      sprintf(fingerprint, "*(12345)");
   } else {
      sprintf(fingerprint, "%d", fp.wsize);
   }

   u8 df;
   df=((ntohs(internet->off) & IP_DF) != 0);
   sprintf(fingerprint + strlen(fingerprint), ":%d:%d:%d:", fp.ittl,df,fp.tot);
   int d=0;
   
   for (i=0;i<opcount;i++) {
      switch (fp.olayout[i]) {
         case TCPOPT_NOP: sprintf(fingerprint + strlen(fingerprint), "N"); d=1; break;
         case TCPOPT_WSCALE: sprintf(fingerprint + strlen(fingerprint), "W%d", fp.scale); d=1; break;
         case TCPOPT_MAXSEG: sprintf(fingerprint + strlen(fingerprint), "M%d", fp.mss); d=1; break;
         case TCPOPT_TIMESTAMP: sprintf(fingerprint + strlen(fingerprint), "T");
            if (!fp.tstamp) { sprintf(fingerprint + strlen(fingerprint), "0"); d=1; }
            break; 
         case TCPOPT_SACKOK: sprintf(fingerprint + strlen(fingerprint), "S"); d=1; break;
         case TCPOPT_EOL: sprintf(fingerprint + strlen(fingerprint), "E"); d=1; break;
         default: sprintf(fingerprint + strlen(fingerprint), "?%d", fp.olayout[i]); d=0; break;
      }
      if (i != opcount-1) { sprintf(fingerprint + strlen(fingerprint), ","); }
   }
   if (!d) { sprintf(fingerprint + strlen(fingerprint), "."); }
   sprintf(fingerprint + strlen(fingerprint), ":");
   if (!fp.quirks) { sprintf(fingerprint + strlen(fingerprint), "."); }
   else {
      if (fp.quirks & QUIRK_RSTACK) { sprintf(fingerprint + strlen(fingerprint), "K"); }
      if (fp.quirks & QUIRK_SEQEQ) { sprintf(fingerprint + strlen(fingerprint), "Q"); }
      if (fp.quirks & QUIRK_SEQ0) { sprintf(fingerprint + strlen(fingerprint), "0"); }
      if (fp.quirks & QUIRK_PAST) { sprintf(fingerprint + strlen(fingerprint), "P"); }
      if (fp.quirks & QUIRK_ZEROID) { sprintf(fingerprint + strlen(fingerprint), "Z"); }
      if (fp.quirks & QUIRK_IPOPT) { sprintf(fingerprint + strlen(fingerprint), "I"); }
      if (fp.quirks & QUIRK_URG) { sprintf(fingerprint + strlen(fingerprint), "U"); }
      if (fp.quirks & QUIRK_X2) { sprintf(fingerprint + strlen(fingerprint), "X"); }
      if (fp.quirks & QUIRK_ACK) { sprintf(fingerprint + strlen(fingerprint), "A"); packet_type=1; }
      if (fp.quirks & QUIRK_T2) { sprintf(fingerprint + strlen(fingerprint), "T"); }
      if (fp.quirks & QUIRK_FLAGS) { sprintf(fingerprint + strlen(fingerprint), "F"); }
      if (fp.quirks & QUIRK_DATA) { sprintf(fingerprint + strlen(fingerprint), "D"); }
      if (fp.quirks & QUIRK_BROKEN) { sprintf(fingerprint + strlen(fingerprint), "!"); }
   }

/*************  Header Printer ****************/
   // Ethernet header
   /*
   printf("Ethernet:\n| ");
   for(i=0; i<5; i++)
       printf("%02X:",ethernet->dhost[i]);
   printf("%02X | ",ethernet->dhost[i]);

   for(i=0; i<5; i++)
       printf("%02X:",ethernet->shost[i]);
   printf("%02X | ",ethernet->shost[i]);
   printf("%04X |\n", htons(ethernet->type));
      
   // IP header
   printf("IP:\n|");
   printf(" %03d |", size_ip*4);    // 8b    8b
   printf(" %02X |", internet->tos);        // 8b    16b
   printf(" %05d |\n| ", htons(internet->tot_len));    // 16b    32b
   printf(" %05d  |", htons(internet->id));        //16b    16b
   printf(" %o %04d |\n|", htons(internet->off)>>13, htons(internet->off) & 0xFFF);//16b 32c
   printf(" %03d |", internet->ttl);        // 8b
   printf(" %02X |", internet->protocol);    // 8b  16b
   printf("  %04X |\n|  ", htons(internet->check));        // 16b 32b

   for(i=0; i<3; i++)
      printf("%d.",internet->saddr[i]);
   printf("%d  |\n|  ", internet->saddr[i]);

   for(i=0; i<3; i++)
      printf("%d.",internet->daddr[i]);
   printf("%d  |\n", internet->daddr[i]);
   
   // TCP header
   printf("TCP:\n|");
   printf(" %05d |", htons(tranctl->sport));
   printf(" %05d |\n", htons(tranctl->dport));
   printf("| %010d |\n", htonl(tranctl->seq));
   printf("| %010d |\n", htonl(tranctl->ack));
   printf("| %02d ", (tranctl->doff)*4);
   printf("| %02X ", tranctl->flags);
   printf("| %05d |\n", htons(tranctl->win));
   printf("| %04X ", htons(tranctl->cksum));
   printf("| %04X |\n", htons(tranctl->urp));
   */
   
   // Handle options
   ip_opts = (u32*)(packet + SIZE_ETHERNET + size_ip - 20);
   while (size_ip>5) {
      ip_opts+=1;
      size_ip--;
   }

   
   // convert ip and mac to type string;
   snprintf(shost_mac, sizeof shost_mac, "%02X:%02X:%02X:%02X:%02X:%02X",ethernet->shost[0],ethernet->shost[1],ethernet->shost[2],ethernet->shost[3],ethernet->shost[4],ethernet->shost[5]);
   snprintf(shost_ip, sizeof shost_ip, "%d.%d.%d.%d",internet->saddr[0],internet->saddr[1],internet->saddr[2],internet->saddr[3]);
  
   printf("Source IP: %s | Source MAC: %s | SYN_ACK: %d | Fingerprint %s\n", shost_ip, shost_mac, packet_type, fingerprint);
   sql_query(shost_ip, shost_mac, packet_type, fingerprint);
}

// sqlite queries
int sql_query(char host_ip[20], char host_mac[20], int packet_type, char fingerprint[40])
{
   //variable for storing return codes
   int retval=0;

   //statement to be executed
   sqlite3_stmt *stmt;
   
   //handle for database connection
   sqlite3 *handle;

   //if database doesn't exist, create it and connect
   retval = sqlite3_open(db,&handle);

   //If connection failed, handle set to NULL, open returns 1
   if(retval)
   {
      printf("Database connection failed\n");
      return -1;
   }

   // create the SQL query for creating a table
   char create_table[250] = "CREATE TABLE IF NOT EXISTS whitelist (sip TEXT, smac TEXT, syn_ack INTEGER, fingerprint TEXT)";
   char create_table2[250] = "CREATE TABLE IF NOT EXISTS mismatches (sip TEXT, smac TEXT, syn_ack INTEGER, fingerprint TEXT, mismatch_code INT, timestamp INTEGER)";
   
   //execute query to create whitelist table
   retval = sqlite3_exec(handle,create_table,0,0,0);
   if(retval)
   {
      printf("Error while creating whitelist table\n");
      return -1;
   }
   //execute query to create mismatches table
   retval = sqlite3_exec(handle,create_table2,0,0,0);
   if(retval)
   {
      printf("Error while creating mismatches table\n");
      return -1;
   }

   // check whitelist
   char query[250];
   snprintf(query, sizeof query, "SELECT * FROM whitelist WHERE (sip=\'%s\' OR smac=\'%s\') AND syn_ack=\'%d\'",host_ip, host_mac, packet_type);
   retval = sqlite3_prepare_v2(handle,query,-1,&stmt,0);

   int cols = sqlite3_column_count(stmt);
   int val;
   
   unsigned int mismatch=0;
   int rows = 0;
   int run = 1;
   while(run) {
      retval = sqlite3_step(stmt);
      if(retval == SQLITE_ROW) {
         rows++;
	 mismatch = 0;
	 int col;
         for(col=0; col<cols; col++) {
            const char *val = (const char*)sqlite3_column_text(stmt,col);
            switch (col){
               case 0:
                   if(strcmp(host_ip,val) != 0)
                      mismatch+=1;
               break;
               case 1:
                  if(strcmp(host_mac,val) != 0) 
                     mismatch+=2;
               break;
               case 2:
               break;
               case 3:
                  if(strcmp(fingerprint,val) != 0)
                     mismatch+=4;
               break;
               default:
                  printf("WARNING! Unexpected Column Number!\n");
               break;
            }
         }
	 if (mismatch == 0) run = 0;
      }
      else if(retval == SQLITE_DONE) { // All rows finished
         if(rows == 0)
            mismatch=7;
            //if no mismatch, mismatch=0    if not found in table, mismatch=7
         if(mismatch > 0) {
	    printf("Not on white-list!\n");
            // if exist in mismatch table...     //may need to ** out TTL and other options that frequently change
            snprintf(query, sizeof query, "SELECT count(*) FROM mismatches WHERE sip=\'%s\' AND smac=\'%s\' AND syn_ack=\'%d\' AND fingerprint=\'%s\'",host_ip, host_mac, packet_type, fingerprint);
            sqlite3_finalize(stmt);
            sqlite3_prepare_v2(handle,query,-1,&stmt,0);
            retval = sqlite3_step(stmt);
            if(retval == SQLITE_ROW) {
	       int timestamp = (int)time(NULL);
	       val = sqlite3_column_int(stmt,0);
               if(val == 0) { //not encountered previously
                  printf("ADMIN WARNING\n");
		  system(script);
                  // no coresponding mismatch rows, add row to mismatch table
                  snprintf(query, sizeof query, "INSERT INTO mismatches VALUES('%s','%s','%d','%s','%d','%d')",host_ip, host_mac, packet_type, fingerprint, mismatch, timestamp);
                  retval = sqlite3_exec(handle,query,0,0,0);
                  if(retval) {
                     printf("Error while inserting data, return code %d\n", retval);
                     printf("Closing Database\n");
                     sqlite3_finalize(stmt);
                     sqlite3_close(handle);
                     return -1;
                  }
               }
	       else {
                  snprintf(query, sizeof query, "SELECT timestamp FROM mismatches WHERE sip=\'%s\' AND smac=\'%s\' AND syn_ack=\'%d\' AND fingerprint=\'%s\'",host_ip, host_mac, packet_type, fingerprint);
                  sqlite3_finalize(stmt);
                  sqlite3_prepare_v2(handle,query,-1,&stmt,0);
                  sqlite3_step(stmt);
		  val = sqlite3_column_int(stmt,0);
		  if((timestamp-val)>timer) { // not encountered in the last x seconds
                     printf("ADMIN WARNING!!!\n");
		     system(script);
		     snprintf(query, sizeof query, "UPDATE mismatches SET timestamp = \'%u\' WHERE sip=\'%s\' AND smac=\'%s\' AND syn_ack=\'%d\' AND fingerprint=\'%s\'", timestamp, host_ip, host_mac, packet_type, fingerprint);
		     retval = sqlite3_exec(handle,query,0,0,0); // update timestamp
		     if(retval) {
		        printf("Error while updating data, return code %d\n", retval);
			printf("Closing Database\n");
			sqlite3_finalize(stmt);
			sqlite3_close(handle);
			return -1;
		     }
		  }
	       }
            }
         }  
	 run=0;
      }
      else {
         // Some error encountered
         printf("Some sql error encountered\n");
         return -1;
      }
   }
   // Close the handle to free memory
   sqlite3_finalize(stmt);
   sqlite3_close(handle);
   printf("\n");
return;
}
/*
void die_nicely(void) {
   pcap_close(pstream);
   printf("Now I lay my head to rest...\n");
}
*/
