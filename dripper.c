/*
* Stateless DNS Scanner -- dripper.c
* (C) 2013 jtripper
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 3, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
 
in_addr_t *dns_servers;
int   NUM_DNS    = 0;
char *RESOLVCONF = "resolv.conf";
char *SUBDOMAINS = "subs.txt";
 
// structs for the DNS protocol
struct dnsflags {
  unsigned short rd:1;
  unsigned short tc:1;
  unsigned short aa:1;
  unsigned short opcode:4;
  unsigned short qr:1;
 
  unsigned short rcode:4;
  unsigned short z:3;
  unsigned short ra:1;
};
 
struct dnshdr {
  unsigned short txid;
  struct dnsflags dns_flags;
  unsigned short questions;
  unsigned short answer_rrs;
  unsigned short authority_rrs;
  unsigned short additional_rrs;
};
 
struct dnstype {
  unsigned short type;
  unsigned short class;
};
 
struct dnsanswer {
  unsigned short name;
  struct dnstype qtype;
  unsigned short pad;
  unsigned short ttl;
  unsigned short len;
};
 
// ipv4_network struct
struct ipv4_network {
  unsigned long mask;
  unsigned long cidr;
  unsigned long max;
  unsigned long addr;
  struct in_addr sin_addr;
};
 
void convert_to_dns(char *dns);
void convert_to_str(char *pkt, int len, char *max);
void error(char *format, ...);
void forward_brute(char *target);
int  ip_range_init(char *range, struct ipv4_network *network);
int  ip_range_next(struct ipv4_network *network);
void parse_dns_reply(unsigned char *pkt, int len_pkt, char *domain);
void parse_resolv_conf();
void print_hex(unsigned char *pkt, int len);
void reverse_search(char *range);
void rstrip(char *str);
int  send_dns(char *target, int type);
void sniff_dns_replies(char *domain);
void usage();
 
// convert dotted format to domain name format
// arguments:
//   dns -> domain name
void convert_to_dns(char *dns) {
  char *mark = NULL;
  int i, j;
 
  for(i=0; i<=strlen(dns); i++) {
    if(dns[i] == '.' && !mark)
      mark = (dns + i);
    else if(dns[i] == '.' || (dns[i] == '\0' && mark)) {
      mark[0] = (char)((dns + i) - mark - 1);
      mark = (dns + i);
    }
  }
}
 
// convert domain name format to regular dotted format
// arguments:
//   pkt -> packet
//   len -> length of domain name (set to 0 if null terminated)
//   max -> highest offset to go to
void convert_to_str(char *pkt, int len, char *max) {
  int i, j;
 
  if((len == 0 && pkt + strlen(pkt) > max) || (len > 0 && pkt + len > max))
    return;
 
  for(i=0; i< (len > 0 ? len : strlen(pkt)); i++) {
    j = pkt[i];
    pkt[i] = '.';
    i += j;
  }
 
  if(len > 0)
    pkt[len] = '\0';
}
 
// print an error
// arguments:
//   format -> format string
//   format string arguments
void error(char *format, ...) {
  char error_buffer[1024];
  va_list args;
 
  va_start(args, format);
  vsnprintf(error_buffer, sizeof(error_buffer), format, args);
  perror(error_buffer);
  va_end(args);
  exit(1);
}
 
// bruteforce forward DNS
// arguments:
//   target -> domain name to bruteforce
void forward_brute(char *target) {
  int i=0;
  char record[80], line[80];
  FILE *f;
 
  if(!(f = fopen(SUBDOMAINS, "r")))
    error("[!] Error opening: %s", SUBDOMAINS);
 
  // loop over file and send requests
  while (fgets(line, 80, f) != NULL) {
    memset(record, 0, 80);
    rstrip(line);
    snprintf(record, 80, ".%s.%s", line, target);
    send_dns(record, 1);
    i++;
    if(i == 1000) {
      sleep(1);
      i = 0;
    }
  }
 
  fprintf(stderr, "All domains scanned.\n");
  fclose(f);
}
 
// initialize an ipv4_network structure
// Arguments:
//   * range   -> string in CIDR network format (e.g. 192.168.0.1/24)
//   * network -> pointer to ipv4_network structure
int ip_range_init(char *range, struct ipv4_network *network) {
  char *slash, tmp_range[20];
  unsigned long num_addrs;
 
  // copy the range into our own variable
  strncpy(tmp_range, range, 19);
 
  // retreive a pointer to the CIDR value
  // thanks for pointing this out http://reddit.com/u/abadidea
  if(!(slash = strchr(tmp_range, '/'))) {
    fprintf(stderr, "[!] Error, invalid CIDR format.\n");
    exit(1);
  }
 
  // verify that the CIDR converts to an unsigned int < 33
  if((network->cidr = atoi(slash + 1)) > 32) {
    fprintf(stderr, "[!] Error, invalid CIDR value.\n");
    exit(1);
  }
 
  // convert the slash into a \0
  slash[0] = '\0';
 
  // convert the IP address into network format
  if(!inet_aton(tmp_range, &network->sin_addr)) {
    fprintf(stderr, "[!] Error, invalid address.\n");
    exit(1);
  }
 
  // reverse the order of the address
  network->addr = ntohl(network->sin_addr.s_addr);
  // retrieve the number of addresses
  num_addrs     = (unsigned long)0xffffffff >> network->cidr;
  // get the network mask
  network->mask = ~num_addrs;
  // get the first address
  network->addr = network->addr & network->mask;
  // get the last address
  network->max  = network->addr + num_addrs;
 
  return 0;
}
 
// Get the next address in an ipv4_network, returns 0 if there are no more addresses
// returns 1 if there are still more address.
// Arguments:
//   * network -> pointer to an initiaziled ipv4_network struct
int ip_range_next(struct ipv4_network *network) {
  if(network->max <= network->addr - 1) {
    return 0;
  } else {
    network->sin_addr.s_addr = htonl(network->addr);
    network->addr++;
    return 1;
  }
}
 
// parse incoming packets
// arguments:
//   pkt     -> packet
//   len_pkt -> packet length
//   domain  -> only print if domain matches (for PTR records only)
void parse_dns_reply(unsigned char *pkt, int len_pkt, char *domain) {
  int length = 0, i, to_dns = 0;
  char *name;
  struct iphdr  *ip_header;
  struct udphdr *udp_header;
  struct dnshdr *dns_header;
  struct dnsanswer *answer;
  struct in_addr *inaddr;
 
  ip_header  = (struct iphdr*)pkt;
  length    += sizeof(struct iphdr);
  udp_header = (struct udphdr*)(pkt + length);
  length    += sizeof(struct udphdr);
  dns_header = (struct dnshdr*)(pkt + length);
  to_dns     = length;
  length    += sizeof(struct dnshdr);
 
  // make sure source port is 53
  if(udp_header->source != htons(53))
    return;
 
  // return if there's no answers
  if(ntohs(dns_header->answer_rrs) < 1)
    return;
 
  // loop over the questions and convert names to strings
  for(i=0; i<ntohs(dns_header->questions); i++) {
    convert_to_str(pkt + length, 0, pkt + len_pkt);
    length += strlen(pkt + length) + 1 + sizeof(struct dnstype);
    if(length > len_pkt)
      return;
  }
 
  // loop over answers
  for(i=0; i<ntohs(dns_header->answer_rrs); i++) {
    answer  = (struct dnsanswer*)(pkt + length);
    length += sizeof(struct dnsanswer);
    if(length > len_pkt)
      return;
 
    // get the offset of the domain name for the answer
    name = (pkt + to_dns + (ntohs(answer->name) & 0xff) + 1);
 
    if(length + ntohs(answer->len) > len_pkt)
      return;
 
    // A
    if(ntohs(answer->qtype.type) == 1) {
      if(ntohs(answer->len) != 4)
        return;
      inaddr = (struct in_addr*)(pkt + length);
      printf("%s -> %s (A)\n", name, inet_ntoa(*inaddr));
    }
    // CNAME
    else if(ntohs(answer->qtype.type) == 5) {
      convert_to_str(pkt + length, ntohs(answer->len) - 1, pkt + len_pkt);
      printf("%s -> %s (CNAME)\n", name, pkt + length + 1);
    }
    // PTR
    else if(ntohs(answer->qtype.type) == 12) {
      convert_to_str(pkt + length, ntohs(answer->len) - 1, pkt + len_pkt);
      if(strstr(pkt + length + 1, domain))
        printf("%s -> %s (PTR)\n", name, pkt + length + 1);
    }
 
    length += ntohs(answer->len);
  }
}
 
// parse a newline delimited resolv.conf file
// arguments:
//   none
void parse_resolv_conf() {
  FILE *f;
  char ns[80];
  int i = 0;
  regex_t preg;
  regmatch_t pmatch[1];
 
  // IP regex
  regcomp(&preg, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\n$", REG_EXTENDED);
 
  if(!(f = fopen(RESOLVCONF, "r")))
    error("[!] Error opening: %s", RESOLVCONF);
 
  // count lines in file
  while (fgets(ns, 80, f) != NULL) {
    if (!regexec(&preg, ns, 1, pmatch, 0))
      NUM_DNS++;
  }
 
  // go back to the beginning
  rewind(f);
 
  // allocate the DNS servers array
  dns_servers = (in_addr_t*)malloc(sizeof(in_addr_t) * NUM_DNS);
 
  // populate array
  while(fgets(ns, 80, f) != NULL) {
    if (regexec(&preg, ns, 1, pmatch, 0) != 0)
      continue;
    dns_servers[i] = inet_addr(ns);
    i++;
  }
 
  fclose(f);
}
 
// hexdump a char array (for debugging mainly)
// arguments:
//   pkt -> char array to dump
//   len -> number of bytes to print
void print_hex(unsigned char *pkt, int len) {
  int i, j;
 
  for(i=0, j=0; i<len; i++, j++) {
    if(j == 16) j = 0;
 
    printf("%02x ", pkt[i]);
    switch (j) {
      case 7:
        printf(" ");
        break;
      case 15:
        printf("\n");
        break;
    }
  }
 
  printf("\n\n");
}
 
// do a reverse dns search
// arguments:
//   range -> IP range in format 192.168.0.0/24
void reverse_search(char *range) {
  char lookup[29];
  struct ipv4_network network;
 
  ip_range_init(range, &network);
  while(ip_range_next(&network)) {
    network.sin_addr.s_addr = network.addr;
    sprintf(lookup, ".%s.in-addr.arpa", inet_ntoa(network.sin_addr));
    send_dns(lookup, 12);
  }
}
 
// remove trailing new lines
// arguments:
//   str -> string to remove
void rstrip(char *str) {
  int i;
 
  // loop over the string, if any newlines are found change to \0
  for(i=0; i<strlen(str); i++) {
    if(str[i] == '\n' || str[i] == '\r')
      str[i] = '\0';
  }
}
 
// send a DNS request
// arguments:
//   target -> domain to lookup
//   type   -> DNS query type (1 for A, 12 for PTR)
int send_dns(char *target, int type) {
  char  *pkt = (char*)calloc(4096, 1);
  int sock, value = 1, length = 0;
  struct iphdr  *ip_header;
  struct udphdr *udp_header;
  struct dnshdr *dns_header;
  struct dnstype *dns_type;
  struct sockaddr_in daddr;
 
  // pick a random DNS server from the list
  daddr.sin_family      = AF_INET;
  daddr.sin_port        = htons(53);
  daddr.sin_addr.s_addr = dns_servers[rand() % NUM_DNS];
 
  // fill IP header
  ip_header = (struct iphdr*)pkt;
  ip_header->ihl      = 5;
  ip_header->version  = 4;
  ip_header->tos      = 0;
  ip_header->id       = htonl(rand() % 65534 + 1);
  ip_header->frag_off = 0;
  ip_header->ttl      = 255;
  ip_header->protocol = IPPROTO_UDP;
  ip_header->check    = 0;
  ip_header->daddr    = daddr.sin_addr.s_addr;
 
  length += sizeof(struct iphdr);
 
  // fill out UDP header
  udp_header = (struct udphdr*)(pkt + length);
  udp_header->source = htons(rand() % 65534 + 1);
  udp_header->dest   = htons(53);
  udp_header->check  = 0;
 
  length += sizeof(struct udphdr);
 
  // fill out DNS header
  dns_header = (struct dnshdr*)(pkt + length);
  dns_header->txid         = htons(rand() % 65534 + 1);
  // recursion desired = 1
  dns_header->dns_flags.rd = 1;
  dns_header->questions    = htons(1);
 
  length += sizeof(struct dnshdr);
 
  // convert domain to DNS format and copy into the packet
  convert_to_dns(target);
  memcpy(pkt + length, target, strlen(target) + 1);
 
  length += strlen(target) + 1;
 
  // set the type and class
  dns_type = (struct dnstype*)(pkt + length);
  dns_type->type  = htons(type);
  dns_type->class = htons(1);
 
  length += sizeof(struct dnstype);
 
  ip_header->tot_len = length;
  udp_header->len    = htons(length - sizeof(struct iphdr));
 
  // spawn the raw socket
  if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
    error("[!] Error socket:");
 
  // tell the kernel we will handle our own headers
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &value, sizeof(int));
 
  // send the packet
  if((sendto(sock, pkt, ip_header->tot_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) < 0)
    error("[!] Error sendto:");
 
  free(pkt);
  close(sock);
}
 
// start UDP sniffer
// arguments:
//   domain -> only print matching PTR records
void sniff_dns_replies(char *domain) {
  int sniffer, sockaddr_size = sizeof(struct sockaddr), len_pkt;
  unsigned char *buffer = (unsigned char *)calloc(65560, 1);
  struct sockaddr saddr;
 
  // start a raw socket
  if((sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
    error("[!] Error socket:");
 
  for(;;) {
    // receive from port 0 (or sniff all incoming UDP packets)
    if((len_pkt = recvfrom(sniffer, buffer, 65536, 0, &saddr, &sockaddr_size)) < 1)
      continue;
    // parse UDP packets
    parse_dns_reply(buffer, len_pkt, domain);
  }
}
 
// print usage and exit
// arguments:
//   void
void usage() {
  fprintf(stderr, "dripper usage:\n");
  fprintf(stderr, " * -h                     -- display this message.\n");
  fprintf(stderr, " * -r <resolv conf>       -- resolv.conf (list of nameservers).\n");
  fprintf(stderr, " * -s <subdomain list>    -- subdomain list (list of subdomains).\n");
  fprintf(stderr, " * -d <domain to brute>   -- target domain (e.g. google.com).\n");
  fprintf(stderr, " * -i <ip range to brute> -- IP range to bruteforce for a target domain.\n");
  exit(1);
}
 
int main(int argc, char *argv[]) {
  char *range=NULL, *domain=NULL, opt;
  srand(time(NULL));
 
  fprintf(stderr, "---------------------------------\n");
  fprintf(stderr, "dripper Stateless DNS Scanner 1.0\n");
  fprintf(stderr, "  (c) jtripper 2013\n");
  fprintf(stderr, "  http://blackhatlibrary.net/\n");
  fprintf(stderr, "---------------------------------\n\n");
 
  if(argc == 1)
    usage();
 
  // get options
  while((opt = getopt(argc, argv, "hr:s:d:i:")) != -1) {
    switch(opt) {
      // override default resolvconf
      case 'r':
        RESOLVCONF = optarg;
        break;
      // override default subdomain file
      case 's':
        SUBDOMAINS = optarg;
        break;
      // set the domain
      case 'd':
        domain = optarg;
        break;
      // set the IP range (if doing reverse scan)
      case 'i':
        range = optarg;
        break;
      default:
        usage();
    }
  }
 
  // make sure a domain is set
  if(!domain) usage();
 
  // retreive name servers
  parse_resolv_conf();
  // make sure subdomains file exists
  if(!fopen(SUBDOMAINS, "r")) error("[!] Error opening: %s", SUBDOMAINS);
 
  if(!fork()) {
    // do a reverse search or a forward search
    if(range) {
      reverse_search(range);
    } else {
      forward_brute(domain);
    }
  } else {
    // spawn the sniffer
    sniff_dns_replies(domain);
  }
}
