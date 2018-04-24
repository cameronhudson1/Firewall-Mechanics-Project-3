/// \file filter.c
/// generic map(n => writeSize)\brief Filters IP packets based on settings in a user supplied
/// configuration file.
/// Author: Chris Dickens (RIT CS)
///
/// Distribution of this file is limited
/// to Rochester Institute of Technology faculty, students and graders
/// currently enrolled in CSCI243, Mechanics of Programming.
/// Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department.
/// The content of this file is protected as an unpublished work.
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "filter.h"
#include "pktUtility.h"

/// maximum line length of a configuration file
#define MAX_LINE_LEN  256

/// The type used to hold the configuration settings for a filter
typedef struct FilterConfig_S{
   unsigned int localIpAddr;    ///< the local IP address
   unsigned int localMask;      ///< the address mask
   bool blockInboundEchoReq;    ///< where to block inbound echo
   unsigned int numBlockedInboundTcpPorts;   ///< count of blocked ports
   unsigned int* blockedInboundTcpPorts;     ///< array of blocked ports
   unsigned int numBlockedIpAddresses;       ///< count of blocked addresses
   unsigned int* blockedIpAddresses;         ///< array of blocked addresses
} FilterConfig;


/// Parses the remainder of the string last operated on by strtok 
/// and converts each octet of the ASCII string IP address to an
/// unsigned integer value.
/// @param ipAddr The destination into which to store the octets
/// @pre caller must have first called strtok to set its pointer.
/// @post ipAddr contains the ip address found in the string
static void parse_remainder_of_string_for_ip(unsigned int* ipAddr)
{
   char* pToken;

   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[0]);
   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[1]);
   pToken = strtok(NULL, ".");
   sscanf(pToken, "%u", &ipAddr[2]);
   pToken = strtok(NULL, "/");
   sscanf(pToken, "%u", &ipAddr[3]);
}


/// Checks if an IP address is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param addr The IP address that is to be checked
/// @return True if the IP address is to be blocked
static bool block_ip_address(FilterConfig* fltCfg, unsigned int addr){
	for(int i = 0; i < numBlockedIpAddresses; i++){
		if(fltCfg->blockedIpAddresses[i] == addr){
			return true;  //IP was meant to be blocked, return true
		}
	}
   	return false;	//No matching blocked port found
}


/// Checks if a TCP port is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param port The TCP port that is to be checked
/// @return True if the TCP port is to be blocked
static bool block_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port){
	for(int i = 0; i < fltCfg->numBlockedTcpPorts; i++){
		if(fltCfg->blockedTcpPorts[i] == port){
			return true;	//tcpPort was meant to be blocked, return true
		}
	}
   	return false;	//No matching blocked port found
}


/// Checks if a packet is coming into the network from the external world. Uses
/// the localMask in the supplied filter configuration to compare the srcIpAddr
/// and dstIpAddr to the localIpAddr supplied in the filter configuration. If the
/// dstIpAddr is on the same network as the localIpAddr, and the srcIpAddr is not
/// on the same network as the localIpAddr then the packet is inbound.
/// @param fltCfg The filter configuration to use
/// @param srcIpAddr The source IP address of a packet
/// @param dstIpAddr The destination IP address of a packet
static bool packet_is_inbound(FilterConfig* fltCfg, unsigned int srcIpAddr, unsigned int dstIpAddr){
	if( !(~(fltCfg->mask & destNetwork)) && ~(fltCfg->mask != srcAddr)){
		return true;
	}
   	return false;
}


/// Adds the specified IP address to the array of blocked IP addresses in the
/// specified filter configuration. This requires allocating additional memory
/// to extend the length of the array that holds the blocked IP addresses.
/// @param fltCfg The filter configuration to which the IP address is added
/// @param ipAddr The IP address that is to be blocked
static void add_blocked_ip_address(FilterConfig* fltCfg, unsigned int ipAddr){
	fltCfg->numBlockedIpAddresses++;
	realloc(fltCfg->blockedIpAddresses, fltCfg->numBlockedIpAddresses);
	assert(fltCfg->blockedIpAddresses);
	fltCfg->blockedIpAddresses[(fltCfg->numBlockedIpAddresses)-1] = ipAddr;
}


/// Adds the specified TCP port to the array of blocked TCP ports in the
/// specified filter configuration. This requires allocating additional
/// memory to extend the length of the array that holds the blocked ports.
/// @param fltCfg The filter configuration to which the TCP port is added
/// @param port The TCP port that is to be blocked
static void add_blocked_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port){
	fltCfg->numBlockedInboundTcpPorts++;
	realloc(fltCfg->blockedInboundTcpPorts, fltCfg->numBlockedInboundTcpPorts);
	assert(fltCfg->blockedInboundTcpPorts);
	fltCfg->blockedInboundTcpPorts[(numBlockedInboundTcpPorts)-1] = port;
}


/// Creates an instance of a filter by allocating memory for a FilterConfig
/// and initializing its member variables.
/// @return A pointer to the new filter
IpPktFilter create_filter(void){
   	FilterConfig* filter = NULL;

	filter = malloc(sizeeof(FilterConfig));
	filter->localIpAddr = 0;
	filter->localMask = 0;
	filter->blockInboundEcoReq = false;
	filter->numBlockedInboundTcpPorts = 0;
	filter->blockedInboundTcpPorts = NULL;
	filter->numBlockedIpAddresses = 0;
	filter->blockedIpAddresses = NULL;

   	return (IpPktFilter*)filter; 
}


/// Destroys an instance of a filter by freeing all of the dynamically
/// allocated memory associated with the filter.
/// @param filter The filter that is to be destroyed
void destroy_filter(IpPktFilter filter)
{
   	FilterConfig* fltCfg = filter;

	if(filter->blockedInboundTcpPorts != NULL){
		free(filter->blockedInboundTcpPorts);
	}
	if(filter->blockedIpAddresses != NULL){
		free(filter->blockedIpAddresses);
	}
	free(filter);
}


/// Configures a filter instance using the specified configuration file.
/// Reads the file line by line and uses strtok, strcmp, and sscanf to 
/// parse each line.  After each line is successfully parsed the result
/// is stored in the filter.  Blank lines are skipped.  When the end of
/// the file is encountered, the file is closed and the function returns.
/// @param filter The filter that is to be configured
/// @param filename The full path/filename of the configuration file that
/// is to be read.
/// @return True when successful
bool configure_filter(IpPktFilter filter, char* filename){
   	char buf[MAX_LINE_LEN];
   	FILE* pFile;
   	char* pToken;
   	char* success;
   	bool  validConfig = false;

	FilterConfig* fltCfg = (FilterConfig*)filter;

	//Handle opening File
   	pFile = fopen(filename, "r"); 
   	if(pFile == NULL){
      	printf("ERROR: invalid config file\n");
      	return false;
   	}
	
	// Get first line to check
	fgets(buf, MAX_LINE_LENGTH, pFile);

	// Check if first line is "LOCAL_NET:"
	ptoken = strtok(buf, " ");
	if(strcmp(ptoken, "LOCAL_NET:")){
		validConfig = true;
	}
	//If not "LOCAL_NET:", error out & return false
  	if(validConfig == false){
      	fprintf(stderr, "Error, configuration file must set LOCAL_NET\n");
   		fclose(pFile);
		return false;
	}

	// If "LOCAL_NET:" is found, sore the data
	parse_remainder_of_string_for_ip(fltCfg->localIpAddr);
	
	// Parse local mask	
	ptoken = strtok(NULL, "\n");
	int bitMask = strtol(ptoken, NULL, 10);
	if(bitMask == 8){
		fltCfg->mask = (fltCfg->localIpAddr) & 0xFF000000;
	}
	else if(bitMask == 16){
		fltCfg->mask = (fltCfg->localIpAddr) & 0xFFFF0000;
	}
	else if(bitMask == 24){
		fltCfg->mask = (fltCfg->localIpAddr) & 0xFFFFFF00;
	}
	else if(bitMask == 32){
		fltCfg->mask = (fltCfg->localIpAddr) & 0xFFFFFFFF; 	
	}
	
	//Get main configurations
	while(fgets(buf, MAX_LINE_LEN, pFile) != NULL){
		if(strcmp(buf, "")){
			ptoken = strtok(buf, " ");
			if(!strcmp(ptoken, "BLOCK_INBOUND_TCP_PORT:")){
				char* temp = strtok(NULL, "\n");
				unsigned int newTcp = strtol(temp, NULL, 10);
				add_blocked_inbound_tcp_port(fltCfg, newTcp);
			}
			else if(!strcmp(ptoken, "BLOCK_IP_ADDR:")){
				unsigned int newBlockIp;
				parse_remainder_of_string_for_ip(&newBlockIp);
				add_blocked_ip_address(cfg, newBlockIp);
			}
			else if(!strcmp(ptoken, "BLOCK_PING_REQ")){
				fltCfg->blockInboundEchoReq	= true;			
			}
		}
	}
	fclose(pFile);
   	return validConfig;
}


/// Uses the settings specified by the filter instance to determine
/// if a packet should be allowed or blocked.  The source and
/// destination IP addresses are extracted from each packet and
/// checked using the block_ip_address helper function. The IP protocol
/// is extracted from the packet and if it is ICMP or TCP then 
/// additional processing occurs. This processing blocks inbound packets
/// set to blocked TCP destination ports and inbound ICMP echo requests.
/// @param filter The filter configuration to use
/// @param pkt The packet to exame
/// @return True if the packet is allowed by the filter. False if the packet
/// is to be blocked
bool filter_packet(IpPktFilter filter, unsigned char* pkt){
   	unsigned int srcIpAddr;
   	unsigned int dstIpAddr;
   	FilterConfig* fltCfg = (FilterConfig*)filter;
	
	srcIpAddr = extractSrcAddrFromIpHeader(pkt);
	dstIpAddr = extractDstAddrFromIpHeader(pkt);
	unsigned int ipProtocol = extractIpProtocol(pkt);
	
	
	
  	return true;
}

