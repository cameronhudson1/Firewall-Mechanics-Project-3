#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define _BSD_SOURCE
#include <stdint.h>
#include <endian.h>


/*
Program to parse data from a text file including IP packet data

Parse:
1. Version
2. IHL (Header Length)
3. Type of Service (TOS)
4. Total Length
5. Identification
6. IP Flags(**note**)
7. Fragment Offset
8. Time To Live (TTL)
9. Protocol
10. Header Checksum
11. Source Address
12. Destination Address

*/

/*
--------------------------------------------------------------------------
	packetData
		Struct to define the fields of a packet
--------------------------------------------------------------------------
*/
typedef struct packetData{
	int length;
	unsigned char version:4;
	unsigned char ihl:4;
	unsigned char tos:8;
	unsigned int totalLength:16;
	unsigned int identification:16;
	unsigned char flags:8;
	unsigned int fragmentOffset:13;
	unsigned char ttl:8;
	unsigned char protocol:8;
	unsigned int headerChecksum:16;
	unsigned char sa3:8;
	unsigned char sa2:8;
	unsigned char sa1:8;
	unsigned char sa0:8;
	unsigned char da3:8;
	unsigned char da2:8;
	unsigned char da1:8;
	unsigned char da0:8;
} packetData;


/*
--------------------------------------------------------------------------
	printPacket
		Given a pointer to a packetData object, printPacket prints it in a
		readable format
--------------------------------------------------------------------------
*/
void printPacket(packetData* packet, int number){
	printf("==>Packet %d\n", number+1);
	printf("Version:\t\t0x%x (%d)\n", packet->version, packet->version);
	printf("IHL (Header Length):\t\t0x%x (%d)\n", packet->ihl, packet->ihl);
	printf("Type of Service (TOS):\t\t0x%x (%d)\n", packet->tos, packet->tos);
	printf("Total Length:\t\t0x%x (%d)\n", packet->totalLength, packet->totalLength);
	printf("Identification:\t\t0x%x (%d)\n", packet->identification, packet->identification);
	printf("IP Flags:\t\t0x%x (%d)\n", packet->flags, packet->flags);
	printf("Fragment Offset:\t\t0x%x (%d)\n", packet->fragmentOffset, packet->fragmentOffset);
	printf("Time To Live (TTL):\t\t0x%x (%d)\n", packet->ttl, packet->ttl);
	printf("Protocol:\t\tTCP 0x%x (%d)\n", packet->protocol, packet->protocol);
	printf("Header Checksum:\t\t0x%x (%d)\n", packet->headerChecksum, packet->headerChecksum);
	printf("Source Address:\t\t%i.%i.%i.%i\n", packet->sa3, packet->sa2, packet->sa1, packet->sa0);
	printf("Destination Address:\t\t%i.%i.%i.%i\n", packet->da3, packet->da2, packet->da1, packet->da0);
	
}


/*
---------------------------------------------------------------------------
	parsePacket(FILE* fp)
		Parses the packet located where the file pointer points
---------------------------------------------------------------------------
*/
packetData* parsePacket(FILE* fp){
	packetData* packet = malloc(sizeof(packetData));
	
	//Read the size of the packet
	fread(&(packet->length), sizeof(int), 1, fp);
	
	//Read relevant Data from packet
	unsigned char d[20];
	fread(&d, 20, 1, fp);
	
	//Iterate over useless data (me_irl)
	if((packet->length) - 20 > 0){
		char uselessData[(packet->length)-20];
		fread(&uselessData, (packet->length)-20, 1, fp);	
	}
	
	//Get fields for packetData
	packet->version = ((d[0] & 0xF0) >> 4);
	packet->ihl = ((d[0] & 0x0F));
	packet->tos = d[1];
	packet->totalLength = ( (unsigned int) d[2] << 8) 
								| ( (unsigned int) d[3] );
	packet->identification = ( ( ( (unsigned int) d[4] ) << 8)
								| ( (unsigned int) d[5]) );
	unsigned char temp = (unsigned int) d[6];
	
	packet->flags = temp & 0b11100000;
	packet -> fragmentOffset = ((unsigned int)((temp & 0b00011111) << 8 ) 
								| (unsigned int)(d[7]));
	
	packet->ttl = d[8];
	packet->protocol = d[9];
	packet->headerChecksum =( (unsigned int) d[10] << 8 )
								| ( (unsigned int) d[11] );	
	
	packet->sa3 = (unsigned char) d[12];
	packet->sa2 = (unsigned char) d[13];
	packet->sa1 = (unsigned char) d[14];
	packet->sa0 = (unsigned char) d[15];
	
	packet->da3 = (unsigned char) d[16];
	packet->da2 = (unsigned char) d[17];
	packet->da1 = (unsigned char) d[18];
	packet->da0 = (unsigned char) d[19];
		
	return packet;
}


/*
---------------------------------------------------------------------------
	parseData(FILE* fp)
		Parses the data from a file into an array of packet pointers
---------------------------------------------------------------------------
*/
int parseData(FILE* fp, char* name){
	//Get number of packets
	int packets;
	if(fread(&packets, 4, 1, fp ) == 0){
		fprintf(stderr, "Failed to read count of packets.\n");
		return 1;
	}
	
	//Make an array to hold pointers to all packets
	packetData** allPackets = malloc(packets*sizeof(packetData*));
	
	for(int i = 0; i < packets; i++){
		allPackets[i] = parsePacket(fp);
	}
	
	printf("==== File %s contains %d Packets.\n", name, packets);
	for(int i = 0; i < packets; i++){
		printPacket(allPackets[i], i);
	}
	
	for(int i = 0; i < packets; i++){
		free(allPackets[i]);
	}
	free(allPackets);
}


/*
---------------------------------------------------------------------------
	Main Function
---------------------------------------------------------------------------
*/
int main(int argc, char **argv){
	if(argc > 1 && argc < 3){		//1 command line args
		FILE *fp;
		if((fp = fopen(argv[1], "rb")) != NULL){
			int m = parseData(fp, argv[1]);
		}
		else{
			fprintf(stderr, "Failed to open input file: No such file or directory\n");
		}		
	}
	else{							//Not enough or too many command line args
		fprintf(stderr, "usage: dissectPackets inputFile\n");
	}
	return 0;
}
