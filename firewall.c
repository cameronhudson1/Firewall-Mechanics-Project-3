/// \file firewall.c
/// \brief Reads IP packets from a named pipe, examines each packet,
/// and writes allowed packets to an output named pipe.
/// Author: Chris Dickens (RIT CS)
/// Author: Ben K Steele (RIT CS)
///
/// Distribution of this file is limited
/// to Rochester Institute of Technology faculty, students and graders
/// currently enrolled in CSCI243, Mechanics of Programming.
/// Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department.
/// The content of this file is protected as an unpublished work.

/// posix needed for signal handling
#define _POSIX_SOURCE

#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>     /* interrupt signal stuff is from here */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     /* read library call comes from here */
#include <string.h>

#include "filter.h"

/// maximum packet length (ipv4)
#define MAX_PKT_LENGTH 2048

/// Type used to control the mode of the firewall
typedef enum FilterMode_E
{
   MODE_BLOCK_ALL,
   MODE_ALLOW_ALL,
   MODE_FILTER
} FilterMode;


/// Pipes_S structure maintains the stream pointers.
typedef struct Pipes_S
{
   FILE * in_pipe;               ///< input pipe stream
   FILE * out_pipe;              ///< output pipe stream
} Pipes_T;

/// FWSpec_S structure holds firewall configuration, filter and I/O.
typedef struct FWSpec_S
{
   char * config_file;           ///< name of the firewall config file
   char * in_file;               ///< name of input pipe 
   char * out_file;              ///< name of output pipe 
   IpPktFilter filter;           ///< pointer to the filter configuration
   Pipes_T pipes;                ///< pipes is the stream data storage.
} FWSpec_T;

/// fw_spec is the specification data storage for the firewall.
static FWSpec_T fw_spec;

/// close the streams. Call this once at the end of a simulation.
/// @param pipetab pointer to the I/O streams
void close_pipes( Pipes_T *pipetab ) {

   if(pipetab->in_pipe != NULL)
   {
      fclose(pipetab->in_pipe);
      pipetab->in_pipe = NULL;
   }

   if(pipetab->out_pipe != NULL)
   {
      fclose(pipetab->out_pipe);
      pipetab->out_pipe = NULL;
   }
}

/// MODE controls the mode of the firewall. main writes it and filter reads it.
static volatile FilterMode MODE = MODE_FILTER;

/// NOT_CANCELLED flag written by main and read by the thread.
static volatile int NOT_CANCELLED = 1;

/// thread object for the filter thread
static pthread_t tid_filter;

/// thread specific data key for pthread cleanup after cancellation.
static pthread_key_t tsd_key;

/// The tsd_destroy function cleans up thread specific data (TSD).
/// The spawning thread passes this function into pthread_key_create before
/// starting the thread.
/// The thread instance calls pthread_setspecific(key, (void *) value)
/// where value is the dynamic thread specific data.
/// When the thread exits, infrastructure calls the destroy function to
/// dispose of the TSD. 
/// @param tsd_data pointer to thread specific data allocations to free/close
void tsd_destroy( void * tsd_data) {

   FWSpec_T *fw_spec = (FWSpec_T *)tsd_data;
   printf( "fw: thread destructor is deleting filter data.\n"); fflush( stdout);
   if ( fw_spec->filter ) 
   {
      destroy_filter( fw_spec->filter);
      fw_spec->filter = NULL; 
   }
   printf( "fw: thread destructor is closing pipes.\n"); fflush( stdout);
   close_pipes( &fw_spec->pipes);
} 

/// signal handler passes signal information to the subordinate thread so
/// that the thread can gracefully terminate and clean up.
/// @param signum signal that was received by the main thread.
static void sig_handler( int signum)
{
    if(signum == SIGHUP) {
        NOT_CANCELLED = 0;
        printf("\nfw: received Hangup request. Cancelling...\n");
        fflush( stdout);
        pthread_cancel(tid_filter);  // cancel on signal to hangup
    }
}

/// init_sig_handlers initializes sigaction and installs signal handlers.
static void init_sig_handlers() {

    struct sigaction signal_action;            // define sig handler table 

    signal_action.sa_flags = 0;               // linux lacks SA_RESTART 
    sigemptyset( &signal_action.sa_mask );    // no masked interrupts 
    signal_action.sa_handler = sig_handler;   // insert handler function

    sigaction( SIGHUP, &signal_action, NULL ); // for HangUP from fwSim
    return; 
} // init_sig_handlers 


/// Open the input and output streams used for reading and writing packets.
/// @param spec_ptr structure contains input and output stream names.
/// @return true if successful
static bool open_pipes( FWSpec_T * spec_ptr){
   spec_ptr->pipes.in_pipe = fopen( spec_ptr->in_file, "rb");
   if(spec_ptr->pipes.in_pipe == NULL)
   {
      printf( "fw: ERROR: failed to open pipe %s.\n", spec_ptr->in_file);
      return false;
   }

   spec_ptr->pipes.out_pipe = fopen( spec_ptr->out_file, "wb");
   if(spec_ptr->pipes.out_pipe == NULL)
   {
      printf( "fw: ERROR: failed to open pipe %s.\n", spec_ptr->out_file);
      return false;
   }

   return true;
}

/// Read an entire IP packet from the input pipe
/// @param in_pipe the binary input file stream
/// @param buf Destination buffer for storing the packet
/// @param buflen The length of the supplied destination buffer
/// @return length of the packet or -1 for error
static int read_packet(FILE * in_pipe, unsigned char* buf, int buflen ){
   	int numRead = 0;
   	int numBytes = -1;

   	int len_read = -1; // assume error
	
	// Get numBytes
	numRead = fread(buf, sizeof(unsigned int), 1, in_pipe);
	numBytes = strtol(buf, NULL, 10);
	
	if(numBytes > buflen){
		fprintf(stderr, "Packet is too long\tnumBytes: %d   buflen: %d\n",
								numBytes, buflen);
		return EXIT_FAILURE;
	}
	
	numBytes++;
	len_read++;	

	// Iterate over numBytes
	for(int i = 0; i < numBytes; i++){
		numRead = fread(&buf[i], 1, sizeof(char), in_pipe);
		len_read++;
	}
	
	printf("Successfully read packet: \"%s\"\n", buf);
	
   	return len_read;
}


/// Runs as a thread and handles each packet. It is responsible
/// for reading each packet in its entirety from the input pipe,
/// filtering it, and then writing it to the output pipe. The
/// single void* parameter matches what is expected by pthread.
/// return value and parameter must match those expected by pthread_create.
/// @param args pointer to an FWSpec_T structure
/// @return pointer to static exit status value which is 0 on success

static void * filter_thread(void* args){
   	unsigned char pktBuf[MAX_PKT_LENGTH];
   	bool allow;
   	int length;

   	static int status = EXIT_FAILURE; // static for return persistence

   	status = EXIT_FAILURE; // reset

   	FWSpec_T* spec_p = (FWSpec_T*)args;
	open_pipes(spec_p);
	
	while(NOT_CANCELLED != 0){
		fprintf(stderr, "Entering read loop\n");
		status = EXIT_SUCCESS;
		length = read_packet((spec_p->pipes).in_pipe, pktBuf, MAX_PKT_LENGTH);
	
		//Set allow flag based on MODE
		switch(MODE){
			case MODE_BLOCK_ALL:
				allow = false;
				break;
			case MODE_ALLOW_ALL:
				allow = true;
				break;
			case MODE_FILTER:
				allow = filter_packet(spec_p->filter, pktBuf);
		}
		
		//If the packet is allowed, write it
		if(allow){
			fwrite(pktBuf, 1, length, (spec_p->pipes).out_pipe);
		}
		
		fflush((spec_p->pipes).in_pipe);
		fflush((spec_p->pipes).out_pipe);
	}
	
	// end of thread is never reached when there is a cancellation.
   	printf( "fw: thread is deleting filter data.\n"); fflush( stdout);
   	tsd_destroy( (void *)spec_p);
   	printf("fw: thread returning. status: %d\n", status);
   	fflush( stdout);

   	pthread_exit( &status);
}

/// Displays a prompt to stdout and menu of commands that a user can choose
static void display_menu(void)
{
   printf("\n\n1. Block All\n");
   printf("2. Allow All\n");
   printf("3. Filter\n");
   printf("0. Exit\n");
   printf("> ");
}

/// The firewall main function creates a filter and launches filtering thread.
/// Then it handles user input with a simple menu and prompt.
/// When the user requests and exit, the main cancels and joins the thread
/// before exiting itself.
/// Run this program with the configuration file as a command line argument.
/// @param argc Number of command line arguments; 1 expected
/// @param argv Command line arguments; name of the configuration file
/// @return EXIT_SUCCESS or EXIT_FAILURE
int main(int argc, char* argv[]){
   	int command;
   	bool done = false;
	char* ferror;
	char buf[MAX_PKT_LENGTH];

   	// print usage message if no arguments
   	if(argc < 2){
      	fprintf(stderr, "usage: %s configFileName\n", argv[0]);
    	return EXIT_FAILURE;
   	}

   	init_sig_handlers();
	printf("fw: starting filter thread.\n");
	display_menu();
	
	// Activate super FilterConfig generation
	IpPktFilter filter = create_filter();
	bool success = configure_filter(filter, argv[1]);
	if(!success){
		fprintf(stderr, "Error reading from config file\n");
		return EXIT_FAILURE;
	}

	fw_spec.config_file = argv[1];
	fw_spec.in_file = "ToFirewall";
	fw_spec.out_file = "FromFirewall";
	fw_spec.filter = filter;
	Pipes_T pipes;
	fw_spec.pipes = pipes;
	pthread_create(&tid_filter, NULL, filter_thread, (void*)&fw_spec);
		
	while((ferror = fgets(buf, 256, stdin)) != NULL){
		if(strcmp(buf, "0\n") == 0){
			//Input was "0" (EXIT)
			NOT_CANCELLED = 0;
			printf("Exiting\n");
			break;
		} else if(strcmp(buf, "1\n") == 0){
			//Input was "1" (BLOCK)
			MODE = MODE_BLOCK_ALL;
			printf("Switching to blocking mode\n");
		} else if(strcmp(buf, "2\n") == 0) {
			//Input was "2" (ALLOW)
			MODE = MODE_ALLOW_ALL;
			printf("Switching to allow mode\n");
		} else if(strcmp(buf, "3\n") == 0) {
			//Input was "3" (Filter)
			MODE = MODE_FILTER;
			printf("Switching to filtering mode\n");
		} else{
			//Input was not a known value
			printf("Unknown argument: \"%s\"\n", buf);
		}
	}
		
   	printf( "fw: main is joining the thread.\n"); fflush( stdout);

   	// wait for the filter thread to terminate
   	void * retval = NULL;
   	int joinResult = pthread_join(tid_filter, &retval);
   	if( joinResult != 0){
      	printf( "fw: main Error: unexpected joinResult: %d\n", joinResult);
      	fflush( stdout);
   	}
   	if ( (void*)retval == PTHREAD_CANCELED ){
      	printf( "fw: main confirmed that the thread was canceled.\n");
   	}

   	printf( "fw: main returning.\n"); fflush( stdout);
   	return EXIT_SUCCESS;
}

