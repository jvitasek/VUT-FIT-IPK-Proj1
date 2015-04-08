#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include "macros.h"

char *ERRMSG[] = {
	"Wrong arguments!\n",
	"Can't have both -l and -u!\n",
	"gethostbyname error!\n",
	"Invalid UID number!\n",
	"No login or UID!\n",
	"Unknown login or UID!\n"
};

int L, U, G, N, H, S, is_login, is_uid = 0;
char *hostname = "";
char *logins[100] = {0};
char *uids[100] = {0};
unsigned int port_client = 0;
int logincount, uidcount = 0;

void getargs_client(int, char **);
void printhelp();
int check_uid(char *);
int sendall(int, char *, int *);

/**
 * Carries out the main server-client functionality in this section.
 * @param  argc The number of arguments passed.
 * @param  argv The argument vector containing the passed arguments.
 * @return int  The success/failure code.
 */
int main(int argc, char *argv[])
{
	int socket_desc;
	struct sockaddr_in socket_addr; struct hostent *hptr;

	//=====================================================
	// HANDLING THE USER-SIDE PARAMETERS
	//=====================================================

	// if there's only 1 argument
	if(argc < 3)
		ERR(0,2);

	// getting the user-side parameters
	getargs_client(argc, argv);

	// lowercasing logins
	for(int i = 0; i < logincount; i++)
		for(int j = 0; logins[i][j]; j++)
			logins[i][j] = tolower(logins[i][j]);

	// checking UID validity
	for(int i = 0; i < uidcount; i++)
		if(check_uid(uids[i]) < 0)
			ERR(3,2);

	if(is_login && is_uid)
		ERR(1,2);
	if(!is_login && !is_uid)
		ERR(4,2);
	if(!port_client || !hostname)
		ERR(0,2);

	//=====================================================
	// SETTING UP THE CONNECTION
	//=====================================================
	
	// creating a socket
	if((socket_desc = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		DIE("Socket Error");

	// protocol family -> internet (IPv4)
	socket_addr.sin_family = PF_INET;
	// port number defined by user-side parameters (-p [port])
	socket_addr.sin_port = htons(port_client);
	// IP address defined by user-side parameters (-h [hostname])
	if((hptr = gethostbyname(hostname)) == NULL)
		ERR(2,1);

	// copying host address to socket address
	memcpy(&socket_addr.sin_addr, hptr->h_addr, hptr->h_length);
	
	// connecting to server
	if(connect(socket_desc, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
		DIE("Connect Error");

	//=====================================================
	// SENDING THE USER-SIDE PARAMETERS TO SERVER
	//=====================================================
	char argsbuffer[11];
	int argslen = 11;
	snprintf(argsbuffer, 11, "%d%d%d%d%d%d%d%d%d%d", L, U, G, N, H, S, is_login, is_uid, logincount, uidcount);

	sendall(socket_desc, argsbuffer, &argslen);
	if(recv(socket_desc, argsbuffer, sizeof(argsbuffer), 0) < 0)
		DIE("Acknowledge Error");

	memset(argsbuffer, 0, sizeof(argsbuffer));

	//=====================================================
	// SENDING THE PASSED LOGIN OR UID TO SERVER
	//=====================================================
	if(is_login == 1) // if login was passed
	{
		int loginlen = 0;
		char loginbuffer[CHUNK_SIZE] = {0};
		for(int i = 0; i < logincount; i++)
		{
			loginlen = strlen(logins[i])+1;
			// storing the lenght of the UID on the first byte
			snprintf(loginbuffer, sizeof(loginbuffer), "%u%s", loginlen, logins[i]);
			// sending the message
			sendall(socket_desc, loginbuffer, &loginlen);
			// acknowledgment
			if(recv(socket_desc, loginbuffer, sizeof(loginbuffer), 0) < 0)
			 	DIE("Acknowledge Error");
			memset(loginbuffer, 0, sizeof(loginbuffer));
		}
	}
	// if UID was passed
	else
	{
		int uidlen = 0;
		char uidbuffer[CHUNK_SIZE] = {0};
		for(int i = 0; i < uidcount; i++)
		{
			uidlen = strlen(uids[i])+1;
			// storing the lenght of the UID on the first byte
			snprintf(uidbuffer, sizeof(uidbuffer), "%u%s", uidlen, uids[i]);
			// sending the message
			sendall(socket_desc, uidbuffer, &uidlen);
			// acknowledgment
			if(recv(socket_desc, uidbuffer, sizeof(uidbuffer), 0) < 0)
			 	DIE("Acknowledge Error");
			memset(uidbuffer, 0, sizeof(uidbuffer));
		}
	}

	//=====================================================
	// RECEIVING THE RESULTS FROM THE SERVER
	//=====================================================

	char result_buffer[CHUNK_SIZE] = {0};

	int found = 0;
	int record = 0;
	int count = 0;
	while(1)
	{
		recv(socket_desc, result_buffer, sizeof(result_buffer), 0);
		for(unsigned int i = 0; i < strlen(result_buffer); i++)
		{
			if(result_buffer[i] == ';')
			{
				found = 1;
				break;
			}
			if(result_buffer[i] == '&' && record == 0)
			{
				record = 1;
			}
			// OUTPUTTING THE RESULTS
			if(record == 1 && result_buffer[i] != '&')
				putchar(result_buffer[i]);
		}
		if(found == 1)
			break;
		count++;
	}
	putchar('\n');	

	// closing the socket
	if(close(socket_desc) < 0)
		DIE("Close Error");

	return 0;
}

/**
 * Gets the arguments passed by the user.
 * @param argc The number of arguments passed.
 * @param argv The argument vector containing the passed arguments.
 */
void getargs_client(int argc, char *argv[])
{
	char opt;
	int index = 0;
	char *nextbuff = "";
	while((opt = getopt(argc, argv, ":LUGNHSh:u:l:p:h:")) != -1)
	{
		switch(opt)
		{
			case 'l':
				index = optind - 1;
				while(index < argc)
				{
					nextbuff = argv[index];
					index++;
					if(nextbuff[0] != '-')
						logins[logincount++] = nextbuff;
					else
						break;
				}
				optind = index - 1;
				is_login = 1;
				break;
			case 'u':
				index = optind - 1;
				while(index < argc)
				{
					nextbuff = argv[index];
					index++;
					if(nextbuff[0] != '-')
						uids[uidcount++] = nextbuff;
					else
						break;
				}
				optind = index - 1;
				is_uid = 1;
				break;
			case 'p': // port
				// converting the port to number directly
				port_client = strtol(optarg, (char **)NULL, 10);
				break;
			case 'h': // host
				hostname = optarg;
				break;
			case 'L': // login
				L = 1;
				break;
			case 'U': // UID
				U = 1;
				break;
			case 'G': // GID
				G = 1;
				break;
			case 'N': // gecos
				N = 1;
				break;
			case 'H': // root
				H = 1;
				break;
			case 'S': // shell
				S = 1;
				break;
			case '?': // error
				ERR(0,2);
			default: // others
				printhelp();
			break;
		}
	}
}

/**
 * Prints the help message. Triggered upon passing the wrong number of parameters.
 */
void printhelp()
{
	printf("\n\033[32;1m Usage: \033[0m\n"
	"-p [port]\tEnter the port number to be opened by the server.\n"
	"-h [hostname]\tEnter the hostname to search the etc/passwd file.\n"
	"-l [login]\tEnter the login to be found in the etc/passwd file.\n"
	"-u [UID]\tEnter the UID to be found in the etc/passwd file.\n\n"
	"-L\tFlag to print the username.\n"
	"-U\tFlag to print the user ID.\n"
	"-G\tFlag to print the group ID.\n"
	"-N\tFlag to print the whole name, the whole gecos.\n"
	"-H\tFlag to print the homes directory.\n"
	"-S\tFlag to print the root shell.\n\n");	
	exit(0);
}

/**
 * Checks the UID passed in by the user for being valid UID.
 * @param  uid The UID to check.
 * @return     Returns -1 if invalid, 0 if valid.
 */
int check_uid(char *uid)
{
	errno = 0;
	char *endptr;
	long val = strtol(uid, &endptr, 10);
	if(errno == ERANGE)
	{
		switch(val)
		{
			// underflow
			case LONG_MIN:
				return -1;
				break;
			// overflow
			case LONG_MAX:
				return -1;
				break;
			// error
			default:
				assert(false);
		}
	}
	// error
	else if(errno != 0)
		DIE("UID Error");

	// not a valid UID
	if(*endptr != '\0')
		return -1;

	// valid UID
	return 0;
}

/**
 * Sends all the bytes from the stream to the server.
 * @param  s   The socket to stream to.
 * @param  buf The buffer to stream.
 * @param  len The length of the stream, stores how many bytes sent (via pointer).
 * @return     0 on success, -1 on failure.
 */
int sendall(int s, char *buf, int *len)
{
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;

    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here

    return n==-1?-1:0; // return -1 on failure, 0 on success
}
