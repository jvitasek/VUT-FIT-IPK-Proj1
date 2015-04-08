#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <pwd.h>
#include "macros.h"

char *ERRMSG[] = {
	"Wrong arguments!\n"
};

unsigned int port_server = 0;
int L, U, G, N, H, S, is_login, is_uid = 0;
char *hostname, *uid_str = "";
unsigned int port_client = 0;
int logincount, uidcount = 0;
int pwdsize = 0;
uid_t uids[100] = {0};
struct passwd *pwd_arr[100] = {0};

void getargs_server(int, char **);
void printhelp();

/**
 * The main server-client functionality carried out in this section.
 * @param  argc The number of arguments passed.
 * @param  argv The argument vector containing the passed arguments.
 * @return int  The success/failure code.
 */
int main(int argc, char *argv[])
{
	// if there is no parameter passed
	if(argc < 2)
		ERR(0,2);

	// getting the user-side parameters
	getargs_server(argc, argv);

	// CONNECTION VARIABLES
	int socket_desc, client_sock, client_sock_len, pid;
	struct sockaddr_in socket_addr;
	struct hostent *host;
	char args_buffer[CHUNK_SIZE], login_buff[CHUNK_SIZE], uid_buff[CHUNK_SIZE] = {0};
	char *result_buffer[CHUNK_SIZE] = {0}; 
	char *logins[100];
	

	//=====================================================
	// SETTING UP THE CONNECTION
	//=====================================================

	// creating a socket
	if((socket_desc = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		DIE("Socket Error");

	// protocol family -> internet (IPv4)
	socket_addr.sin_family = PF_INET;
	// port number defined by user-side parameters (-p [port])
	socket_addr.sin_port = htons(port_server);
	// IP address can be any interface
	socket_addr.sin_addr.s_addr = INADDR_ANY;

	// binding the socket to the port
	if(bind(socket_desc, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
		DIE("Bind Error");

	// listening for a connection
	if(listen(socket_desc, NUM_CLIENTS))
		DIE("Listen Error");

	// holds the size of the socket address
	client_sock_len = sizeof(socket_addr);

	//=====================================================
	// KEEP THE SERVER RUNNING FOREVER
	//=====================================================
	while(1)
	{
		// accepting a connection request
		if((client_sock = accept(socket_desc, (struct sockaddr *)&socket_addr, (socklen_t *)&client_sock_len)) < 0)
			DIE("Accept Error");

		//=====================================================
		// FORKING TO ENABLE MULTIPLE CLIENTS
		//=====================================================

		if((pid = fork()) < 0)
			DIE("Fork Error");
		if(pid == 0) // child process
		{
			// host port
			host = (struct hostent *)gethostbyaddr((char *)&socket_addr.sin_addr, 4, AF_INET);
			// From [IP] ([hostname]):[PORT]
			printf("Connection [%s (%s:%d)]\n", host->h_name, inet_ntoa(socket_addr.sin_addr), ntohs(socket_addr.sin_port));

			//=====================================================
			// READ THE CLIENT USER-SIDE PARAMETERS
			//=====================================================
			if(recv(client_sock, args_buffer, sizeof(args_buffer), 0) < 0) 
				DIE("Receive Error");

			// assigning the state of the user-side parameters to server variables
			L = args_buffer[0] - '0'; // name
			U = args_buffer[1] - '0'; // uid
			G = args_buffer[2] - '0'; // gid
			N = args_buffer[3] - '0'; // gecos
			H = args_buffer[4] - '0'; // homedir
			S = args_buffer[5] - '0'; // shell
			is_login = args_buffer[6] - '0'; // login passed
			is_uid = args_buffer[7] - '0'; // uid passed
			logincount = args_buffer[8] - '0'; // how many logins
			uidcount = args_buffer[9] - '0'; // how many uids

			// acknowledgment
			if(send(client_sock, args_buffer, sizeof(args_buffer), 0) < 0)
				DIE("Acknowledge Error");

			//=====================================================
			// READ THE CLIENT PASSED LOGIN OR UID
			//=====================================================
			if(is_login == 1) // login
			{
				char log_res_str[CHUNK_SIZE] = {0};
				for(int i = 0; i < logincount; i++)
				{
					int lenf = 0;
					int received = 0;
					memset(login_buff, 0, sizeof(login_buff));

					// the length of the UID stored in the first byte
					if((received = recv(client_sock, login_buff, CHUNK_SIZE, 0)) < 0)
						DIE("Receive Error");

					// getting the lenght of the login
					lenf = login_buff[0] - '0';
					for(int count = 1; count < lenf; count++)
						log_res_str[count-1] = login_buff[count];

					logins[i] = strdup(log_res_str);

					// acknowledgment
					if(send(client_sock, login_buff, sizeof(login_buff), 0) < 0)
						DIE("Acknowledge Error");
				}
				pwdsize = logincount;

				for(int i = 0; i < pwdsize; i++)
					pwd_arr[i] = getpwnam(logins[i]);
			}
			else if(is_uid == 1) // UID
			{
				for(int i = 0; i < uidcount; i++)
				{
					int lenf = 0;
					int received = 0;
					memset(uid_buff, 0, sizeof(uid_buff));

					// the length of the UID stored in the first byte
					if((received = recv(client_sock, uid_buff, CHUNK_SIZE, 0)) < 0)
						DIE("Receive Error");

					// getting the lenght of the UID
					lenf = uid_buff[0] - '0';
					char uid_res_string[CHUNK_SIZE] = {0};
					for(int count = 1; count < lenf; count++)
						uid_res_string[count-1] = uid_buff[count];
					uid_str = uid_res_string;
					// storing the UID in the UIDs array
					uids[i] = (uid_t)strtol(uid_str, (char **)NULL, 10);

					// acknowledgment
					if(send(client_sock, uid_buff, sizeof(uid_buff), 0) < 0)
						DIE("Acknowledge Error");
				}
				pwdsize = uidcount;

				for(int i = 0; i < pwdsize; i++)
					pwd_arr[i] = getpwuid(uids[i]);
					
			}

			//=====================================================
			// GET THE PASSWD INFORMATION
			//=====================================================
			for(int i = 0; i < pwdsize; i++)
			{
				// RESULT VARIABLES
				char *name = "";
				uid_t uid_fin = 0;
				gid_t gid_fin = 0;
				char *gec = "";
				char *home = "";
				char *sh = "";
				char resultstring[CHUNK_SIZE] = {0};

				if(pwd_arr[i] == NULL)
				{
					if(logincount == 1 || uidcount == 1)
						snprintf(resultstring, sizeof(resultstring), "&Unknown UID or login!;");
					else if(i == 0)
						snprintf(resultstring, sizeof(resultstring), "&Unknown UID or login!\n");
					else if(i == (pwdsize-1))
						snprintf(resultstring, sizeof(resultstring), "Unknown UID or login!;");
					else
						snprintf(resultstring, sizeof(resultstring), "Unknown UID or login!\n");
					result_buffer[i] = strdup(resultstring);
					continue;
				}

				if(L == 1)
					name = pwd_arr[i]->pw_name;
				if(U == 1)
					uid_fin = pwd_arr[i]->pw_uid;
				if(G == 1)
					gid_fin = pwd_arr[i]->pw_gid;
				if(N == 1)
					gec = pwd_arr[i]->pw_gecos;
				if(H == 1)
					home = pwd_arr[i]->pw_dir;
				if(S == 1)
					sh = pwd_arr[i]->pw_shell;

				if(logincount == 1 || uidcount == 1)
				{
					if(U == 1 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "&%s %u %u %s %s %s;", name, uid_fin, gid_fin, gec, home, sh);
					else if(U == 1 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "&%s %u %s %s %s;", name, uid_fin, gec, home, sh);
					else if(U == 0 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "&%s %u %s %s %s;", name, gid_fin, gec, home, sh);
					else if(U == 0 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "&%s %s %s %s;", name, gec, home, sh);			
				}
				else if(i == 0) // START -> we delimit the beginning of the results
				{
					if(U == 1 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "&%s %u %u %s %s %s\n", name, uid_fin, gid_fin, gec, home, sh);
					else if(U == 1 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "&%s %u %s %s %s\n", name, uid_fin, gec, home, sh);
					else if(U == 0 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "&%s %u %s %s %s\n", name, gid_fin, gec, home, sh);
					else if(U == 0 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "&%s %s %s %s\n", name, gec, home, sh);
				}
				else if(i == (pwdsize-1)) // END -> we delimit the end of the result
				{
					if(U == 1 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "%s %u %u %s %s %s;", name, uid_fin, gid_fin, gec, home, sh);
					else if(U == 1 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "%s %u %s %s %s;", name, uid_fin, gec, home, sh);
					else if(U == 0 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "%s %u %s %s %s;", name, gid_fin, gec, home, sh);
					else if(U == 0 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "%s %s %s %s;", name, gec, home, sh);
				}
				else
				{
					if(U == 1 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "%s %u %u %s %s %s\n", name, uid_fin, gid_fin, gec, home, sh);
					else if(U == 1 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "%s %u %s %s %s\n", name, uid_fin, gec, home, sh);
					else if(U == 0 && G == 1)
						snprintf(resultstring, sizeof(resultstring), "%s %u %s %s %s\n", name, gid_fin, gec, home, sh);
					else if(U == 0 && G == 0)
						snprintf(resultstring, sizeof(resultstring), "%s %s %s %s\n", name, gec, home, sh);
				}
				result_buffer[i] = strdup(resultstring);
			}


			//=====================================================
			// SENDING THE RESULTS BACK TO THE CLIENT
			//=====================================================

			for(int i = 0; i < pwdsize; i++)
				if(send(client_sock, result_buffer[i], strlen(result_buffer[i]), 0) < 0)
			 		DIE("Send Error");
		}
		if(close(client_sock) < 0)
			DIE("Close Error");
	}
	// closing the whole socket
	if(close(socket_desc) < 0) 
		DIE("Close Error");

	return 0;
}

/**
 * Get the arguments passed by the user.
 * @param argc The number of arguments passed.
 * @param argv The argument vector containing the passed arguments.
 */
void getargs_server(int argc, char *argv[])
{
	char opt;
	while((opt = getopt(argc, argv, "p:")) != -1)
	{
		switch(opt)
		{
			case 'p':
				// converting the port to number directly
				port_server = strtol(optarg, (char **)NULL, 10);
				break;
			case '?':
				ERR(0,2);
			default:
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
	printf("\n\033[32;1m Usage: \033[0m\n-p [port]\tEnter the port number to be opened by the server.\n\n");
	exit(0);
}
