#define MAX_LEN 2000
#define ARGS_LEN 6
#define NUM_CLIENTS 5
#define CHUNK_SIZE 1024
#define DIE(MSG){perror(MSG);exit(1);}
#define ERR(NUM,CODE){fprintf(stderr, "%s", ERRMSG[NUM]);exit(CODE);}
#define h_addr h_addr_list[0]
