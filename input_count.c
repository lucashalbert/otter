#include <stdio.h>
#include <stdlib.h>

// Process functions
int syn_process(char **syn_data, FILE *outp);
int ack_process(char **ack_data, FILE *outp);
void print_usage();

int main(int argc, char *argv[]) {
	FILE *outp;
	printf("# of Args %d \n",argc);
	printf("argv[1] %s\n", argv[1]);
//	printf("argv[2] %s\n\n", argv[2]);
//	printf("argv[3] %s\n", argv[3]);
//      printf("argv[4] %s\n\n", argv[4]);
	if (argc < 2) {
		printf("Fatal Usage Error\n");
	        print_usage();
		//printf("Usage:\n-S for SYN processing\n-A for SYN-ACK processing\n\n");
	        return 0;
	}

	if (strcmp(argv[1], "-S") == 0) {
		printf("SYN function\n");
		//outp = fopen("syn.log", "a");
		//send argv[2] to SYN stream capture
	}
	else if (strcmp(argv[1], "-A") == 0) {
		printf("SYN-ACK function\n");
		//outp = fopen("syn-ack.log", "a");
		//send argv[2] to SYN-ACK stream capture
	}
	else {
		printf("Fatal Usage Error\n");
                print_usage();
		return 0;
	}
/*	
	if (strcmp(argv[3], "-S") == 0) {
                printf("SYN function\n");
                //send argv[4] to SYN stream capture
	}
	else if (strcmp(argv[3], "-A") == 0) {
		printf("SYN-ACK function\n");
	        //send argv[4] to SYN-ACK stream capture
	}
	else {
		printf("Fatal Usage Error\n");
		print_usage();
		//printf("Usage:\n-S for SYN processing\n-A for SYN-ACK processing\n\n");
		return 0;
	}
*/
	int count = 1;
	char *readin = NULL;
	int exit_char = 0;
	size_t slen = 0;

// Actually daemonize
// Check existence of DB and initialize if it does not
// table: ip; syn-print; sack-print; (mac? maybe...)
   printf("OPENING A STREAM!\n");
   if (stdin == NULL) { printf("OH NOES!\n"); exit(1); }
   printf("STREAM OPEN, ENTERING LOOP!\nTo exit daemon type \"Ctrl-D\"\n");

	while(1) {
		/*scanf("%c", exit_char);*/
		//printf("Exit Character:  %s \n", exit_char);
		//printf("Exit Character:  %s \n", exit_char);
		while((exit_char=getchar()) == EOF) {
			printf("Exiting input count daemon\n");
			//fclose(outp);
			return 0;
		}
		
		// POTENTIAL BUG: getline returns -1 in EOF, but also on other errors
		// clear all variables changed in loop every loop
		//		
		if(getline(&readin, &slen, stdin) != -1) {
			//printf("FOUND A LINE! NUMBER: %d\n", count);
			//process info collected process();
			//printf("Processing %s \n", readin);
			//printf("size_t %zd \n", slen);
			if (strcmp(argv[1], "-S") == 0) {
				//printf("SYN function\n");
				syn_process(&readin, outp);				
			}
			else if (strcmp(argv[1], "-A") == 0) {
				//printf("SYN-ACK function\n");
				ack_process(&readin, outp);
				//send argv[2] to SYN-ACK stream capture
			}
			// grab source and fingerprint (with regex)
			// existing_syn=(SELECT syn FROM table WHERE IP=$ip)
			// if existing_syn == NULL => new_node alert; print to found nodes file
			// elsif existing_sys != greped_sys => rouge node alert
			// else {}
			count++;
		}
		// Another if group to cover the SYN-ACK
		else {
			printf("NO LINE FOUND, WAITING 10secs\n");
			sleep(10);
		}
	}
}

void print_usage()
{
	printf("Print Usage Function\n");
	printf("Usage:\n-S for SYN processing\n-A for SYN-ACK processing\n\n");
	return;
}

int syn_process(char **syn_data, FILE *outp)
{
	//print p0f data to syn.log file
	//printf("SYN_process() function. \n");
	outp = fopen("syn.log", "a");
	fprintf(outp, "Data: %s", *syn_data);
	fclose(outp);
	//printf("Data: %s \n", *syn_data);
	//fclose(outp);
	return;
}

int ack_process(char **ack_data, FILE *outp)
{
	//print p0f data to syn-ack.log file
	//printf("ACK_process() function. \n");
	outp = fopen("syn-ack.log", "a");
	fprintf(outp, "Data: %s", *ack_data);
	fclose(outp);
	//printf("Data: %s \n", *ack_data);
	return;
}
