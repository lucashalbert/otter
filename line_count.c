#include <stdio.h>
#include <stdlib.h> 
int main(int argc, char *argv[]) {
   FILE *read;
   int count = 1;
   char *readin = NULL;
   size_t slen = 0;

// Actually daemonize
// Check existence of DB and initialize if it does not
// table: ip; syn-print; sack-print; (mac? maybe...)
   printf("OPENING A FILE!\n");
   read = fopen(argv[1], "r");
   if (read == NULL) { printf("OH NOES!\n"); exit(1); }
   printf("FILE OPEN, ENTERING LOOP!\n");
   while(1) {
// POTENTIAL BUG: getline returns -1 in EOF, but also on other errors
// clear all variables changed in loop every loop
      if(getline(&readin, &slen, read) != -1) {
         printf("FOUND A LINE! NUMBER: %d\n", count);
//       grab source and fingerprint (with regex)
//       existing_syn=(SELECT syn FROM table WHERE IP=$ip)
//       if existing_syn == NULL => new_node alert; print to found nodes file
//       elsif existing_sys != greped_sys => rouge node alert
//       else {} 
         count++;
      }
//    Another if group to cover the  
     else {
         printf("NO LINE FOUND, WAITING 10secs\n");
         sleep(10);
      }
   }
}
