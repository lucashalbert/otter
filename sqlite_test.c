/* sqlite query test
Lucas Halbert
*/

#include<stdio.h>
#include<sqlite3.h>
#include<stdlib.h>

int main(int argc, char** args)
{
    // Create an int variable for storing the return code for each call
    int retval;
    
    // The number of queries to be handled,size of each query and pointer
    int q_cnt = 5,q_size = 150,ind = 0;
    char **queries = malloc(sizeof(char) * q_cnt * q_size);
        
    // A prepered statement for fetching tables
    sqlite3_stmt *stmt;
    
    // Create a handle for database connection, create a pointer to sqlite3
    sqlite3 *handle;
    
    // try to create the database. If it doesnt exist, it would be created
    // pass a pointer to the pointer to sqlite3, in short sqlite3**
    retval = sqlite3_open("sampledb.sqlite3",&handle);
    // If connection failed, handle returns NULL
    if(retval)
    {
        printf("Database connection failed\n");
        return -1;
    }
    printf("Connection successful\n");
    
    /*
    // Create the SQL query for creating a table
    char create_table[150] = "CREATE TABLE IF NOT EXISTS prints (sip TEXT PRIMARY KEY,smac TEXT,dmac TEXT,syn_print TEXT,ack_print TEXT)";
    
    // Execute the query for creating the table
    retval = sqlite3_exec(handle,create_table,0,0,0);
    if(retval) 
    {
    	printf("Error while creating table\n");
    	return -1;
    }
    // Insert first row and second row
    queries[ind++] = "INSERT INTO prints VALUES('192.168.195.243','00:19:D1:9F:3B:E2','dest-mac','syn-print','ack-print')";
    retval = sqlite3_exec(handle,queries[ind-1],0,0,0);
    queries[ind++] = "INSERT INTO prints VALUES('150.156.201.20','00:15:5D:C0:65:2E','dest-mac','syn-print','ack-print')";
    retval = sqlite3_exec(handle,queries[ind-1],0,0,0);
    */

    // select those rows from the table
    queries[ind++] = "SELECT * from prints";
    retval = sqlite3_prepare_v2(handle,queries[ind-1],-1,&stmt,0);
    if(retval)
    {
        printf("Selecting data from DB Failed\n");
        return -1;
    }
    
    // Read the number of rows fetched
    int cols = sqlite3_column_count(stmt);
    while(1)
    {
        // fetch a row's status
        retval = sqlite3_step(stmt);
        if(retval == SQLITE_ROW)
        {
            // SQLITE_ROW means fetched a row
            // sqlite3_column_text returns a const void* , typecast it to const char*
            for(int col=0 ; col<cols;col++)
            {
                const char *val = (const char*)sqlite3_column_text(stmt,col);
                printf("%s = %s\t",sqlite3_column_name(stmt,col),val);
            }
            printf("\n");
        }
        else if(retval == SQLITE_DONE)
        {
            // All rows finished
            printf("All rows fetched\n");
            break;
        }
        else
        {
            // Some error encountered
            printf("Some error encountered\n");
            return -1;
        }
    }
    
    // Close the handle to free memory
    sqlite3_close(handle);
    return 0;
}
