#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <fcntl.h>

#include "util.h"
#include "list.h"

typedef struct {
    int sock;
    struct sockaddr address;
    int addr_len;
} Connection;

struct node *head_of_list_users = NULL;
pthread_mutex_t mutex_list_users;

void prepareListUser(char * info){
    printListInBuffer(head_of_list_users,info);
}


/** Returns true on success, or false if there was an error */
bool SetSocketBlockingEnabled(int fd, bool blocking)
{
   if (fd < 0) return false;

#ifdef _WIN32
   unsigned long mode = blocking ? 0 : 1;
   return (ioctlsocket(fd, FIONBIO, &mode) == 0) ? true : false;
#else
   int flags = fcntl(fd, F_GETFL, 0);
   if (flags == -1) return false;
   flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
   return (fcntl(fd, F_SETFL, flags) == 0) ? true : false;
#endif
}

bool try_to_challenge(char * adversary_nickname,struct node * node_of_guest,uint16_t * adversary_port){
    pthread_mutex_lock(&mutex_list_users);
    struct node * node_of_adversary = get_node_by_nickname(head_of_list_users,adversary_nickname);
    if(node_of_adversary==NULL){
        printf("[%s]:Not exist such a nickname!\n",node_of_guest->nickname);
        pthread_mutex_unlock(&mutex_list_users);
        return false;
    }
    if(strcmp(node_of_adversary->adversary_nickname,"")!=0){
        printf("%s is busy already with %s\n",node_of_adversary->adversary_nickname,adversary_nickname);
        pthread_mutex_unlock(&mutex_list_users);
        return false;
    }
    printf("[%s]: We can try to challenge\n",node_of_guest->nickname);
    node_of_adversary->accepted=false;
    //we prepare our nick in his node
    strncpy(node_of_adversary->adversary_nickname,node_of_guest->nickname,NICKNAME_LENGTH);
    while (node_of_adversary->accepted==false && (strcmp(node_of_adversary->adversary_nickname,"")!=0)){
        printf("[%s]: waiting a response from %s\n",node_of_guest->nickname,adversary_nickname);
        pthread_cond_wait(&node_of_adversary->waiting_response,&mutex_list_users);
    }

    printf("[%s]: is awake\n",node_of_guest->nickname);
    if(strcmp(node_of_adversary->adversary_nickname,node_of_guest->nickname)==0){
        //he has accepted
        //MODIFY OUR NODE WRITING ADVERSARY_NICK
        node_of_guest->accepted=true;
        strncpy(node_of_guest->adversary_nickname,adversary_nickname,NICKNAME_LENGTH);
        *adversary_port= htons(node_of_adversary->address.sin_port);
        pthread_cond_signal(&node_of_guest->waiting_response); //so whoever is waiting for us will be woken up to discover that he's been rejected
        pthread_mutex_unlock(&mutex_list_users);
        return true;

    }
    pthread_mutex_unlock(&mutex_list_users);
    return false;
}

bool check_pending_request(struct node * node_of_guest, int sock){
    int guest_answer;

    pthread_mutex_lock(&mutex_list_users); //otherwise can be changed
    if((strcmp(node_of_guest->adversary_nickname,"")==0) || (node_of_guest->accepted==true)){
        pthread_mutex_unlock(&mutex_list_users);
        printf("[%s]: Pending request? false\n",node_of_guest->nickname);
        return false;
    }
    pthread_mutex_unlock(&mutex_list_users);
    printf("[%s]: Pending request? true\n",node_of_guest->nickname);
    printf("[%s]: has found a request by %s\n",node_of_guest->nickname,node_of_guest->adversary_nickname);
    printf("[%s]: I have to ask my guest if it wants to accept\n",node_of_guest->nickname);
    //ASK (send a special opcode = 3)
        //reset sock to blocking
        if(SetSocketBlockingEnabled(sock,true)==false){
            printf("[%s]: Error in setting blocking socket\nI've to abort!",node_of_guest->nickname);
        }
        //send 3 and later send nickname of opponent //AT THE END, ONCE MEX FORMATS HAVE BEEN DEFINED, JUST SEND 1 MEX
        //then wait for the answer
        int opcode = 3;
        send(sock, &opcode, sizeof(int), 0);
        send(sock,node_of_guest->adversary_nickname,strlen(node_of_guest->adversary_nickname)+1,0);
        read(sock, &guest_answer, sizeof(int));
        //printf("[%s]: It should be asked guest --> 1/0? ",node_of_guest->nickname); ///MAYBE USE ANOTHER SOCKET NOT BLOCKING FOR THE CLIENT SO THAT PERIODICALLY CHECK IF SOMEONE HAS REQUESTED TO PLAY WITH HIM
        //scanf("%d",&guest_answer);
    //
    pthread_mutex_lock(&mutex_list_users);
    if(guest_answer==true){ //has accepted
        node_of_guest->accepted=true;
        pthread_cond_signal(&node_of_guest->waiting_response);
        //we should wait until our guest had finished to play
    } else{
        node_of_guest->accepted=false;
        strncpy(node_of_guest->adversary_nickname,"",NICKNAME_LENGTH);
        pthread_cond_signal(&node_of_guest->waiting_response);
    }
    pthread_mutex_unlock(&mutex_list_users);

    //reset to non-blocking
    if(SetSocketBlockingEnabled(sock,false)==false){
            printf("[%s]: Error in setting non-blocking socket\nI've to abort!",node_of_guest->nickname);
    }

    return true;
}

//JUST TO TRY (to choose the username to assign the user: in truth it will be assigned basing of FILE OF PUBKEYs)
int name=0;

void *thread_handler_client(void *ptr) {
    Connection *conn;
    long addr = 0;
    struct sockaddr_in user_address;

    int msg = MSG_OK;
    char* buffer = (char*)malloc(COMMAND_SIZE);
    char* command = (char*)malloc(COMMAND_SIZE);
    
    //Just to test
    int commandInt;
    int len;
    bool result;
    char guest_nickname[NICKNAME_LENGTH]; //WILL BE OBTAINED BY FILE IN WHICH THERA ARE STORED PUBKEYS
    struct node * node_of_guest;
    uint16_t adversary_port;


    if (!ptr) pthread_exit(0);
    conn = (Connection *)ptr;


    /*char ip[INET_ADDRSTRLEN]; 
        inet_ntop(AF_INET, &((struct sockaddr_in *)&conn->address)->sin_addr.s_addr, ip, INET_ADDRSTRLEN); 
      
        // "ntohs(peer_addr.sin_port)" function is  
        // for finding port number of client
        printf("Port-> %d\n",((struct sockaddr_in *)&conn->address)->sin_port);
        printf("connection established with IP : %s and PORT : %d\n",  
                                            ip, ntohs(((struct sockaddr_in *)&conn->address)->sin_port));
    */
    user_address.sin_addr.s_addr =  ((struct sockaddr_in *)&conn->address)->sin_addr.s_addr;
    user_address.sin_family = AF_INET;
    user_address.sin_port = htons(PORT_FOR_GAMING); //GOOD IF USERS ARE ON DIFFERENT MACHINES (as it should.. but not in our case)
    //subscribe the user's presence
    //WILL BE PROTECTED BY MUTEX
    pthread_mutex_lock(&mutex_list_users);
    if(name==0){
        strncpy(guest_nickname,"graziano",NICKNAME_LENGTH);
        node_of_guest = insertFirst(&head_of_list_users,(long)pthread_self(),"graziano",user_address);
    }
    if(name==1){
        strncpy(guest_nickname,"silvano",NICKNAME_LENGTH);
        node_of_guest = insertFirst(&head_of_list_users,(long)pthread_self(),"silvano",user_address);
    }
    if(name==2){
        strncpy(guest_nickname,"loriano",NICKNAME_LENGTH);
        node_of_guest = insertFirst(&head_of_list_users,(long)pthread_self(),"loriano",user_address);
    }
    if(name==3){
        strncpy(guest_nickname,"oreste",NICKNAME_LENGTH);
        node_of_guest = insertFirst(&head_of_list_users,(long)pthread_self(),"oreste",user_address);
    }
    name++;    
    pthread_mutex_unlock(&mutex_list_users);
    
    // LOGIC OF APP
    while (1) {
        //memset(buffer, 0, COMMAND_SIZE);
		//memset(command, 0, COMMAND_SIZE);
        /*if (len > 0) {
            addr = (long)((struct sockaddr_in *)&conn->address)->sin_addr.s_addr;
            buffer = (char *)malloc((len + 1) * sizeof(char));
            buffer[len] = 0;

            // read message 
            read(conn->sock, buffer, len);

            // print message 
            printf("%d.%d.%d.%d: %s\n", (int)((addr)&0xff), (int)((addr >> 8) & 0xff), (int)((addr >> 16) & 0xff), (int)((addr >> 24) & 0xff),
                   buffer);

            free(buffer);
        } else{
            break;
        }*/

        //CHECK IF PENDING REQUEST
        //printf("[%s]: Pending request? %d\n",guest_nickname,check_pending_request(node_of_guest));

        /*
		if (msg != MSG_OK) {
            //write something to the client
            sprintf(command,"%d",msg);
            write(conn->sock, &command, strlen(command));
			msg = MSG_OK;
		}*/

        /* read message */
        //Even if "L'attesa attiva del processore è immorale" cit.Corsini
        //HAS TO BE NON-BLOCKING OTHERWISE THIS THREAD CANNOT SEE A PENDING REQUEST UNTIL THE CLIENT HAS SENT SOMETHING
        if(SetSocketBlockingEnabled(conn->sock,false)==false){
            printf("[%s]: Error in setting non-blocking socket\nI've to abort!",guest_nickname);
        }
        do
        {
            //sleep a bit otherwise too much overhead
            sleep(2);
            //CHECK IF PENDING REQUEST
            check_pending_request(node_of_guest,conn->sock);
            //CHECK IF THE CLIENT HAS SENT SOMETHING
        }while(read(conn->sock, &commandInt, sizeof(int))<=0);
        
        

        printf("[%s]: we've received -> %d\n",guest_nickname ,commandInt);

        //Come back to blocking socket
        if(SetSocketBlockingEnabled(conn->sock,true)==false){
            printf("[%s]: Error in setting blocking socket\nI've to abort!",guest_nickname);
        }

		if (commandInt == 1) {
            printf("[%s]: He's required the list!\n",guest_nickname);

            //to avoid that some user can be cancelled or added in the meanwhile
            memset(command, 0, COMMAND_SIZE);
            pthread_mutex_lock(&mutex_list_users);
			prepareListUser(command);
            pthread_mutex_unlock(&mutex_list_users);

            printList(head_of_list_users);

            write(conn->sock, command, strlen(command));

		} else if (commandInt == 2) {
            printf("[%s]: He's required to challenge -> ",guest_nickname);
            memset(buffer, 0, COMMAND_SIZE);
            read(conn->sock,buffer,COMMAND_SIZE);
            //In buffer there is the nickname of the opponent he's going to ask to play
            printf("%s\n",buffer);
            result = try_to_challenge(buffer,node_of_guest,&adversary_port);
            printf("[%s]:Has he accepted? %d\n",node_of_guest->nickname,result);
            //inform the client of the answer
            write(conn->sock, &result, sizeof(bool));
            if(result==true){
                //let che client contact the opponent writing him the ip and port
                write(conn->sock, &adversary_port, sizeof(uint16_t));
                    //SHOULD SEND ALSO IP (in our case localhost)
                do{
                    printf("[%s]: Waiting for the end of the game\n",guest_nickname);
                    /* read message */
                    //THE THREAD THAT HANDLEs THE PLAYER WHO HAS REQUESTED TO PLAY FOR FIRST IS BLOCKED HERE
                    read(conn->sock, &commandInt, sizeof(int));
                }while(commandInt!=7);
                //in the meanwhile the server is waiting for the end of game OPCODE
                printf("[%s]: The client has notified the end of the game\n",guest_nickname);
                //reset the info in list_user (accepted = false; adversary_nickname = "")
                pthread_mutex_lock(&mutex_list_users);
                reset_after_gaming(node_of_guest);
                pthread_mutex_unlock(&mutex_list_users);

            }else{
                //the opponent has rejected: inform the client about this

                printf("[%s]: The client has been informed about the denial of challenging\n",guest_nickname);
            }
           

		} else if(commandInt == 6){ //THE CLIENT HAS ALERT THE SERVER THAT HE'S PLAYING P2P
            do{
                printf("[%s]: Waiting for the end of the game\n",guest_nickname);
                //THE THREAD THAT HANDLEs THE PLAYER WHO HAS BEEN CHALLENGED IS BLOCKED HERE
                read(conn->sock, &commandInt, sizeof(int));
            }while(commandInt!=7);

            printf("[%s]: The client has notified the end of the game\n",guest_nickname);
            //reset the info in list_user (accepted = false; adversary_nickname = "")
            pthread_mutex_lock(&mutex_list_users);
            reset_after_gaming(node_of_guest);
            pthread_mutex_unlock(&mutex_list_users);


        }else if(commandInt == 8){ //THE CLIENT INFORMs ITS SERVER THREAD ON WHICH PORT HE WILL LISTEN FOR P2P GAMING
            int client_p2p_port;
            read(conn->sock, &client_p2p_port, sizeof(int));
            pthread_mutex_lock(&mutex_list_users);
            node_of_guest->address.sin_port = htons(client_p2p_port);
            pthread_mutex_unlock(&mutex_list_users);

        }//else if (strcmp(command, "close") == 0) {
         else if (commandInt == -1) { //closing
			break;
		} else {
			msg = MSG_COMMAND_NOT_FOUND;
		}
	
    }

    //update list of active users
    //PROTECT WITH MUTEX!
    pthread_mutex_lock(&mutex_list_users);
    delete_elem(&head_of_list_users,(long)pthread_self());
    pthread_mutex_unlock(&mutex_list_users);
    
    /* close socket and clean up */
    strcpy(command,"closing");
    write(conn->sock, &command, strlen(command));
    close(conn->sock);
    free(conn);
    pthread_exit(0);
}








int main(int argc, char **argv) {
    int sock_main_thread = -1;
    struct sockaddr_in address_server;
    int port;
    Connection *connection_to_client;
    pthread_t thread;

    /* check for command line arguments */
    if (argc != 2) {
        fprintf(stderr, "usage: %s port\n", argv[0]);
        return -1;
    }

    /* obtain port number */
    if (sscanf(argv[1], "%d", &port) <= 0) {
        fprintf(stderr, "%s: error: wrong parameter: port\n", argv[0]);
        return -2;
    }

    /* create socket */
    sock_main_thread = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_main_thread <= 0) {
        fprintf(stderr, "%s: error: cannot create socket\n", argv[0]);
        return -3;
    }

    /* bind socket to port */
    address_server.sin_family = AF_INET;
    address_server.sin_addr.s_addr = INADDR_ANY;
    address_server.sin_port = htons(port);
    if (bind(sock_main_thread, (struct sockaddr *)&address_server, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "%s: error: cannot bind socket to port %d\n", argv[0], port);
        return -4;
    }

    /* listen on port */
    if (listen(sock_main_thread, BACKLOG_LISTEN_QUEUE) < 0) {
        fprintf(stderr, "%s: error: cannot listen on port\n", argv[0]);
        return -5;
    }
    // listen return 0 if ok
    printf("%s: ready and listening\n", argv[0]);


    //Initialize Mutex for list users
    pthread_mutex_init(&mutex_list_users,NULL);

    while (1) {
        /* accept incoming connections */
        connection_to_client = (Connection *)malloc(sizeof(Connection));
        connection_to_client->sock = accept(sock_main_thread, &connection_to_client->address, &connection_to_client->addr_len);
        // check if accept has return a valid socketID
        if (connection_to_client->sock <= 0) {
            free(connection_to_client);
        } else {
            /* start a new thread but do not wait for it */
            pthread_create(&thread, 0, thread_handler_client, (void *)connection_to_client);
            pthread_detach(thread);
        }
    }

    return 0;
}