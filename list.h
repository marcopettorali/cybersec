#include <sys/socket.h>
#include"util.h"

struct node {
   //Info of local player
   char nickname[NICKNAME_LENGTH];
   struct sockaddr_in address;
   long thread_id;
   bool accepted;
   //fill by adversary
   char adversary_nickname[NICKNAME_LENGTH];
   struct sockaddr_in adversary_address;
   pthread_cond_t waiting_response;
   struct node *next;
};

void printList(struct node *head);
void printListInBuffer(struct node *head, char * buffer);
struct node* insertFirst(struct node **head,long thread_id, char* nickname, struct sockaddr_in address);
struct node* deleteFirst(struct node **head);
bool isEmpty(struct node *head);
int length(struct node *head);
struct node* find(struct node *head,long thread_id);
struct node* get_node_by_nickname(struct node *head,char* nickname);
struct node* set(struct node *head,bool accepted,char* adversary_nickname, struct sockaddr_in adversary_address);
struct node* delete_elem(struct node **head, long thread_id);
