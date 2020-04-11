#include"util.h"

struct node {
   char nickname[NICKNAME_LENGTH];
   long thread_id;
   bool gaming;
   struct node *next;
};

void printList(struct node *head);
void insertFirst(struct node **head,long thread_id, char* nickname);
struct node* deleteFirst(struct node **head);
bool isEmpty(struct node *head);
int length(struct node *head);
struct node* find(struct node *head,long thread_id);
struct node* set(struct node *head,long thread_id,bool gaming);
struct node* delete_elem(struct node **head, long thread_id);
