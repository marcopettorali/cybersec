#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "list.h"


//display the list
void printList(struct node *head) {
   struct node *ptr = head;
   printf("\n[ ");
	
   //start from the beginning
   while(ptr != NULL) {
      printf("(%ld,%s,%d,Enemy->%s) ",ptr->thread_id,ptr->nickname,ptr->accepted,ptr->adversary_nickname);
      ptr = ptr->next;
   }
	
   printf(" ]\n");
}

//print the list in a buffer (to be sent)
void printListInBuffer(struct node *head, char * buffer) {
   struct node *ptr = head;
   sprintf(buffer,"\n[ ");
	
   //start from the beginning
   while(ptr != NULL) {
      sprintf(buffer + strlen(buffer),"(%ld,%s,%d,Enemy->%s) ",ptr->thread_id,ptr->nickname,ptr->accepted,ptr->adversary_nickname);
      ptr = ptr->next;
   }
	
   sprintf(buffer + strlen(buffer)," ]\n");
}

//insert link at the first location
struct node* insertFirst(struct node **head,long thread_id, char* nickname, struct sockaddr_in address) {
   //create a link
   struct node *link = (struct node*) malloc(sizeof(struct node));
	
   link->thread_id = thread_id;
   if(strlen(nickname)>NICKNAME_LENGTH)
       nickname[NICKNAME_LENGTH]='\0';
   strcpy(link->nickname,nickname);
   memcpy(&link->address, &address , sizeof(struct sockaddr_in));
   //Initialize the other params
   link->accepted = false;
   strncpy(link->adversary_nickname, "", NICKNAME_LENGTH);
   link->adversary_nickname[NICKNAME_LENGTH]='\0';
   pthread_cond_init(&link->waiting_response,NULL);
	
   //point it to old first node
   link->next = (*head);
	
   //point first to new first node
   *head = link;

   return link;
}

//delete first item
struct node* deleteFirst(struct node **head) {

   //save reference to first link
   struct node *tempLink = *head;
	
   //mark next to first link as first 
   *head = (*head)->next;
	
   //return the deleted link
   return tempLink;
}

//is list empty
bool isEmpty(struct node *head) {
   return head == NULL;
}

int length(struct node *head) {
   int length = 0;
   struct node *current;
	
   for(current = head; current != NULL; current = current->next) {
      length++;
   }
	
   return length;
}

//find a link with given thread_id
struct node* find(struct node *head,long thread_id) {

   //start from the first link
   struct node* current = head;

   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while(current->thread_id != thread_id) {
	
      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //go to next link
         current = current->next;
      }
   }      
	
   //if data found, return the current Link
   return current;
}

void reset_after_gaming(struct node* guest_node){
   if(guest_node == NULL)
      return;
   guest_node->accepted=false;
   strncpy(guest_node->adversary_nickname, "", NICKNAME_LENGTH);
   guest_node->adversary_nickname[NICKNAME_LENGTH]='\0';
}



//find a link with given thread_id
struct node* get_node_by_nickname(struct node *head,char* nickname) {

   //start from the first link
   struct node* current = head;

   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while(strcmp(current->nickname,nickname)!=0) {
	
      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //go to next link
         current = current->next;
      }
   }      
	
   //if data found, return the current Link
   return current;
}

//delete a link with given thread_id
struct node* delete_elem(struct node **head, long thread_id) {

   //start from the first link
   struct node* current = *head;
   struct node* previous = NULL;
	
   //if list is empty
   if(*head == NULL) {
      return NULL;
   }

   //navigate through list
   while(current->thread_id != thread_id) {

      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //store reference to current link
         previous = current;
         //move to next link
         current = current->next;
      }
   }

   //found a match, update the link
   if(current == *head) {
      //change first to point to next link
      *head = (*head)->next;
   } else {
      //bypass the current link
      previous->next = current->next;
   }    
	
   return current;
}

/*
struct node *head = NULL;

void main() {
   insertFirst(&head,1,"graziano");
   insertFirst(&head,2,"silvano");

   printf("Original List: "); 
	
   //print list
   printList(head);

   while(!isEmpty(head)) {            
      struct node *temp = deleteFirst(&head);
      printf("\nDeleted value:");
      printf("(%d,%s) ",temp->thread_id,temp->nickname);
   }  
	
   printf("\nList after deleting all items: ");
   printList(head);

   insertFirst(&head,1,"graziano");
   insertFirst(&head,2,"silvano");
   insertFirst(&head,3,"orazio");

   struct node *foundLink = find(head,1);
	
   if(foundLink != NULL) {
      printf("Element found: ");
      printf("(%d,%s) ",foundLink->thread_id,foundLink->nickname);
      printf("\n");  
   } else {
      printf("Element not found.");
   }

   delete_elem(&head,2);
   printf("List after deleting an item: ");
   printList(head);

}*/