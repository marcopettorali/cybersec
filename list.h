#include <sys/socket.h>

#include "util.h"

typedef struct {
    // Info of local player
    char nickname[NICKNAME_LENGTH];
    struct sockaddr_in address;
    long thread_id;
    bool accepted;
    // fill by adversary
    char adversary_nickname[NICKNAME_LENGTH];
    struct sockaddr_in adversary_address;
    pthread_cond_t waiting_response;
    node *next;
} node;

void print_list(node *head);
void print_list_in_buffer(node *head, char *buffer);
node *insert_first(node **head, long thread_id, char *nickname, struct sockaddr_in address);
node *delete_first(node **head);
bool isEmpty(node *head);
int get_length(node *head);
node *find(node *head, long thread_id);
node *get_node_by_nickname(node *head, char *nickname);
node *set(node *head, bool accepted, char *adversary_nickname, struct sockaddr_in adversary_address);
void reset_after_gaming(node *user_node);
node *delete_elem(node **head, long thread_id);
