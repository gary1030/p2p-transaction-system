#ifndef MYQUEUE_H_
#define MYQUEUE_H_
#include <openssl/ssl.h>
#include <iostream>

struct node {
    struct node* next;
    int *client_socket;
    SSL *ssl;
};

typedef struct node node_t;

void enqueue(int *client_socket, SSL *ssl);
std::pair<int*, SSL*> dequeue();

#endif