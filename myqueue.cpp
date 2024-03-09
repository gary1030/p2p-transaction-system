#include "myqueue.h"
#include <stdlib.h>
#include <openssl/ssl.h>
#include <utility>
#include <iostream>

using namespace std;

node_t* head = NULL;
node_t* tail = NULL;

void enqueue(int *client_socket, SSL *ssl) {
    node_t *newnode = (node_t*) malloc(sizeof(node_t));
    newnode->client_socket = client_socket;
    newnode->next = NULL;
    newnode->ssl = ssl;
    if(tail == NULL){
        head = newnode;
    } else {
        tail->next = newnode;
    }
    tail = newnode;
}

std::pair<int*, SSL*> dequeue() {
    if (head == NULL) {
        return make_pair(nullptr, nullptr);
    } 
    int *result = head->client_socket;
    SSL *ssl = head->ssl;
    node_t *temp = head;
    head = head->next;
    if (head == NULL)  {tail = NULL;}
    free(temp);
    return make_pair(result, ssl);
}