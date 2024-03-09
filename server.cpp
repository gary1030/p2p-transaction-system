#include <iostream>
#include <string.h>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>	//write
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include "myqueue.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <fstream>

#define SERVERPORT 8888
#define BUFSIZE 4096
#define SOCKETERROR (-1)
#define SERVER_BACKLOG 100
#define MAX_BUFFER_LEN 4096
#define MAX_RECV_LEN 4096
#define THREAD_POOL_SIZE 3

// initilize SSL
SSL_CTX* InitServerCTX()
{
    SSL_CTX *ctx;
    /* SSL 庫初始化 */
    SSL_library_init();
    /* 載入所有 SSL 演算法 */
    OpenSSL_add_all_algorithms();
    /* 載入所有 SSL 錯誤訊息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
    return ctx;
}

// load certificate from pem file
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 載入使用者私鑰 */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 檢查使用者私鑰是否正確 */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

pthread_t thread_pool[THREAD_POOL_SIZE];

typedef struct sockaddr_in SA_IN;
typedef struct sockaddr SA;

struct arg_struct {
    int sockfd;
    std::string ip;
};

void handle_connection(int* client_socket, SSL* ssl, std::string ip);
int check(int exp, const char *msg);
bool _register(std::string client_name);
bool login(std::string client_name, std::string ip, std::string port, int* userId);
std::pair<int, std::string> list();
int findUserId(std::string client_name);
std::pair<bool, SSL*> transaction(std::string sender_name, std::string receiver_name, int amount);
void *thread_function(void *arg);

std::string getIP(int newfd) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(newfd, (struct sockaddr *)&addr, &addr_size);
    std::string ip = inet_ntoa(addr.sin_addr);
    return ip;
}

class User
{
	private:
		std::string name;
		std::string ip;
		std::string port;
		int balance;
		bool online;
        int sockfd;
        SSL* ssl;

	public:
		User(std::string n):name(n), balance(10000), ip("0"), port("0"), online(false), sockfd(-1){}
		~User() {}
	
		std::string getName() {return name; }
		std::string getIP() {return ip; }
		std::string getPort() {return port; }
        int getSockfd() { return sockfd; }
        SSL* getSSL() { return ssl; }
		int getBalance() {return balance; }

		bool isOnline() {return online; }
		 
		void setOnline() { online = true; }
		void setOffline() { online = false; }
		void setIP(std::string I) { ip = I; }
        void setSockfd(int sockfd ) { this->sockfd = sockfd; }
        void setSSL(SSL* ssl ) { this->ssl = ssl; }
		void setPort(std::string P) { port = P; }
        void setBalance(int balance) { this->balance = balance; }
};

std::vector<User> users;
pthread_mutex_t mutex_user = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int online_cnt = 0;
std::string publicKey;

int main(int argc, char **argv){
    // generate server key
    system("openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout server_private.pem -out server_public.crt");
    system("openssl x509 -in server_public.crt -pubkey -noout > server_public_key.pem");
    
    std::ifstream file("server_public_key.pem");
    std::string str;
    while (getline(file , str))
    {
        publicKey += str + "\n";
    } 
    file.close();

    std::cout << publicKey << std::endl;
    std::cout << "size of key: " << strlen(publicKey.c_str()) << std::endl; 
    
    SSL_CTX* ctx = InitServerCTX();

    char serverPublicFile[1000] = {0};
    strcpy(serverPublicFile, "./server_public.crt");
    char serverPrivateFile[1000] = {0};
    strcpy(serverPrivateFile, "./server_private.pem");

    LoadCertificates(ctx, serverPublicFile, serverPrivateFile);

    int server_socket, client_socket, addr_size;
    SA_IN server_addr, client_addr;

    int port = 8888;
    if (argc == 2){
        port = atoi(argv[1]);
    }

    for(int i=0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&thread_pool[i], NULL, thread_function, NULL);
    }

    check((server_socket = socket(AF_INET, SOCK_STREAM, 0)), "Failed to create socket!\n");

    // initialize  the address struct
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    check(bind(server_socket, (SA *)&server_addr, sizeof(server_addr)), "Bind failed!\n");
    check(listen(server_socket, SERVER_BACKLOG), "Listen Failed!\n");
    std::cout << "Preparing to accept!\n";  

    while (true){
        // addr_size = sizeof(SA_IN);

        struct sockaddr_in clientInfo;
        int addr_len = sizeof(clientInfo);
        client_socket = accept(server_socket, (struct sockaddr *)&clientInfo, (socklen_t*)&addr_len);
        // std::string ip = inet_ntoa(clientInfo.sin_addr);
        check(client_socket, "accept failed\n");

        /* 將連線使用者的 socket 加入到 SSL */
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        /* 建立 SSL 連線 */
        if (SSL_accept(ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;
        }
        // ShowCerts(ssl);

        if (online_cnt >= THREAD_POOL_SIZE) {
            std::cout << "Online count: "<< online_cnt << std::endl;
            char buf[MAX_BUFFER_LEN] = {0};
            memset(&buf, 0, sizeof(buf));
            strcpy(buf, "230 QUEUE_FULL");
            SSL_write(ssl, buf, strlen(buf));
            // write(client_socket, buf, sizeof(buf));
            close(client_socket);
            continue;
        }
        std::cout << "Online count: "<< online_cnt << std::endl;
        online_cnt += 1;
        char buf[MAX_BUFFER_LEN] = {0};
        memset(&buf, 0, sizeof(buf));
        strcpy(buf, "110 CONNECTION");
        SSL_write(ssl, buf, strlen(buf));
        SSL_write(ssl, publicKey.c_str(), strlen(publicKey.c_str()));
        // write(client_socket, buf, sizeof(buf));
        printf("Successfully Connected!\n");
        
        memset(&buf, 0, sizeof(buf));
        SSL_read(ssl, buf, MAX_BUFFER_LEN);
        std::cout << "connection test: " << buf << std::endl;

        int *pclient = &client_socket;

        pthread_mutex_lock(&mutex);
        enqueue(pclient, ssl);
        pthread_mutex_unlock(&mutex);
    }

    close(server_socket);
    SSL_CTX_free(ctx);
    return 0;
}

int check(int exp, const char *msg) {
    if (exp == SOCKETERROR) {
        perror(msg);
        std::cout << msg;
        exit(1);
    }
    return exp;
}

void *thread_function(void *arg) {
    while (true) {
        pthread_mutex_lock(&mutex);
        std::pair<int*, SSL*> socket = dequeue();
        pthread_mutex_unlock(&mutex);
        
        if (socket.first != NULL) {
            std::string ip = getIP(*socket.first);
            std::cout << "Client IP address: " << ip << std::endl;
            handle_connection(socket.first, socket.second, ip);
            online_cnt -= 1;
            std::cout << "Online count: "<< online_cnt << std::endl;
        }
    }
}

void handle_connection(int* p_client_socket, SSL* ssl, std::string ip) {
    char peer_msg[MAX_BUFFER_LEN] = {0};
    int client_socket = *p_client_socket;
    int userId = -1;
    std::string userName = "-1";
    
    while (true){
        // int size = SSL_read(ssl, peer_msg, sizeof(peer_msg));
        char pri[100] = "server_private.pem";
        char peer_msg_encrypted[MAX_RECV_LEN] = {0};
        int size = SSL_read(ssl, peer_msg_encrypted, MAX_RECV_LEN);
        check(size, "Receiving error!\n");
        if (size == 0) {
            std::cout << "Client has unexpected error. Terminate the connection" << std::endl;
            break;
        }

        FILE *key_file = fopen(pri, "r");
        RSA *privateKey = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
        int err = RSA_private_decrypt(RSA_size(privateKey), (const unsigned char*)peer_msg_encrypted, (unsigned char *)peer_msg, privateKey, RSA_PKCS1_PADDING);
        if (err == -1)
        {
            // Error handling
            ERR_print_errors_fp(stderr);
            char buff[MAX_BUFFER_LEN] = {0};
            strcpy(buff, "Decrypt Error!\n");
            SSL_write(ssl, buff, sizeof(buff));            
        }
        else
        {
            std::cout << "Decrypt Success!\n";
        }
        std::cout << peer_msg << std::endl;
        
        // int size = recv(client_socket, peer_msg, sizeof(peer_msg), 0);
        // std::cout << "New Message: " << std::endl;
        // std::cout << peer_msg << std::endl;

        // if (strcmp(peer_msg, "Exit") == 0){
        //     break;
        // }

        char *action = strtok(peer_msg, "#");
        // std::cout << action << std::endl;
        char buf[MAX_BUFFER_LEN] = {0};
        memset(&buf, 0, sizeof(buf));
        if (action == NULL) {
            memset(&peer_msg, 0, sizeof(peer_msg));
            std::cout << "Receive Undefined Packet." << std::endl;
            continue;
        }
        if (strcmp(action, "REGISTER") == 0){
            char *name = strtok(NULL, "#");
            std::string s;
            s += name;
            bool suc = _register(name);
            std::cout << "Register: "<< name << ", Success: " << suc << std::endl;
            if (suc == true){
                strcpy(buf, "100 Register");
            }
            else {
                strcpy(buf, "210 Fail");
            }
            // write(client_socket, buf, sizeof(buf));
            SSL_write(ssl, buf, sizeof(buf));
        } else if (strcmp(action, "List") == 0) {
            std::cout << "List" << std::endl;
            std::pair<int, std::string> info = list();
            std::string tmp = std::to_string(info.first);
            int balance = users[userId].getBalance();
            std::string tmp2 = std::to_string(balance);
            char med[MAX_BUFFER_LEN] = "\n";
            //char publicKey[MAX_BUFFER_LEN] = "public key\n";
            std::string output = tmp2 +  "\n" + publicKey + tmp + med + info.second;
            // std::cout << publicKey.c_str() << std::endl;
            // strcpy(buf, tmp2.c_str());
            // strcat(buf, med);
            // strcat(buf, "scss");
            // strcat(buf, "CurrentOnlineAccount\n");
            // strcat(buf, tmp.c_str());
            // strcat(buf, med);
            // strcat(buf, info.second.c_str());
            std:: cout << output << std::endl;
            //write(client_socket, buf, sizeof(buf));
            SSL_write(ssl, output.c_str(), BUFSIZE);
        } else if (strcmp(action, "Exit") == 0) {
            if (userId == -1) {
                strcpy(buf, "Bye\n");
                SSL_write(ssl, buf, sizeof(buf));
                // write(client_socket, buf, sizeof(buf));
            } else {                
                users[userId].setSockfd(-1);
                users[userId].setOffline();
                strcpy(buf, "Bye\n");
                // write(client_socket, buf, sizeof(buf));
                SSL_write(ssl, buf, sizeof(buf));
                std::cout << users[userId].getName() << " exited." << std::endl;
            }
            break;          
        } else {
            // to tell transaction or login
            char *num = strtok(NULL, "#");
            // std::cout << "num: "<< num << std::endl;
            char *recepient = strtok(NULL, "#");
            if (recepient != NULL){ //transaction
                std::cout << "Transaction recepient: "<< recepient << std::endl;
                std::string sender_name;
                sender_name += action;
                std::string amount;
                amount += num;
                std::string reciever_name;
                reciever_name += recepient;
                std::pair<bool, SSL*> info = transaction(sender_name, reciever_name, std::stoi(amount));
                if (info.first == true) {
                    strcpy(buf, "Transfer ok!\n");
                    // write(info.second, buf, sizeof(buf));
                    SSL_write(info.second, buf, sizeof(buf));
                } else {
                    if (info.second != nullptr){
                        strcpy(buf, "Transfer fail!\n");
                        // write(info.second, buf, sizeof(buf));
                        SSL_write(info.second, buf, sizeof(buf));                    
                    }
                }
            } else {
                // login
                std::string name;
                name += action;
                std::string portNum;
                portNum += num;
                bool loginStatus = login(name, ip, portNum, &userId);
                if (loginStatus == false){
                    strcpy(buf, "220 AUTH_FAIL\n");
                    // write(client_socket, buf, sizeof(buf));
                    SSL_write(ssl, buf, sizeof(buf));
                } else {
                    users[userId].setSockfd(client_socket);
                    users[userId].setSSL(ssl);
                    std::cout << "Login: "<< name << std::endl;
                    // std::cout << "Login user id: "<< userId << std::endl;
                    std::pair<int, std::string> info = list();
                    std::string tmp = std::to_string(info.first);
                    int balance = users[userId].getBalance();
                    std::string tmp2 = std::to_string(balance);
                    char med[MAX_BUFFER_LEN] = "\n";
                    char publicKey[MAX_BUFFER_LEN] = "public key\n";
                    strcpy(buf, tmp2.c_str());
                    strcat(buf, med);
                    strcat(buf, publicKey);
                    strcat(buf, tmp.c_str());
                    strcat(buf, med);
                    strcat(buf, info.second.c_str());
                    // write(client_socket, buf, sizeof(buf));
                    SSL_write(ssl, buf, sizeof(buf));
                    // std::cout << "buf: "<< buf << std::endl;
                }
            }
        }
        
        memset(&peer_msg, 0, sizeof(peer_msg));
        fflush(stdout);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    std::cout << "closing connection!\n";
}

// check whether the client name has been registered
bool _register(std::string client_name){
	pthread_mutex_lock(&mutex_user);
	bool success = true;
	for(int i = 0; i< users.size(); i++)
	{
		if(users[i].getName() == client_name)
		{
			success = false;
			break;			
		}
	}

    // push to user vector
    if (success == true) {
        users.push_back(User(client_name));  
    }

	pthread_mutex_unlock(&mutex_user);
  	return success; 
}

std::pair<int, std::string> list() {
    int onlineCnt = 0;
    std::string send;

	// pthread_mutex_lock(&mutex_user);
    for(int i = 0; i < users.size(); i++)
	{
		if(users[i].isOnline()){
			onlineCnt++;      
      		send +=  users[i].getName() + "#" + users[i].getIP() +  "#" + users[i].getPort() + "\n";  
		} 
	}
    // pthread_mutex_unlock(&mutex_user);
    return std::make_pair(onlineCnt, send);
}

bool login(std::string client_name, std::string ip, std::string port, int* userId) {
    *userId = findUserId(client_name);
    
    if (*userId == -1){
        return false;        
    }
    // pthread_mutex_lock(&mutex_user);
    users[*userId].setPort(port);
    users[*userId].setIP(ip);
    users[*userId].setOnline();

    // pthread_mutex_unlock(&mutex_user);
    return true;
}

int findUserId(std::string client_name) {
	int userID = -1;
	// pthread_mutex_lock(&mutex_user);
    for(int i = 0; i < users.size(); ++i) {
        if(client_name.compare(users[i].getName()) == 0) {
            return i;	 
		}
	}
    // pthread_mutex_unlock(&mutex_user);
  	return userID;
}


std::pair<bool, SSL*> transaction(std::string sender_name, std::string receiver_name, int amount){
    bool success = false;
    int senderSockfd = -1;
    SSL* senderSSL = nullptr;
    int senderId = findUserId(sender_name);
    int receiverId = findUserId(receiver_name);
    if (senderId == -1) {
        return std::make_pair(success, senderSSL);
    } else {
        senderSockfd = users[senderId].getSockfd();
        senderSSL = users[senderId].getSSL();
        // std::cout << "senderSockfd: " << senderSockfd << std::endl;
        // check balance
        if (users[senderId].getBalance() < amount) {
            return std::make_pair(success, senderSSL);
        }
        // check receiver exist
        if (receiverId == -1){
            return std::make_pair(success, senderSSL);
        }
        // transaction process
        users[senderId].setBalance(users[senderId].getBalance() - amount);
        users[receiverId].setBalance(users[receiverId].getBalance() + amount);
        success = true;
    }

    return std::make_pair(success, senderSSL);
}
