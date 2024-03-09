#include <arpa/inet.h>	//inet_addr
#include <unistd.h>	//write
#include <iostream>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <fstream>
#define MAX_BUFFER_LEN 80
#define MAX_RECV_LEN 4096
#define PORT 8888
#define SA struct sockaddr
#define STDIN 0 // standard input 的 file descriptor

void home();
void middleware(int sockfd, int connfd, int listenPort, char *username, SSL* ssl, char* privateKeyFile, char* publicKeyFile);
void registerUser(int sockfd, SSL* ssl);
int login(int sockfd, int listenPort, char *username, SSL* ssl);
void listenToPeers(int connfd, int port);
int list(int sockfd, char **userlist, SSL* ssl);
void transaction(int sockfd, char *username, SSL* ssl);
void encryptAndSend(SSL* ssl, char* msg);

// temp to store other's public key
char serverPubKey[1024] = {0};
char clientPubKey[1024] = {0};
std::string myPubKey;

// initilize SSL
SSL_CTX* InitClientCTX()
{
    SSL_CTX *ctx;
    /* SSL 庫初始化 */
    SSL_library_init();
    /* 載入所有 SSL 演算法 */
    OpenSSL_add_all_algorithms();
    /* 載入所有 SSL 錯誤訊息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_client_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
    return ctx;
}

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

// print 出對方的憑證
void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("Digital certificate information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificate information!\n");
}

int main(int argc , char *argv[])
{
	srand( time(NULL) );
    int y = rand();

    char cmd[1000] = "openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout ";
    char clientPublicFile[1000] = {0};
    char clientPrivateFile[1000] = {0};
    char secondRandon[1000] = {0};
    sprintf(secondRandon, "%d", y);
    char pub[20] = "_public.pem";
    char pri[20] = "_private.pem";

    strncat(clientPublicFile, secondRandon, 50);
    strncat(clientPrivateFile, secondRandon, 50);
    strcat(clientPublicFile, pub);
    strcat(clientPrivateFile, pri);  
    
    strcat(cmd, clientPrivateFile);
    char out[10] = " -out ";
    strcat(cmd, out);
    strcat(cmd, clientPublicFile);
    printf("There is the cmd to generate a key pair.\n%s\n\n", cmd);
    // generate server key
    system(cmd);

    // to get client public key and store
    char pub_temp[50] = "temp_public.pem";
    char cmd2[1000] = "openssl x509 -in ";
    strcat(cmd2, clientPublicFile);
    char temp[50] = " -pubkey -noout > ";
    strcat(cmd2, temp);
    strcat(cmd2, pub_temp);
    system(cmd2);
    
    std::ifstream file("temp_public.pem");
    std::string str;
    while (getline(file , str))
    {
        myPubKey += str + "\n";
    } 
    file.close();

    std::cout << "This is my public key: " << std::endl << myPubKey << "\n\n";

    SSL_CTX* ctx = InitClientCTX();

    int sockfd, connfd;
	struct sockaddr_in servaddr;

	char server_addr[20] = "127.0.0.1";
    int port = 8888;
    if (argc != 3){
        printf("Please enter the server address:");
        scanf("%s", server_addr);
        printf("Please enter the server port: ");
        scanf("%d", &port);
    }
    else {
        strcpy(server_addr, argv[1]);
        port = atoi(argv[2]);
    }

	// socket create and varification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("Server socket creation failed...\n");
		exit(0);
	}
	else
		printf("Server socket successfully created..\n");
    
    connfd = socket(AF_INET, SOCK_STREAM, 0);
	if (connfd == -1) {
		printf("Peer socket creation failed...\n");
		exit(0);
	}
	else
		printf("Peer socket successfully created..\n");
	
    bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
    servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(server_addr);
	servaddr.sin_port = htons(port);

	// connect the client socket to server socket
	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
		printf("connection with the server failed...\n");
		exit(0);
	}
    printf("connected to the server..\n");

    // create ssl
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    // 建立 SSL 連線
    if (SSL_connect(ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        // ShowCerts(ssl);
    }        
    
    char recv_msg[MAX_RECV_LEN] = {0};
    SSL_read(ssl, recv_msg, MAX_RECV_LEN);
    // read(sockfd, recv_msg, sizeof(recv_msg));
    std::cout << "recv_msg: " << recv_msg << std::endl;
    

    if (strcmp(recv_msg, "230 QUEUE_FULL") == 0)
    {
        printf("\nServer is busy right now!\nPlease connect again later!\n");
        close(sockfd);
        close(connfd);
        exit(0);
    }

    // GET server public key
    SSL_read(ssl, serverPubKey, MAX_RECV_LEN);

    memset(&recv_msg, 0, sizeof(recv_msg));
    strcpy(recv_msg, "Hello!");
    SSL_write(ssl, recv_msg, strlen(recv_msg));

    bool hasLogin = 0;
    // login or register
    char username[MAX_BUFFER_LEN] = {0};
    int listenPort = 6666;

    memset(&recv_msg, 0, sizeof(recv_msg));
    while(!hasLogin) {
        printf("Please enter the number of service:\n ");
        printf("0: Register\n ");
        printf("1: Login\n ");
        printf("2: Exit\n");
        int action = -1;
        scanf("%d", &action);
        fflush(stdin);
        char buff[MAX_BUFFER_LEN] = {0};
        switch (action)
        {
            case 0:
                registerUser(sockfd, ssl);
                break;
            case 1:
                printf("Please enter a port number: ");
                scanf("%d", &listenPort);
                if (login(sockfd, listenPort, username, ssl) != -1) {
                    hasLogin = 1;
                };
                break;
            case 2:
                strcpy(buff, "Exit");
                encryptAndSend(ssl, buff);
                // SSL_write(ssl, buff, sizeof(buff));
                // write(sockfd, buff, sizeof(buff));
                SSL_read(ssl, recv_msg, MAX_RECV_LEN);
                // read(sockfd, recv_msg, sizeof(recv_msg));
                if (strcmp(recv_msg, "Bye\n") == 0)
                {
                    printf("See you next time!\n");
                    remove(clientPrivateFile);
                    remove(clientPublicFile);
                    exit(0);
                }
                printf("Client Exit...\n");
                remove(clientPrivateFile);
                remove(clientPublicFile);
                exit(0);
                break;
            default:
                printf("Invalid Operation!\n");
                break;
        }
        fflush(stdin);        
    }
    
    // create listening port
    struct sockaddr_in cli;
    int addrlen = sizeof(cli);
    bzero(&cli, sizeof(cli));

    cli.sin_family = AF_INET;
    cli.sin_addr.s_addr = INADDR_ANY;
    cli.sin_port = htons(listenPort);
    // bind
    if (bind(connfd, (struct sockaddr *)&cli, sizeof(cli)) == -1) {
        printf("bind socket error\n");
        close(sockfd);
        exit(0);
    }
    if (listen(connfd, 1) < 0 ) // only allow one peer connected
    {
        close(sockfd);
        perror("listen");
        exit(0);
    }

	// function for chat
    printf("Hello, %s!\n", username);
    middleware(sockfd, connfd, listenPort, username, ssl, clientPrivateFile, clientPublicFile);

	// close the socket
    SSL_shutdown(ssl);
    SSL_free(ssl);
	close(sockfd);
    close(connfd);
}

void home()
{
    printf("Our services: \n");
    printf("0: List account balance and online users\n");
    printf("1: Transfer\n");
    printf("2: Exit\n");
}

void middleware(int sockfd, int connfd, int listenPort, char *username, SSL* ssl, char* privateKeyFile, char* publicKeyFile)
{
	
    home();
    char *userlist;
    // create fd
    fd_set set;
    FD_ZERO(&set);
    SSL_CTX* ctx2 = InitServerCTX();
    LoadCertificates(ctx2, publicKeyFile, privateKeyFile);
    while (1)
    {
        FD_SET(connfd, &set);
        FD_SET(STDIN, &set);
        //printf("connfd: %d, stdin: %d\n", connfd, STDIN);
        int maxfdp = (connfd > STDIN) ? connfd + 1 : STDIN + 1;
        int status = select(maxfdp, &set, NULL, NULL, NULL);
        //printf("%d, %d\n", maxfdp, status);
        
        int action = -1;
        int onlineCnt = 0;

        char buff[MAX_BUFFER_LEN] = {0};
        char recv_msg[MAX_RECV_LEN] = {0};
        if (status < 0){
            bzero(recv_msg, sizeof(recv_msg));
            strcpy(buff, "Exit");
            encryptAndSend(ssl, buff);
            // SSL_write(ssl, buff, strlen(buff));
            SSL_read(ssl, recv_msg, MAX_RECV_LEN);
            // write(sockfd, buff, sizeof(buff));
            // read(sockfd, recv_msg, sizeof(recv_msg));
            if (strcmp(recv_msg, "Bye\n") == 0)
            {
                printf("See you next time!");
                exit(0);
            }
            printf("Client Exit...\n");
            exit(0);
        } else if (status = 0){
            printf("Something Wrong...\n");
        } else {            
            // printf("connfd: %d, stdin: %d\n", FD_ISSET(connfd, &set), FD_ISSET(STDIN, &set));
            
            // receive msg from peer
            if (FD_ISSET(connfd, &set)){
                struct sockaddr_in peerInfo;
                int addr_len = sizeof(peerInfo);
                int forClientSockfd = accept(connfd, (struct sockaddr *)&peerInfo, (socklen_t*)&addr_len);
                SSL* ssl2 = SSL_new(ctx2);
                SSL_set_fd(ssl2, forClientSockfd);
                /* 建立 SSL 連線 */
                if (SSL_accept(ssl2) == -1)
                {
                    ERR_print_errors_fp(stderr);
                    close(forClientSockfd);
                    continue;
                }
                SSL_write(ssl2, myPubKey.c_str(), strlen(myPubKey.c_str()));
                char peer_msg[MAX_BUFFER_LEN] = {0};
                char peer_msg_encrypted[MAX_RECV_LEN] = {0};
                char peer_msg_plain[MAX_RECV_LEN] = {0};
                SSL_read(ssl2, peer_msg_encrypted, MAX_RECV_LEN);
                FILE *key_file = fopen(privateKeyFile, "r");
                RSA *privateKey = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
                char *buf = (char *)malloc(RSA_size(privateKey));
                int err = RSA_private_decrypt(RSA_size(privateKey), (const unsigned char*)peer_msg_encrypted, (unsigned char *)peer_msg_plain, privateKey, RSA_PKCS1_PADDING);
                if (err == -1)
                {
                    ERR_print_errors_fp(stderr);
                }
                else
                {
                    std::cout << "Decrypt Success!!\n";
                }
                std::cout << peer_msg_plain << std::endl;
                // SSL_read(ssl2, peer_msg, MAX_RECV_LEN);
                // int size = recv(forClientSockfd, peer_msg, sizeof(peer_msg), 0);
                encryptAndSend(ssl, peer_msg_plain);
                // if( SSL_write(ssl, peer_msg, strlen(peer_msg)) == -1){ 
                    // send(sockfd, peer_msg, sizeof(peer_msg), 0)
                    // printf("Someone want to transfer to you, but he failed.\n\n");
                    // bzero(recv_msg, sizeof(recv_msg));
                    // strcpy(recv_msg, "Transfer fail.");
                    // send(forClientSockfd, recv_msg, sizeof(recv_msg), 0);
                //     SSL_shutdown(ssl2);
                //     SSL_free(ssl2);
                //     continue;
                // }
                // bzero(recv_msg, sizeof(recv_msg));
                // recv(sockfd, recv_msg, sizeof(recv_msg), 0);
                // send(forClientSockfd, recv_msg, sizeof(recv_msg), 0);
                SSL_shutdown(ssl2);
                SSL_free(ssl2);
                printf("There is a new transfer coming in.\n%s\n\n", peer_msg);
            }

            if (FD_ISSET(STDIN, &set)){
                bzero(buff, sizeof(buff));
                bzero(recv_msg, sizeof(recv_msg));
                scanf("%d", &action);
                fflush(stdin);
                switch (action)
                {
                    case 0:
                        list(sockfd, &userlist, ssl);
                        break;
                    case 1:
                        transaction(sockfd, username, ssl);
                        break;
                    case 2:
                        strcpy(buff, "Exit");
                        encryptAndSend(ssl, buff);
                        // SSL_write(ssl, buff, strlen(buff));
                        SSL_read(ssl, recv_msg, MAX_RECV_LEN);
                        // write(sockfd, buff, sizeof(buff));
                        // read(sockfd, recv_msg, sizeof(recv_msg));
                        if (strcmp(recv_msg, "Bye\n") == 0)
                        {
                            printf("See you next time!\n");
                            remove(privateKeyFile);
                            remove(publicKeyFile);
                            exit(0);
                        }
                        remove(privateKeyFile);
                        remove(publicKeyFile);
                        printf("Client Exit...\n");
                        exit(0);
                        break;
                    default:
                        printf("Invalid Operation!\n\n");
                        home();
                        break;
                }
            }
        }
    }
}

void registerUser(int sockfd, SSL* ssl)
{
    char buf[MAX_BUFFER_LEN] = {0};
    char name[MAX_BUFFER_LEN] = {0};
    char recv_msg[MAX_RECV_LEN] = {0};
    char header[MAX_BUFFER_LEN] = "REGISTER#";
    printf("Please enter username: ");
    scanf("%s", name);
    strcat(buf, header);
    strcat(buf, name);
    // write(sockfd, buf, sizeof(buf));
    // read(sockfd, recv_msg, sizeof(recv_msg));
    encryptAndSend(ssl, buf);
    // SSL_write(ssl, buf, strlen(buf));
    SSL_read(ssl, recv_msg, MAX_RECV_LEN);
    if (strncmp(recv_msg, "100", 3) == 0)
    {
        printf("Register successfully!\n\n");
    }
    else if (strncmp(recv_msg, "210", 3) == 0)
    {
        printf("Register failed!\n\n");
    }
    else {
        printf("Unexpected Error!\n\n");
    }
}

int login(int sockfd, int listenPort, char *username, SSL* ssl){
    char buf[MAX_BUFFER_LEN] = {0};
    char name[MAX_BUFFER_LEN] = {0};
    char recv_msg[MAX_RECV_LEN] = {0};
    char med[MAX_BUFFER_LEN] = "#";
    printf("Please enter your username: ");
    scanf("%s", name);
    strcpy(buf, name);
    strcat(buf, med);
    char str[10];
    sprintf(str, "%d", listenPort);
    // printf("char: %s \n", str);
    strcat(buf, str);
    // printf("send msg: %s \n", buf);
    encryptAndSend(ssl, buf);
    // SSL_write(ssl, buf, strlen(buf));
    SSL_read(ssl, recv_msg, MAX_RECV_LEN);
    // write(sockfd, buf, sizeof(buf));
    // read(sockfd, recv_msg, sizeof(recv_msg));
    // printf("receive msg: %s \n", recv_msg);
    if (strcmp(recv_msg, "220 AUTH_FAIL\n") == 0){
        printf("User doesn't exist.\n\n");
        return -1;
    } else {
        strcpy(username, name);
        char *token = strtok(recv_msg, "\n");
        printf("Your account balance: %s\n", token);
        token = strtok(NULL, "\n");
        token = strtok(NULL, "\n");
        printf("Current online account: %s\n", token);
        int onlineCnt = atoi(token);
        int cnt = 0;
        bool flag = 0;
        bool userFlag = 0;
        token = strtok(NULL, "\n");
        // TO BE FIXED, SERVER HAS UNEXPECTED ERROR
        while (!flag){
            while( token != NULL ) 
            {
                if(strstr(token, name) != NULL){
                    userFlag = 1;
                } else {
                    cnt++;
                }
                printf("%s \n", token );
                token = strtok(NULL, "\n");
            }
            if(cnt >= onlineCnt - 1 && userFlag == 1){
                flag = 1;
                break;
            }
            SSL_read(ssl, recv_msg, MAX_RECV_LEN);
            // recv(sockfd, recv_msg, sizeof(recv_msg), 0);
            token = strtok(recv_msg, "\n");
        }
        printf("\n");
    }
    return 0;
}

int list(int sockfd, char **userlist, SSL* ssl){
    char buf[MAX_BUFFER_LEN] = "List";
    char recv_msg[MAX_RECV_LEN] = {0};
    encryptAndSend(ssl, buf);
    // SSL_write(ssl, buf, strlen(buf));
    SSL_read(ssl, recv_msg, MAX_RECV_LEN);
    // write(sockfd, buf, sizeof(buf));
    // read(sockfd, recv_msg, sizeof(recv_msg));
    // printf("Your: %s\n", recv_msg);
    if (strcmp(recv_msg, "Please login first\n") == 0){
        printf("Please login first\n\n");
        return 0;
    } 
    else {
        char *token = strtok(recv_msg, "\n");
        printf("Your account balance: %s\n", token);
        token = strtok(NULL, "\n");
        printf("Server public key:\n %s\n", token);
        while (true) {
            token = strtok(NULL, "\n");
            printf("%s\n", token);
            // std::cout << strcmp("-----END PUBLIC KEY-----\n", token);
            if (strcmp("-----END PUBLIC KEY-----", token) == 0){
                break;
            }
        }
        token = strtok(NULL, "\n");
        printf("Current online account: %s\n", token);
        int onlineCnt = atoi(token);
        int cnt = 0;
        *userlist = (char *)malloc((size_t)2 * onlineCnt * MAX_BUFFER_LEN * sizeof(char));
        bool flag = 0;
        token = strtok(NULL, "\n");
        while( token != NULL ) 
        {
            strcpy(*userlist + cnt * MAX_BUFFER_LEN, token);
            cnt++;
            printf("%s \n", token );
            token = strtok(NULL, "\n");
        }
        printf("\n");
        return onlineCnt;
    }
}

void transaction(int sockfd, char *username, SSL* ssl){
    char *userlist;
    int onlineCnt = list(sockfd, &userlist, ssl);
    char name[MAX_BUFFER_LEN] = {0};
    char recipient[MAX_BUFFER_LEN] = {0};
    char amount[MAX_BUFFER_LEN] = {0};
    char med[MAX_BUFFER_LEN] = "#";
    // printf("Please enter your username: ");
    // scanf("%s", name);
    strcpy(name, username);
    printf("Please enter the recipient: ");
    scanf("%s", recipient);
    printf("Please enter transfer amount: ");
    scanf("%s", amount);
    fflush(stdin);
    printf("online count: %d\n", onlineCnt);
    bool flag = 0;

    if (strcmp(name, recipient) == 0) {
        printf("You cannot transfer to yourself!\n");
        return;
    }

    for(int i = 0; i < onlineCnt; i++){
        char buf[MAX_BUFFER_LEN] = {0};
        char recv_msg[MAX_RECV_LEN] = {0};
        char *user = strtok(userlist + i * MAX_BUFFER_LEN, "#");
        char *user_addr = strtok(NULL, "#");
        char *user_port = strtok(NULL, "\n");
        if (strcmp(recipient, user) == 0){
            flag = 1;
            strcpy(buf, name);
            strcat(buf, med);
            strcat(buf, amount);
            strcat(buf, med);
            strcat(buf, user);
            printf("%s\n", buf);
            
            int peerfd = 0;
            peerfd = socket(AF_INET, SOCK_STREAM, 0);

            if (peerfd == -1)
            {
                printf("Fail to create a socket.\n");
                break;
            }

            struct sockaddr_in peer;
            bzero(&peer, sizeof(peer));
            peer.sin_family = AF_INET;
            peer.sin_addr.s_addr = INADDR_ANY; // inet_addr(user_addr);
            peer.sin_port = htons(atoi(user_port));
            
            int err = connect(peerfd, (struct sockaddr *)&peer, sizeof(peer));
            if (err == -1)
            {
                printf("Connection error\n");
                break;
            }

            SSL_CTX* ctx = InitClientCTX();
            SSL* ssl3 = SSL_new(ctx);
            SSL_set_fd(ssl3, peerfd);

            // 建立 SSL 連線
            if (SSL_connect(ssl3) == -1)
            {
                ERR_print_errors_fp(stderr);
            }
            else
            {
                printf("Connected with %s encryption\n", SSL_get_cipher(ssl3));
                // ShowCerts(ssl3);
            } 

            printf("Transfering to: %s:%s...\n", user_addr, user_port);
            // X509 *peer_cert = SSL_get_peer_certificate(ssl3);
            // if (peer_cert == NULL)
            // {
            //     printf("No Certificate Received\n");
            // }
            // EVP_PKEY *peer_pubkey = X509_get_pubkey(peer_cert);            
            // RSA *peer_rsa_pubkey = EVP_PKEY_get1_RSA(peer_pubkey);
            // if (peer_rsa_pubkey == NULL)
            // {
            //     std::cout << "peer_rsa_pubkey wrong!\n";
            // }
            bzero(&clientPubKey, sizeof(clientPubKey));
            SSL_read(ssl3, clientPubKey, MAX_RECV_LEN);
            BIO* bio = BIO_new(BIO_s_mem());
            int len = BIO_write(bio, clientPubKey, strlen(clientPubKey));
            EVP_PKEY* evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
            RSA* peer_rsa_pubkey = EVP_PKEY_get1_RSA(evp_key);
            if (peer_rsa_pubkey == NULL)
            {
                std::cout << "Peer public key is wrong!\n";
                return;
            }            

            char *cipher_text = (char *)malloc(RSA_size(peer_rsa_pubkey));
            err = RSA_public_encrypt((strlen(buf) + 1)*sizeof(char), (const unsigned char*) buf, (unsigned char*) cipher_text, peer_rsa_pubkey, RSA_PKCS1_PADDING);
            if (err == -1)
            {
                ERR_print_errors_fp(stderr);
            }
            else
            {
                std::cout << "Encrypt Success!!\n";
            }
            int status = SSL_write(ssl3, cipher_text, RSA_size(peer_rsa_pubkey));
            // std::cout << "status0: " << status << std::endl;
            // int status = SSL_write(ssl3, buf, strlen(buf)); // send(peerfd, buf, sizeof(buf), 0);
            if (status == -1){
                printf("Transfer error\n");
                SSL_shutdown(ssl3);
                SSL_free(ssl3);
                break;                
            }
            if( SSL_read(ssl, recv_msg, MAX_RECV_LEN) == -1){
                // recv(sockfd, recv_msg, sizeof(recv_msg), 0)
                printf("Transfer error\n");
            }
            printf("%s\n", recv_msg);
            SSL_shutdown(ssl3);
            SSL_free(ssl3);
            close(peerfd);
            SSL_CTX_free(ctx);
            break;
        }
    }
    if(flag == 0){
        printf("Recipient is not online or not exist.\n\n");
    }
}

void encryptAndSend(SSL* ssl, char* msg){
    std::cout << "Encrypting...\n";
    // X509 *peer_cert = SSL_get_peer_certificate(ssl);
    // if (peer_cert == NULL)
    // {
    //     printf("No Certificate Received\n");
    //     return;
    // }
    // EVP_PKEY *peer_pubkey = X509_get_pubkey(peer_cert);            
    // RSA *peer_rsa_pubkey = EVP_PKEY_get1_RSA(peer_pubkey);
    // if (peer_rsa_pubkey == NULL)
    // {
    //     std::cout << "Peer public key is wrong!\n";
    //     return;
    // }

    // Translate public key from char to rsa type
    BIO* bio = BIO_new(BIO_s_mem());
    int len = BIO_write(bio, serverPubKey, strlen(serverPubKey));
    EVP_PKEY* evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    RSA* rsa_server = EVP_PKEY_get1_RSA(evp_key);
    if (rsa_server == NULL)
    {
        std::cout << "Peer public key is wrong!\n";
        return;
    }

    char *cipher_text = (char *)malloc(RSA_size(rsa_server));
    int err = RSA_public_encrypt((strlen(msg) + 1)*sizeof(char), (const unsigned char*) msg, (unsigned char*) cipher_text, rsa_server, RSA_PKCS1_PADDING);
    if (err == -1)
    {
        ERR_print_errors_fp(stderr);
        std::cout << "Encrypt Fail!\n";
    }
    int status = SSL_write(ssl, cipher_text, RSA_size(rsa_server));
    if ( status <= 0){
        printf("Send Fail!\n");
        return;
    }
    std::cout << "Encryption Done!\n";
}