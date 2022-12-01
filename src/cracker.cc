/*
 * Copyright (C) 2018-2022 David C. Harrison. All right reserved.
 *
 * You may not use, distribute, publish, or modify this code without 
 * the express written permission of the copyright holder.
 */
//#define _GNU_SOURCE
#include <crypt.h>
#include <time.h>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <algorithm>
#include <iomanip>
#include <string.h>
#include "cracker.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

/**
 * @brief main function of yoiur cracker
 * 
 * No command line arguments are passed
 * 
 * @return int not checked by test harness
 */
void pcrack(const char *alphabet, const char *hash, char *passwd, unsigned int split, unsigned int threads){
    char a[5]; //4 char password
    char salt[3];
    clock_t start, end;
    start = clock();
    memcpy( salt, &hash[0], 2); // first two character as salt
    struct crypt_data data;
    data.initialized = 0;
    a[4] = '\0';
    salt[2] = '\0';

    for(unsigned int i = threads; i < MAX_HASHES; i = i + split){
        a[0] = alphabet[i];
        for(unsigned int j = 0; j <  ALPHABET_LEN; j++){
            a[1] = alphabet[j];
            for(unsigned int k = 0; k <  ALPHABET_LEN; k++){
                a[2] = alphabet[k];
                for(unsigned int p = 0; p < ALPHABET_LEN; p++){
                    a[3] = alphabet[p];
                    if(strcmp(crypt_r(a, salt, &data), hash) == 0){
                        memcpy( passwd, &a[0], 5);
                        end = clock();
                        std::cout << "\nthread: " << threads << "\ncharacter: " << a << "\ncrypt(a,salt):" << crypt_r(a, salt, &data)
                        << "\nsalt: " << salt << "\nhash: " << hash << "\npasswd:" << passwd << "\nTime: " << (double)(end -start) <<std::endl;
                        return;
                    }
                    if(strcmp(passwd, "!!!!") != 0){
                        return;
                    }
                }
            }
        }
    }
}

typedef struct subcontainer {
    char passwds[MAX_HASHES][HASH_LENGTH+1]; // NUM_PASSWD plain text passwords or password hashes
    char hostname[MAX_HOSTNAME_LEN];         // Host to return decrypted passwords to over TCP
}
Sub;

int main() {
//Receive Message from Test/Grade Server
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0); //receiving UDP socket
    if(sockfd < 0 ) exit(-1);

    struct sockaddr_in server_addr; // server address
    bzero((char*) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_multicast_port()); //recieving port

    if(bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0) exit(-1);

    struct ip_mreq multicastRequest;
    multicastRequest.imr_multiaddr.s_addr = get_multicast_address(); //receiving multicast address
    multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY); //from any port
    if(setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*) &multicastRequest, //response to multicast request
    sizeof(multicastRequest)) < 0) exit(-1);

    Message buffer; //recipent buffer
    Message newBuffer; //sender buffer

    int n = recvfrom(sockfd, (void*)&buffer, sizeof(buffer), 0, NULL, 0); //receive data
    if(n < 0) exit(-1);

    close(sockfd);

    strcpy(newBuffer.alphabet,buffer.alphabet);
    strcpy(newBuffer.hostname,buffer.hostname);
    strcpy(newBuffer.cruzid,buffer.cruzid);
    newBuffer.num_passwds = buffer.num_passwds;
    newBuffer.port = buffer.port;


    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << buffer.passwds[i] <<std::endl;
    }
 
    char hostname[7];
    gethostname(hostname, 7);
    if(strcmp(hostname, "noggin") == 0){
//Crack passwords
        unsigned int ssize = 24;
        for(unsigned int k = 0; k < ntohl(buffer.num_passwds); k = k + 4){
            std::vector<std::thread> thrs;
            std::cout << std::endl << buffer.passwds[k] <<std::endl;
            //
            strcpy(newBuffer.passwds[k], "!!!!"); 
            //
            for(unsigned int i = 0; i < ssize ; i++){
                thrs.push_back(std::thread([&buffer, &newBuffer, ssize, i, k]{
                    pcrack(buffer.alphabet, buffer.passwds[k], newBuffer.passwds[k], ssize, i);
                }));
            }

            for(auto& t: thrs){
                t.join(); // join threads vector
            }
        }
//Noggin: master server 
        fd_set readfds;
        struct timeval tv;
        //char buffer[256];
        int maxfd = 0;
        std::vector<int> sockets;
        int port = 5001;
        for(int i = 1; i < 4; i++){
            int sockfd = socket(AF_INET, SOCK_STREAM, 0);

            struct sockaddr_in master_addr;
            bzero((char*) &master_addr, sizeof(master_addr));
            master_addr.sin_family = AF_INET;
            master_addr.sin_port = htons(port);

            bind(sockfd, (struct sockaddr*) &master_addr, sizeof(master_addr));

            listen(sockfd, 5);
            printf("Listening on port: %d\n", port);

            FD_SET(sockfd, &readfds);
            if(sockfd > maxfd) maxfd = sockfd;
            sockets.push_back(sockfd);
            port++;
        }
//loop until 3 clients send messages
        int counter = 0;
        while(counter < 3){
            int status = -1;
            for(int sock: sockets)
                FD_SET(sock, &readfds);
            
            tv.tv_sec = 2;
            int rc = select(maxfd + 1, &readfds, 0,0, &tv);
            if(rc == 0){
                printf("Timeout\n");
                continue;
            }
            int sockfd = -1;
            for(int sock: sockets){
                if(FD_ISSET(sock, &readfds)){
                    sockfd = sock;
                    break;
                }
            }

            if(sockfd == -1) continue;

            Sub Rbuffer;
            struct sockaddr_in client_addr;
            socklen_t len = sizeof(client_addr);

            int newsockfd = accept(sockfd, (struct sockaddr*) &client_addr, &len);

            //bzero(buffer, 256);
            unsigned int st;
            status = recv(newsockfd, (void*) &Rbuffer, sizeof(Rbuffer), 0);

            if(status >= 0) {
                if(strcmp(Rbuffer.hostname, "nogbad") == 0) st = 1;
                else if(strcmp(Rbuffer.hostname, "thor") == 0) st = 2;
                else st = 3;

                for(unsigned int i = st; i < ntohl(buffer.num_passwds); i = i + 4){
                    strcpy(newBuffer.passwds[i], Rbuffer.passwds[i]);
                }
                counter++;
            }
            close(newsockfd);
        }
        for(unsigned int i = 0; i < ntohl(newBuffer.num_passwds); i++){
            //strcpy(newBuffer.passwds[i], Rbuffer.passwds[i]);
            std::cout << newBuffer.passwds[i] << std::endl;
        }
//send message to test server
        int sendsock = socket(AF_INET, SOCK_STREAM, 0);
        if(sendsock < 0) exit(-1);

        struct hostent *server = gethostbyname(buffer.hostname);
        if(server == NULL) exit(-1);

        struct sockaddr_in serv_addr;
        bzero((char*) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char*)server->h_addr, (char*)&serv_addr.sin_addr.s_addr, server->h_length);
        serv_addr.sin_port = buffer.port;

        if(connect(sendsock, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) exit(-1);

        //int s = send(sendsock, (void*) &newBuffer, sizeof(newBuffer), 0);
        int s = write(sendsock, &newBuffer, sizeof(newBuffer));
        if(s < 0) exit(-1);

        close(sendsock);
    }
//Nogbad, thor, olaf: clients
    else{
        unsigned int st;
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0) exit(-1);

        struct hostent *server = gethostbyname("noggin");
        if(server == NULL) exit(-1);

        struct sockaddr_in serv_addr;
        bzero((char*) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char*)server->h_addr, (char*)&serv_addr.sin_addr.s_addr, server->h_length);
        if(strcmp(hostname, "nogbad") == 0) {serv_addr.sin_port = htons(5001); st = 1;}
        else if(strcmp(hostname, "thor") == 0) {serv_addr.sin_port = htons(5002); st = 2;}
        else {serv_addr.sin_port = htons(5003); st = 3;}

//Crack passwords
        Sub sBuffer;
        unsigned int ssize = 24;
        for(unsigned int k = st; k < ntohl(buffer.num_passwds); k = k + 4){
            std::vector<std::thread> thrs;
            std::cout << std::endl << buffer.passwds[k] <<std::endl;
            //
            strcpy(sBuffer.passwds[k], "!!!!"); 
            //
            for(unsigned int i = 0; i < ssize ; i++){
                thrs.push_back(std::thread([&buffer, &sBuffer, ssize, i, k]{
                    pcrack(buffer.alphabet, buffer.passwds[k], sBuffer.passwds[k], ssize, i);
                }));
            }

            for(auto& t: thrs){
                t.join(); // join threads vector
            }
        }
//Send to master server
        strcpy(sBuffer.hostname, hostname);
        while(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0){} 
        int s = write(sockfd, &sBuffer, sizeof(sBuffer));
        if(s < 0) exit(-1);

        close(sockfd);
    }

// Send new Message to the Server 

}
