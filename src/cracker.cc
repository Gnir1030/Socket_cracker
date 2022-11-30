/*
 * Copyright (C) 2018-2022 David C. Harrison. All right reserved.
 *
 * You may not use, distribute, publish, or modify this code without 
 * the express written permission of the copyright holder.
 */
//#define _GNU_SOURCE
#include <crypt.h>
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
    memcpy( salt, &hash[0], 2 ); // first two character as salt
    struct crypt_data data;
    data.initialized = 0;
    a[4] = '\0';

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
                        std::cout << "\nthread: " << threads << "\ncharacter: " << a << "\ncrypt(a,salt):" << crypt_r(a, salt, &data)
                        << "\nsalt: " << salt << "\nhash: " << hash << "\npasswd:" << passwd <<std::endl;
                        return;
                    }
                }
            }
        }
    }
}


int main() {
/*
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
//Receive Message from Test/Grade Server

    std::cout << buffer.alphabet << std::endl;
    strcpy(newBuffer.alphabet,buffer.alphabet);
    std::cout << buffer.hostname << std::endl;
    strcpy(newBuffer.hostname,buffer.hostname);
    std::cout << buffer.cruzid << std::endl;
    strcpy(newBuffer.cruzid,buffer.cruzid);
    std::cout << ntohl(buffer.num_passwds) << std::endl;
    newBuffer.num_passwds = buffer.num_passwds;
    std::cout << ntohl(buffer.port) << std::endl;
    newBuffer.port = buffer.port;


    unsigned int ssize = 24;
    for(unsigned int k = 0; k < ntohl(buffer.num_passwds); k++){
        std::vector<std::thread> thrs;
        std::cout << buffer.passwds[k] <<std::endl;

        for(unsigned int i = 0; i < ssize ; i++){
            thrs.push_back(std::thread([&buffer, &newBuffer, ssize, i, k]{
                pcrack(buffer.alphabet, buffer.passwds[k], newBuffer.passwds[k], ssize, i);
            }));
        }

        for(auto& t: thrs){
            t.join(); // join threads vector
        }
    }


    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << newBuffer.passwds[i] <<std::endl;
    }
*/
// Crack passwords  
    char hostname[10];
    std::cout << gethostname(hostname, 10) << std::endl;

/*
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

    int s = send(sendsock, (void*) &newBuffer, sizeof(newBuffer), 0);
    if(s < 0) exit(-1);

    close(sendsock);
*/
// Send new Message to the Server 

}
