/*
 * Copyright (C) 2018-2022 David C. Harrison. All right reserved.
 *
 * You may not use, distribute, publish, or modify this code without 
 * the express written permission of the copyright holder.
 */

#include <iostream>
#include <string.h>
#include <thread>
#include <vector>
#include <mutex>
#include <algorithm>
#include <iomanip>
#include <string>
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
void pcrack(const char *alphabet, const char *hash, char *passwd, unsigned int split, unsigned int threads, std::mutex& iMutex){
    char a[5];
    char salt[2];
    memcpy( salt, &hash[0], 2 );

    for(unsigned int i = threads; i < MAX_HASHES; i = i + split){
        a[0] = alphabet[i];
        for(unsigned int j = 0; j <  ALPHABET_LEN; j++){
            a[1] = alphabet[j];
            for(unsigned int k = 0; k <  ALPHABET_LEN; k++){
                a[2] = alphabet[k];
                for(unsigned int p = 0; p < ALPHABET_LEN; p++){
                    a[3] = alphabet[p];
                    if(strcmp(crypt(a, salt), hash) == 0){
                        std::lock_guard<std::mutex> lock(iMutex);
                        memcpy( passwd, &a[0], 5);
                        //std::cout << strcmp(crypt(a, salt), hash) << "!" <<crypt(a, salt) << std::endl;
                        return;
                    }
                }
            }
        }
        std::cout << a << std::endl;
        std::cout << alphabet << std::endl;
        std::cout << hash << std::endl;
        std::cout << passwd << std::endl;
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
*/
    std::vector<std::thread> thrs; // multithread vector

    char alphabet[ALPHABET_LEN + 1] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char passwds[HASH_LENGTH + 1] = "a5LrgVquuk6a2";
    char pass[5] = "!!!!";
//zUS0
    std::mutex iMutex;
    unsigned int ssize = 24;
    for(unsigned int i = 0; i < ssize; i++){
        thrs.push_back(std::thread([&iMutex, alphabet, passwds, pass, ssize, i]{
            pcrack(alphabet, passwds, pass, ssize, i, iMutex);
            //std::cout << pass <<std::endl;
        }));
    }

    for(auto& t: thrs){
        t.join(); // join threads vector
    }

    std::cout << pass <<std::endl;

/*
    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << buffer.passwds[i] <<std::endl;
        thrs.push_back(std::thread([&newBuffer,&buffer, i]{
            crack(buffer.alphabet, buffer.passwds[i], newBuffer.passwds[i]);
            std::cout << newBuffer.passwds[i] <<std::endl;
        }));
    }

    for(auto& t: thrs){
        t.join(); // join threads vector
    }
    //std::copy(&passArr[0][0], &passArr[0][0] + MAX_HASHES * (HASH_LENGTH + 1), &newBuffer.passwds[0][0]);

    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << newBuffer.passwds[i] <<std::endl;
    }
*/

    char salt[2];
    memcpy( salt, &passwds[0], 2 );
    char* hash = crypt(pass, salt);
    std::cout << "HASH: " << hash << std::endl;

/*
    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << buffer.passwds[i] <<std::endl;
        crack(buffer.alphabet, buffer.passwds[i], password2);
        std::cout << password2 << std::endl;
  
    }
*/

/*
    close(sockfd);

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
}
