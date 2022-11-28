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
#include "cracker.h"
#include <unistd.h>

/**
 * @brief main function of yoiur cracker
 * 
 * No command line arguments are passed
 * 
 * @return int not checked by test harness
 */
int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0 ) exit(-1);

    struct sockaddr_in server_addr;
    bzero((char*) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_multicast_port());

    if(bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0) exit(-1);

    struct ip_mreq multicastRequest;
    multicastRequest.imr_multiaddr.s_addr = get_multicast_address();
    multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
    if(setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*) &multicastRequest, 
    sizeof(multicastRequest)) < 0) exit(-1);

    Message buffer;
    //char buffer[5000];
    int n = recvfrom(sockfd, (void*)&buffer, sizeof(buffer), 0, NULL, 0);
    //int n = recvfrom(sockfd, &buffer, 4999, 0, NULL, 0);
    if(n < 0) exit(-1);
    std::cout << buffer.alphabet << std::endl;
    std::cout << buffer.hostname << std::endl;
    std::cout << buffer.cruzid << std::endl;
    std::cout << buffer.passwds << std::endl;
    std::cout << ntohl(buffer.num_passwds) << std::endl;
    std::cout << buffer.port << std::endl;

    //char password[4];
    //char a[MAX_HASHES][HASH_LENGTH+1] = buffer.passwds;

    //std::cout << buffer.passwds.size() << std::endl;
    //std::cout << sizeof(buffer.passwds)/sizeof(char)/(HASH_LENGTH + 1) << std::endl;

    std::vector<std::thread> thrs;
    std::mutex iMutex;
    char password2[4];
    char passArr[ntohl(buffer.num_passwds)][4];

    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << buffer.passwds[i] <<std::endl;
        thrs.push_back(std::thread([&iMutex,&passArr,&buffer, i]{
            //char password[4];
            crack(buffer.alphabet, buffer.passwds[i], passArr[i]);
            std::cout << passArr[i] <<std::endl;
            //std::cout << i <<std::endl;
            //std::lock_guard<std::mutex> guard(iMutex);
            //passArr[i] = password;
        }));

        //std::cout << password << std::endl;
    }

    for(auto& t: thrs){
        t.join();
    }

    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << passArr[i] <<std::endl;
    }

    for(unsigned int i = 0; i < ntohl(buffer.num_passwds); i++){
        std::cout << buffer.passwds[i] <<std::endl;
        crack(buffer.alphabet, buffer.passwds[i], password2);
        std::cout << password2 << std::endl;
  
    }

    close(sockfd);
}
