/*
 * Copyright (C) 2018-2022 David C. Harrison. All right reserved.
 *
 * You may not use, distribute, publish, or modify this code without 
 * the express written permission of the copyright holder.
 */

#include <iostream>
#include <string.h>
#include "cracker.h"

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

    char buffer[1000];
    bzero(buffer,256);
    int n = recvfrom(sockfd, buffer, 1000, 0, NULL, 0);
    if(n < 0) exit(-1);
    std::cout << buffer << std::endl;
}
