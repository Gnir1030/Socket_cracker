/*
 * Copyright (C) 2018-2022 David C. Harrison. All right reserved.
 *
 * You may not use, distribute, publish, or modify this code without 
 * the express written permission of the copyright holder.
 */

/******************  DO NOT MODIFY THIS FILE ****************************
 *
 * It is not included in the subission archive created by 'make submit'.
 *
 * If you modify it and your code relies on those modifications, your code
 * will not compile in the automated test harness and will be unable to
 * execute any tests.
 *
 * To put it another way, if you modify this file, you will get a big fat
 * ZERO on this assignment.
 *
 ************************************************************************/

#pragma once

#include <netinet/in.h>

#define HASH_LENGTH       13
#define ALPHABET_LEN      62
#define MAX_HASHES        64 // Make sure you test up to this limit
#define MAX_HOSTNAME_LEN  64
#define MAX_CRUZID_LEN    32

/*
 * On-wire datagram. 
 *
 * Numeric elements should be converted to network byte-order before transmission
 * and converted back to host byte-order on receipt.
 */
typedef struct message_t {
    char alphabet[ALPHABET_LEN+1];           // The plain text password alphabet
    char cruzid[MAX_CRUZID_LEN];             // Who this datagram is for
    char passwds[MAX_HASHES][HASH_LENGTH+1]; // NUM_PASSWD plain text passwords or password hashes
    unsigned int num_passwds;                // Number of plain text passwords or password  hases in PASSWDS
    char hostname[MAX_HOSTNAME_LEN];         // Host to return decrypted passwords to over TCP
    unsigned int port;                       // Port to return decrypted passwords to
}
Message;

/*
 * Find the four character plain-text password PASSWD given the 
 * password hash HASH.
 *
 * If the keyspace is restricted to [a..z][A..Z][0..9], i.e ALPHABET
 * is "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
 * then "Y6f0" is a valid password, but "a$^K" is not.
 */
void crack(const char *alphabet, const char *hash, char *passwd);

/*
 * Returns the multicast address the currently logged in user should use,
 * initially for listening for the in-bound Message, then for communication
 * between servers, if required.
 */
in_addr_t get_multicast_address();

/*
 * Returns the multicast port the currently logged in user should use,
 * initially for listening for the in-bound Message, then for communication
 * between servers, if required.
 */
unsigned int get_multicast_port();

/*
 * Returns the unicast port the currently logged in user should use
 * for TCP connections between servers if required.
 */
unsigned int get_unicast_port();
