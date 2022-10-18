#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#define MAX 80
#define PORT 8082
#define SA struct sockaddr


int client_conn()
{
        int sockfd, connfd;
        struct sockaddr_in servaddr = {}, cli;

        // socket create and verification
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
                printf("socket creation failed...\n");
                exit(0);
        }

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        servaddr.sin_port = htons(PORT);

        // connect the client socket to server socket
        if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        perror("connection with the server failed...\n");
                exit(0);
        }
    return sockfd;
}


void client_disconn(int sockfd) {
    char buff[] = "Hi!";
    write(sockfd, buff, sizeof(buff));

        // close the socket
        close(sockfd);
}


// Driver function
int main()
{
        int sockfd, connfd;
    socklen_t len;
        struct sockaddr_in servaddr, cli;

        // socket create and verification
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
                printf("socket creation failed...\n");
                exit(0);
        }
        else
                printf("Socket successfully created..\n");
        bzero(&servaddr, sizeof(servaddr));

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(PORT);

        // Binding newly created socket to given IP and verification
        if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
                printf("socket bind failed...\n");
                exit(0);
        }
        else
                printf("Socket successfully binded..\n");

        // Now server is ready to listen and verification
        if ((listen(sockfd, 5)) != 0) {
                printf("Listen failed...\n");
                exit(0);
        }
        else
                printf("Server listening..\n");
        len = sizeof(cli);

    char buf[4];

    for (int i = 0; i < 100000; i++){
                int client_fd = client_conn();
                // Accept the data packet from client and verification
                connfd = accept(sockfd, (SA*)&cli, &len);
                if (connfd < 0) {
                        printf("server accept failed...\n");
                        exit(0);
                }
        
                client_disconn(client_fd);
                // recv(int sockfd, void *buf, size_t len, int flags);
                recv(connfd, buf, 0, 0);
                close(connfd);
    }
        close(sockfd);
}
