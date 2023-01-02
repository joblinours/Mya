//server code file//

#include <stdio.h>
#include<sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define LISTEN_BUFFER_SIZE 4

void handleError ( const char* msg, int sockid )
{
    fprintf(stderr, msg);
    close(sockid);
    exit(1);
}

int main (void)
{
    int sockid = socket(AF_INET,SOCK_STREAM,0);
    int server_port = 6969;
    char * server_ip = "192.168.1.1";

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    unsigned char buffer_in [BUFFER_SIZE];

    int bind_result = bind(sockid, (struct sockaddr *) &server_addr, sizeof( server_addr ));
    if ( bind_result >= 0)
    {
        printf("TCP listening on %s:%d\n", server_ip, server_port);
    }
    else
    {
        handleError("Error during binding\n", sockid);
    }

    listen(sockid, LISTEN_BUFFER_SIZE);
    int client_sock = accept(sockid, (struct sockaddr *) &client_addr, &client_addr_len);
    printf("Accepted connection from %d (%s:%d)\n", client_sock, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    int size_rec = recv (client_sock, ( unsigned char *) buffer_in, BUFFER_SIZE, 0);
    buffer_in[size_rec] = '\0';
    for (int i = 0; i < size_rec; i++){
    printf("%c", buffer_in[i]);
    }

    printf("\n");
    close ( sockid ) ;
 }