// server code file//

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define LISTEN_BUFFER_SIZE 4

static void handle_error(const char *message, int sockid) {
  fprintf(stderr, "%s", message);
  if (sockid >= 0) {
    close(sockid);
  }
  exit(EXIT_FAILURE);
}

int main(void) {
  const int server_port = 6969;
  const char *server_ip = "192.168.1.1";

  int sockid = socket(AF_INET, SOCK_STREAM, 0);
  if (sockid < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);
  server_addr.sin_addr.s_addr = inet_addr(server_ip);

  if (bind(sockid, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("bind");
    handle_error("Error during binding\n", sockid);
  }

  if (listen(sockid, LISTEN_BUFFER_SIZE) < 0) {
    perror("listen");
    handle_error("Error during listen\n", sockid);
  }

  printf("TCP listening on %s:%d\n", server_ip, server_port);

  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  int client_sock =
      accept(sockid, (struct sockaddr *)&client_addr, &client_addr_len);
  if (client_sock < 0) {
    perror("accept");
    handle_error("Error during accept\n", sockid);
  }

  printf("Accepted connection from %d (%s:%d)\n", client_sock,
         inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

  unsigned char buffer_in[BUFFER_SIZE];
  ssize_t received = recv(client_sock, buffer_in, sizeof(buffer_in) - 1, 0);
  if (received < 0) {
    perror("recv");
    handle_error("Error during recv\n", client_sock);
  }

  if (received == 0) {
    printf("Client disconnected before sending data\n");
  } else {
    buffer_in[received] = '\0';
    printf("%s\n", buffer_in);
  }

  close(client_sock);
  close(sockid);

  return 0;
}