#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define LISTEN_PORT 11221

int main() {
  char buf[64];

  int sock;
  int peersock;
  struct sockaddr_in my_addr;
  int reuse = 1;

  if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    perror("socket");
    return(1);
  }

  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
    perror("setsockopt");
    return(1);
  }

  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(LISTEN_PORT);
  if(bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1) {
    perror("bind");
    return(1);
  }

  if(listen(sock, 5) == -1) {
    perror("listen");
    return(1);
  }

  while(1) {
    if((peersock = accept(sock, NULL, 0)) == -1) {
      perror("accept");
      return(1);
    }

    if(fork()) continue;

    if(read(peersock, buf, 4096) == -1) {
      perror("read");
      return(1);
    }

    shutdown(peersock, SHUT_RDWR);
    close(peersock);
    return(0);
  }

  return(0);
}
