#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
   if (argc != 3)
      return 1;
   char *hostname = argv[1];
   int PORT = atoi(argv[2]);
   if (PORT <= 0 || PORT > 65535)
      return 1;
   if (strcmp(hostname, "localhost") == 0)
      hostname = "127.0.0.1";

   int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

   struct sockaddr_in serveraddr;
   serveraddr.sin_family = AF_INET;
   serveraddr.sin_addr.s_addr = inet_addr(hostname);
   serveraddr.sin_port = htons(PORT);

   int flags = fcntl(sockfd, F_GETFL);
   flags |= O_NONBLOCK;
   fcntl(sockfd, F_SETFL, flags);

   flags = fcntl(STDIN_FILENO, F_GETFL);
   flags |= O_NONBLOCK;
   fcntl(STDIN_FILENO, F_SETFL, flags);

   char client_buf[] = "";
   int did_send = sendto(sockfd, client_buf, strlen(client_buf), 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
   if (did_send < 0)
      return errno;

   int BUF_SIZE = 1024;
   char server_buf[BUF_SIZE];
   socklen_t serversize = sizeof(serveraddr);
   char stdin_buf[BUF_SIZE];
   while (1)
   {
      int bytes_recvd = recvfrom(sockfd, server_buf, BUF_SIZE, 0, (struct sockaddr *)&serveraddr, &serversize);
      if (bytes_recvd > 0)
      {
         int bytes_written = write(STDOUT_FILENO, server_buf, bytes_recvd);
         if (bytes_written != bytes_recvd)
            break;
      }
      int bytes_read = read(STDIN_FILENO, stdin_buf, BUF_SIZE);
      if (bytes_read > 0)
      {
         int bytes_sent = sendto(sockfd, stdin_buf, bytes_read, 0, (struct sockaddr *)&serveraddr, serversize);
         if (bytes_sent != bytes_read)
            break;
      }
   }
   close(sockfd);
   return 0;
}