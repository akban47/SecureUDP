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
    int PORT = atoi(argv[1]);
    if (PORT <= 0 || PORT > 65535)
        return 1;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    int did_bind = bind(sockfd, (struct sockaddr *)&servaddr,
                        sizeof(servaddr));

    if (did_bind < 0)
        return errno;

    int BUF_SIZE = 1024;
    char client_buf[BUF_SIZE];
    struct sockaddr_in clientaddr;
    socklen_t clientsize = sizeof(clientaddr);
    int client_connect = 0;

    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);

    flags = fcntl(STDIN_FILENO, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags);

    char stdin_buf[BUF_SIZE];

    while (1)
    {

        int bytes_rec = recvfrom(sockfd, client_buf, BUF_SIZE, 0, (struct sockaddr *)&clientaddr, &clientsize);

        if (bytes_rec > 0)
        {
            int bytes_written = write(STDOUT_FILENO, client_buf, bytes_rec);
            if (bytes_written != bytes_rec)
            {
                perror("write");
                break;
            }
            client_connect = 1;
        }
        if (client_connect)
        {
            int bytes_read = read(STDIN_FILENO, stdin_buf, BUF_SIZE);
            if (bytes_read > 0)
            {
                int bytes_sent = sendto(sockfd, stdin_buf, bytes_read, 0, (struct sockaddr *)&clientaddr, clientsize);
                if (bytes_sent != bytes_read)
                {
                    perror("sendto");
                    break;
                }
            }
        }
    }

    close(sockfd);
    return 0;
}