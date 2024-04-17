#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <sys/select.h>
#include <unistd.h>

// using namespace std;

SSL *ssl;
int sock;

int RecvPacket() {
  int len = 100;
  char buf[1024 * 64];
  while (1) {
    len = SSL_read(ssl, buf, 1024);
    if (len < 0) {
      int err = SSL_get_error(ssl, len);
      if (err == SSL_ERROR_WANT_READ) {
        // printf("retry");
        continue;
      }
      // return 0;
      if (err == SSL_ERROR_WANT_WRITE) {

        printf("write");
        return 0;
      }
      if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        printf("real error");

        return -1;
      }
    }
    buf[len] = 0;
    printf("%s", buf);
    break;
  }

  return -1;
}

int SendPacket(const char *buf) {
  int len = SSL_write(ssl, buf, strlen(buf));
  if (len < 0) {
    int err = SSL_get_error(ssl, len);
    switch (err) {
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_WANT_READ:
      return 0;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    default:
      return -1;
    }
  }

  return -1;
}

void log_ssl() {
  int err;
  while (err = ERR_get_error()) {
    char *str = ERR_error_string(err, 0);
    if (!str)
      return;
    printf("%s", str);
    printf("\n");
    fflush(stdout);
  }
}

int main(int argc, char *argv[]) {
  int s;
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (!s) {
    printf("Error creating socket.\n");
    return -1;
  }
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr("3.226.231.140"); // address of google.ru
  sa.sin_port = htons(443);
  socklen_t socklen = sizeof(sa);
  int retval = connect(s, (struct sockaddr *)&sa, socklen);
  if (retval) {
    log_ssl();
    return -1;
  }
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  SSL_load_error_strings();
  const SSL_METHOD *meth = TLSv1_2_client_method();
  SSL_CTX *ctx = SSL_CTX_new(meth);
  ssl = SSL_new(ctx);
  if (!ssl) {
    printf("Error creating SSL.\n");
    log_ssl();
    return -1;
  }

  if (fcntl(s, F_SETFL, SOCK_NONBLOCK) == -1) {
    printf("Could not switch to non-blocking.\n");
    return -1;
  }

  SSL_set_fd(ssl, s);

  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(s, &fds);

  while (1) {
    printf("Attempt.\n");

    int err = SSL_connect(ssl);
    if (err == 1) {
      break;
    }

    int decodedError = SSL_get_error(ssl, err);

    if (decodedError == SSL_ERROR_WANT_READ) {
      int result = select(s + 1, &fds, NULL, NULL, NULL);
      if (result == -1) {
        printf("Read-select error.\n");
        return -1;
      }
    } else if (decodedError == SSL_ERROR_WANT_WRITE) {
      int result = select(s + 1, NULL, &fds, NULL, NULL);
      if (result == -1) {
        printf("Write-select error.\n");
        return -1;
      }
    } else {
      printf("Error creating SSL connection.  err=%x\n", decodedError);
      return -1;
    }
  }

  printf("SSL connection using %s\n", SSL_get_cipher(ssl));

  char request[] = "GET /ip HTTP/1.1\r\nHost: www.httpbin.com\r\nuser-agent: curl/7.81.0\r\naccept: */*\r\n\r\n";
  SendPacket(request);
  RecvPacket();

  return 0;
}