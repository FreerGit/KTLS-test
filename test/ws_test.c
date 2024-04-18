// #define _POSIX_C_SOURCE 200809L

// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <openssl/err.h>
// #include <openssl/ssl.h>
// #include <stdio.h>
// #include <sys/socket.h>

#include "stx.h"
// #include <fcntl.h>
// #include <sys/select.h>
// #include <unistd.h>
// // using namespace std;

// SSL *ssl;
// int sock;

// int RecvPacket() {
//   int len = 100;
//   char buf[1024 * 64];
//   while (1) {
//     CHECK_TIME({
//       len = SSL_read(ssl, buf, 1024 * 8);
//     },
//                "read");
//     if (len < 0) {
//       int err = SSL_get_error(ssl, len);
//       if (err == SSL_ERROR_WANT_READ) {
//         // printf("retry");
//         continue;
//       }
//       // return 0;
//       if (err == SSL_ERROR_WANT_WRITE) {

//         printf("write");
//         return 0;
//       }
//       if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
//         printf("real error");

//         return -1;
//       }
//     }
//     buf[len] = 0;
//     printf("%s", buf);
//     break;
//   }

//   return -1;
// }

// int SendPacket(const char *buf) {
//   int len = SSL_write(ssl, buf, strlen(buf));
//   if (len < 0) {
//     int err = SSL_get_error(ssl, len);
//     switch (err) {
//     case SSL_ERROR_WANT_WRITE:
//       return 0;
//     case SSL_ERROR_WANT_READ:
//       return 0;
//     case SSL_ERROR_ZERO_RETURN:
//     case SSL_ERROR_SYSCALL:
//     case SSL_ERROR_SSL:
//     default:
//       return -1;
//     }
//   }

//   return -1;
// }

// void log_ssl() {
//   int err;
//   while (err = ERR_get_error()) {
//     char *str = ERR_error_string(err, 0);
//     if (!str)
//       return;
//     printf("%s", str);
//     printf("\n");
//     fflush(stdout);
//   }
// }

// int main(int argc, char *argv[]) {
//   int s;
//   s = socket(AF_INET, SOCK_STREAM, 0);
//   if (!s) {
//     printf("Error creating socket.\n");
//     return -1;
//   }
//   struct sockaddr_in sa;
//   memset(&sa, 0, sizeof(sa));
//   sa.sin_family = AF_INET;
//   sa.sin_addr.s_addr = inet_addr("3.226.231.140"); // address of google.ru
//   sa.sin_port = htons(443);
//   socklen_t socklen = sizeof(sa);
//   int retval = connect(s, (struct sockaddr *)&sa, socklen);
//   if (retval) {
//     log_ssl();
//     return -1;
//   }
//   SSL_library_init();
//   SSLeay_add_ssl_algorithms();
//   SSL_load_error_strings();
//   const SSL_METHOD *meth = TLSv1_2_client_method();
//   SSL_CTX *ctx = SSL_CTX_new(meth);
//   ssl = SSL_new(ctx);
//   if (!ssl) {
//     printf("Error creating SSL.\n");
//     log_ssl();
//     return -1;
//   }

//   SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

//   if (fcntl(s, F_SETFL, SOCK_NONBLOCK) == -1) {
//     printf("Could not switch to non-blocking.\n");
//     return -1;
//   }

//   SSL_set_fd(ssl, s);

//   fd_set fds;
//   FD_ZERO(&fds);
//   FD_SET(s, &fds);

//   while (1) {
//     printf("Attempt.\n");
//     int err;
//     CHECK_TIME({
//       err = SSL_connect(ssl);
//     },
//                "connect");
//     if (err == 1) {
//       break;
//     }

//     int decodedError = SSL_get_error(ssl, err);

//     if (decodedError == SSL_ERROR_WANT_READ) {
//       int result;
//       CHECK_TIME({
//         result = select(s + 1, &fds, NULL, NULL, NULL);
//       },
//                  "select read");
//       if (result == -1) {
//         printf("Read-select error.\n");
//         return -1;
//       }
//     } else if (decodedError == SSL_ERROR_WANT_WRITE) {
//       int result = select(s + 1, NULL, &fds, NULL, NULL);
//       if (result == -1) {
//         printf("Write-select error.\n");
//         return -1;
//       }
//     } else {
//       printf("Error creating SSL connection.  err=%x\n", decodedError);
//       return -1;
//     }
//   }

//   printf("SSL connection using %s\n", SSL_get_cipher(ssl));

//   char request[] = "GET /ip HTTP/1.1\r\nHost: www.httpbin.com\r\nuser-agent: curl/7.81.0\r\naccept: */*\r\n\r\n";
//   SendPacket(request);
//   RecvPacket();

//   return 0;
// }

/* client-tls.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <sys/select.h>

/* the usual suspects */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* socket includes */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <endian.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* wolfSSL */
#define WC_NO_HARDEN
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#define CONNECT_WAIT_SEC 2
#define SELECT_WAIT_SEC 1
#define CERT_FILE "keys/tls_self_signed_certificate.crt"

#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef SOL_TCP
#define SOL_TCP 6
#endif

// int tls_version = 0;
// bool tcp_cork = false;
// bool send_all = false;
// bool ktls_tx = true;
// bool ktls_rx = true;

// int config_ktls(int sockfd, WOLFSSL *ssl) {
//   struct tls_crypto_info *crypto_info;
//   struct tls12_crypto_info_aes_gcm_128 crypto_128;
//   struct tls12_crypto_info_aes_gcm_256 crypto_256;
//   const unsigned char *key, *iv;
//   int key_size, iv_size, crypto_size;
//   unsigned long seq;
//   unsigned int rand_hi, rand_lo;

//   if (!ktls_tx && !ktls_rx)
//     return 0;

//   if ((wolfSSL_GetCipherType(ssl) != WOLFSSL_AEAD_TYPE) ||
//       (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes_gcm)) {
//     printf("ERROR: cipher type is not AES-GCM\n");
//     return -1;
//   }

//   key_size = wolfSSL_GetKeySize(ssl);
//   iv_size = wolfSSL_GetIVSize(ssl);

//   if ((key_size != TLS_CIPHER_AES_GCM_128_KEY_SIZE) &&
//       (key_size != TLS_CIPHER_AES_GCM_256_KEY_SIZE)) {
//     printf("ERROR: invalid AES key size %d\n", key_size);
//     return -1;
//   }

//   if (setsockopt(sockfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
//     printf("ERROR: failed to set TCP_ULP\n");
//     return -1;
//   }

//   memset(&crypto_128, 0, sizeof(crypto_128));
//   memset(&crypto_256, 0, sizeof(crypto_256));

//   if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
//     crypto_info = &crypto_128.info;
//     crypto_size = sizeof(crypto_128);
//   } else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
//     crypto_info = &crypto_256.info;
//     crypto_size = sizeof(crypto_256);
//   }

//   crypto_info->version =
//       (tls_version == WOLFSSL_TLSV1_2)
//           ? TLS1_3_VERSION
//           : TLS1_3_VERSION;
//   crypto_info->cipher_type =
//       (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE)
//           ? TLS_CIPHER_AES_GCM_128
//           : TLS_CIPHER_AES_GCM_256;

//   rand_hi = rand();
//   rand_lo = rand();

//   if (ktls_tx) {
//     key = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
//               ? wolfSSL_GetClientWriteKey(ssl)
//               : wolfSSL_GetServerWriteKey(ssl);

//     iv = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
//              ? wolfSSL_GetClientWriteIV(ssl)
//              : wolfSSL_GetServerWriteIV(ssl);

//     wolfSSL_GetSequenceNumber(ssl, &seq);
//     seq = __bswap_64(seq);

//     if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
//       memcpy(crypto_128.key, key, key_size);
//       if (crypto_info->version == TLS_1_2_VERSION) {
//         memcpy(crypto_128.salt, iv, 4);
//         memcpy(crypto_128.iv, (unsigned char *)&rand_hi, 4);
//         memcpy((crypto_128.iv + 4), (unsigned char *)&rand_lo, 4);
//       } else { /* TLS_1_3_VERSION */
//         memcpy(crypto_128.salt, iv, 4);
//         memcpy(crypto_128.iv, (iv + 4), 8);
//       }
//       memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
//     } else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
//       memcpy(crypto_256.key, key, key_size);
//       if (crypto_info->version == TLS_1_2_VERSION) {
//         memcpy(crypto_256.salt, iv, 4);
//         memcpy(crypto_256.iv, (unsigned char *)&rand_hi, 4);
//         memcpy((crypto_256.iv + 4), (unsigned char *)&rand_lo, 4);
//       } else { /* TLS_1_3_VERSION */
//         memcpy(crypto_256.salt, iv, 4);
//         memcpy(crypto_256.iv, (iv + 4), 8);
//       }
//       memcpy(crypto_256.rec_seq, &seq, sizeof(seq));
//     }

//     if (setsockopt(sockfd, SOL_TLS, TLS_TX, crypto_info,
//                    crypto_size) < 0) {
//       printf("ERROR: failed to set TLS_TX\n");
//       return -1;
//     }
//   }

//   if (ktls_rx) {
//     key = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
//               ? wolfSSL_GetServerWriteKey(ssl)
//               : wolfSSL_GetClientWriteKey(ssl);
//     iv = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
//              ? wolfSSL_GetServerWriteIV(ssl)
//              : wolfSSL_GetClientWriteIV(ssl);

//     wolfSSL_GetPeerSequenceNumber(ssl, &seq);
//     seq = __bswap_64(seq);

//     if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
//       memcpy(crypto_128.key, key, key_size);
//       if (crypto_info->version == TLS_1_2_VERSION) {
//         memcpy(crypto_128.salt, iv, 4);
//         memcpy(crypto_128.iv, (unsigned char *)&rand_hi, 4);
//         memcpy((crypto_128.iv + 4), (unsigned char *)&rand_lo, 4);
//       } else { /* TLS_1_3_VERSION */
//         memcpy(crypto_128.salt, iv, 4);
//         memcpy(crypto_128.iv, (iv + 4), 8);
//       }
//       memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
//     } else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
//       memcpy(crypto_256.key, key, key_size);
//       if (crypto_info->version == TLS_1_2_VERSION) {
//         memcpy(crypto_256.salt, iv, 4);
//         memcpy(crypto_256.iv, (unsigned char *)&rand_hi, 4);
//         memcpy((crypto_256.iv + 4), (unsigned char *)&rand_lo, 4);
//       } else { /* TLS_1_3_VERSION */
//         memcpy(crypto_256.salt, iv, 4);
//         memcpy(crypto_256.iv, (iv + 4), 8);
//       }
//       memcpy(crypto_256.rec_seq, &seq, sizeof(seq));
//     }

//     if (setsockopt(sockfd, SOL_TLS, TLS_RX, crypto_info,
//                    crypto_size) < 0) {
//       printf("ERROR: failed to set TLS_RX\n");
//       return -1;
//     }
//   }

//   return 0;
// }

enum {
  TEST_SELECT_FAIL,
  TEST_TIMEOUT,
  TEST_RECV_READY,
  TEST_SEND_READY,
  TEST_ERROR_READY
};

static int tcp_select(SOCKET_T socketfd, int to_sec, int rx) {
  fd_set fds, errfds;
  fd_set *recvfds = NULL;
  fd_set *sendfds = NULL;
  SOCKET_T nfds = socketfd + 1;
  struct timeval timeout;
  int result;

  FD_ZERO(&fds);
  FD_SET(socketfd, &fds);
  FD_ZERO(&errfds);
  FD_SET(socketfd, &errfds);

  if (rx)
    recvfds = &fds;
  else
    sendfds = &fds;

  result = select(nfds, recvfds, sendfds, &errfds, &timeout);

  if (result == 0)
    return TEST_TIMEOUT;
  else if (result > 0) {
    if (FD_ISSET(socketfd, &fds)) {
      if (rx)
        return TEST_RECV_READY;
      else
        return TEST_SEND_READY;
    } else if (FD_ISSET(socketfd, &errfds))
      return TEST_ERROR_READY;
  }

  return TEST_SELECT_FAIL;
}

int main(int argc, char **argv) {
  int sockfd;
  struct sockaddr_in servAddr;
  char buff[256] = "GET /ip HTTP/1.1\r\nHost: www.httpbin.com\r\n\r\n";
  size_t len;
  int ret;

  /* declare wolfSSL objects */
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;

  /* Check for proper calling convention */
  if (argc != 2) {
    printf("usage: %s <IPv4 address>\n", argv[0]);
    return 0;
  }

  /*---------------------------------*/
  /* Start of wolfSSL initialization and configuration */
  /*---------------------------------*/
  /* Initialize wolfSSL */
  if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: Failed to initialize the library\n");
    goto socket_cleanup;
  }

  /* Create a socket that uses an internet IPv4 address,
   * Sets the socket to be stream based (TCP),
   * 0 means choose the default protocol. */
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "ERROR: failed to create the socket\n");
    ret = -1;
    goto end;
  }

  if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
    fprintf(stderr, "ERROR: failed to set non-blocking\n");
    ret = -1;
    goto end;
  }

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
    ret = -1;
    goto socket_cleanup;
  }

  /* Load client certificates into WOLFSSL_CTX */
  if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL)) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
            CERT_FILE);
    goto ctx_cleanup;
  }

  /* Initialize the server address struct with zeros */
  memset(&servAddr, 0, sizeof(servAddr));

  /* Fill in the server address */
  servAddr.sin_family = AF_INET;  /* using IPv4      */
  servAddr.sin_port = htons(443); /* on DEFAULT_PORT */

  /* Get the server IPv4 address from the command line call */
  if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) {
    fprintf(stderr, "ERROR: invalid address\n");
    ret = -1;
    goto end;
  }

  /* Connect to the server */
  while (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      /* non-blocking connect, wait for read activity on socket */
      tcp_select(sockfd, CONNECT_WAIT_SEC, 1);
      continue;
    } else if (errno == EINPROGRESS || errno == EALREADY) {
      break;
    }
    fprintf(stderr, "ERROR: failed to connect %d\n\n", errno);
    ret = -1;
    goto end;
  }
  /* Create a WOLFSSL object */
  if ((ssl = wolfSSL_new(ctx)) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
    ret = -1;
    goto ctx_cleanup;
  }

  /* Attach wolfSSL to the socket */
  if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
    goto cleanup;
  }

  /* Connect to wolfSSL on the server side */
  int err;
  do {
    ret = wolfSSL_connect(ssl);
    err = wolfSSL_get_error(ssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ)
      tcp_select(sockfd, SELECT_WAIT_SEC, 1);
  } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

  if (ret != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR %d: failed to connect to wolfSSL %d\n", err, ret);
    goto end;
  }

  // if (config_ktls(sockfd, ssl) < 0) {
  //   printf("ERROR: failed to configure KTLS\n");
  //   goto end;
  // }

  // if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
  //   fprintf(stderr, "ERROR: failed to connect to wolfSSL %d %d\n ", ret, WOLFSSL_ERROR_WANT_READ);
  //   goto cleanup;
  // }

  /* Get a message for the server from stdin */
  // printf("Message for server: ");
  // memset(buff, 0, sizeof(buff));
  // if (fgets(buff, sizeof(buff), stdin) == NULL) {
  //   fprintf(stderr, "ERROR: failed to get message for server\n");
  //   ret = -1;
  //   goto cleanup;
  // }
  // char *msg =
  //     memcpy(buff, msg, )
  len = strnlen(buff, sizeof(buff));

  // if (ktls_tx) {
  //   printf("IS KTLS_TXS");
  //   exit(1);
  // } else {
  // }

  // if (ktls_rx) {
  //   printf("IS KTLS_RXS");
  //   exit(1);
  // }

  /* Send the message to the server */
  do {
    ret = wolfSSL_write(ssl, buff, len);
    err = wolfSSL_get_error(ssl, ret);
  } while (err == WOLFSSL_ERROR_WANT_WRITE);
  if (ret < 0) {
    fprintf(stderr, "ERROR %d: failed to write\n", ret);
    goto end;
  }

  /* Read the server data into our buff array */
  memset(buff, 0, sizeof(buff));
  do {
    CHECK_TIME({
      ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
      err = wolfSSL_get_error(ssl, ret);
    },
               "read");
  } while (err == WOLFSSL_ERROR_WANT_READ);
  if (ret < 0) {
    fprintf(stderr, "ERROR %d: failed to read\n", ret);
    goto end;
  }

  /* Print to stdout any data the server sends */
  printf("Server: %s\n", buff);

  /* Read the server data into our buff array */
  memset(buff, 0, sizeof(buff));
  do {
    CHECK_TIME({
      ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
      err = wolfSSL_get_error(ssl, ret);
    },
               "second_read");
  } while (err == WOLFSSL_ERROR_WANT_READ);
  if (ret < 0) {
    fprintf(stderr, "ERROR %d: failed to read\n", ret);
    goto end;
  }

  /* Print to stdout any data the server sends */
  printf("Server: %s\n", buff);

  /* Bidirectional shutdown */
  while (wolfSSL_shutdown(ssl) == WOLFSSL_SHUTDOWN_NOT_DONE) {
    // printf("Shutdown not complete\n");
  }

  printf("Shutdown complete\n");

  ret = 0;

  /* Cleanup and return */
cleanup:
  wolfSSL_free(ssl); /* Free the wolfSSL object                  */
ctx_cleanup:
  wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
socket_cleanup:
  close(sockfd); /* Close the connection to the server       */
end:
  return ret; /* Return reporting a success               */
}

// https://stackoverflow.com/questions/59107556/setsockopt-fails-while-kernel-tls-option-enabling