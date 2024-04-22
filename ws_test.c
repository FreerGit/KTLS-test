

#include "stx.h"

#define __USE_MISC
#define _POSIX_C_SOURCE 200809L
#include <endian.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#define WC_NO_HARDEN
#include <wolfssl/ssl.h>

#define CONNECT_WAIT_SEC 2
#define SELECT_WAIT_SEC 1
#define CERT_FILE "keys/tls_self_signed_certificate.crt"

int tls_version = 0;
bool tcp_cork = false;
bool send_all = false;
bool ktls_tx = true;
bool ktls_rx = true;

int config_ktls(int sockfd, WOLFSSL *ssl) {
  struct tls_crypto_info *crypto_info;
  struct tls12_crypto_info_aes_gcm_128 crypto_128;
  struct tls12_crypto_info_aes_gcm_256 crypto_256;
  const unsigned char *key, *iv;
  int key_size, iv_size, crypto_size;
  unsigned long seq;
  unsigned int rand_hi, rand_lo;
  time_t t;

  if (!ktls_tx && !ktls_rx)
    return 0;

  if ((wolfSSL_GetCipherType(ssl) != WOLFSSL_AEAD_TYPE) ||
      (wolfSSL_GetBulkCipher(ssl) != wolfssl_aes_gcm)) {
    printf("ERROR: cipher type is not AES-GCM\n");
    return -1;
  }

  key_size = wolfSSL_GetKeySize(ssl);
  iv_size = wolfSSL_GetIVSize(ssl);

  if ((key_size != TLS_CIPHER_AES_GCM_128_KEY_SIZE) &&
      (key_size != TLS_CIPHER_AES_GCM_256_KEY_SIZE)) {
    printf("ERROR: invalid AES key size %d\n", key_size);
    return -1;
  }

  if (setsockopt(sockfd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
    printf("ERROR: failed to set TCP_ULP\n");
    return -1;
  }

  memset(&crypto_128, 0, sizeof(crypto_128));
  memset(&crypto_256, 0, sizeof(crypto_256));

  if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
    crypto_info = &crypto_128.info;
    crypto_size = sizeof(crypto_128);
  } else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
    crypto_info = &crypto_256.info;
    crypto_size = sizeof(crypto_256);
  }

  crypto_info->version =
      (tls_version == WOLFSSL_TLSV1_2)
          ? TLS_1_2_VERSION
          : TLS_1_3_VERSION;
  crypto_info->cipher_type =
      (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE)
          ? TLS_CIPHER_AES_GCM_128
          : TLS_CIPHER_AES_GCM_256;

  srand((unsigned int)time(&t));
  rand_hi = rand();
  rand_lo = rand();

  if (ktls_tx) {
    key = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
              ? wolfSSL_GetClientWriteKey(ssl)
              : wolfSSL_GetServerWriteKey(ssl);

    iv = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
             ? wolfSSL_GetClientWriteIV(ssl)
             : wolfSSL_GetServerWriteIV(ssl);

    wolfSSL_GetSequenceNumber(ssl, &seq);
    seq = htobe64(seq);

    if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
      memcpy(crypto_128.key, key, key_size);
      if (crypto_info->version == TLS_1_2_VERSION) {
        memcpy(crypto_128.salt, iv, 4);
        memcpy(crypto_128.iv, (unsigned char *)&rand_hi, 4);
        memcpy((crypto_128.iv + 4), (unsigned char *)&rand_lo, 4);
      } else { /* TLS_1_3_VERSION */
        memcpy(crypto_128.salt, iv, 4);
        memcpy(crypto_128.iv, (iv + 4), 8);
      }
      memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
    } else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
      memcpy(crypto_256.key, key, key_size);
      if (crypto_info->version == TLS_1_2_VERSION) {
        memcpy(crypto_256.salt, iv, 4);
        memcpy(crypto_256.iv, (unsigned char *)&rand_hi, 4);
        memcpy((crypto_256.iv + 4), (unsigned char *)&rand_lo, 4);
      } else { /* TLS_1_3_VERSION */
        memcpy(crypto_256.salt, iv, 4);
        memcpy(crypto_256.iv, (iv + 4), 8);
      }
      memcpy(crypto_256.rec_seq, &seq, sizeof(seq));
    }

    if (setsockopt(sockfd, SOL_TLS, TLS_TX, crypto_info,
                   crypto_size) < 0) {
      printf("ERROR: failed to set TLS_TX\n");
      return -1;
    }
  }

  if (ktls_rx) {
    key = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
              ? wolfSSL_GetServerWriteKey(ssl)
              : wolfSSL_GetClientWriteKey(ssl);
    iv = (wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END)
             ? wolfSSL_GetServerWriteIV(ssl)
             : wolfSSL_GetClientWriteIV(ssl);

    wolfSSL_GetPeerSequenceNumber(ssl, &seq);
    seq = htobe64(seq);

    if (key_size == TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
      memcpy(crypto_128.key, key, key_size);
      if (crypto_info->version == TLS_1_2_VERSION) {
        memcpy(crypto_128.salt, iv, 4);
        memcpy(crypto_128.iv, (unsigned char *)&rand_hi, 4);
        memcpy((crypto_128.iv + 4), (unsigned char *)&rand_lo, 4);
      } else { /* TLS_1_3_VERSION */
        memcpy(crypto_128.salt, iv, 4);
        memcpy(crypto_128.iv, (iv + 4), 8);
      }
      memcpy(crypto_128.rec_seq, &seq, sizeof(seq));
    } else { /* (key_size == TLS_CIPHER_AES_GCM_256_KEY_SIZE) */
      memcpy(crypto_256.key, key, key_size);
      if (crypto_info->version == TLS_1_2_VERSION) {
        memcpy(crypto_256.salt, iv, 4);
        memcpy(crypto_256.iv, (unsigned char *)&rand_hi, 4);
        memcpy((crypto_256.iv + 4), (unsigned char *)&rand_lo, 4);
      } else { /* TLS_1_3_VERSION */
        memcpy(crypto_256.salt, iv, 4);
        memcpy(crypto_256.iv, (iv + 4), 8);
      }
      memcpy(crypto_256.rec_seq, &seq, sizeof(seq));
    }

    if (setsockopt(sockfd, SOL_TLS, TLS_RX, crypto_info,
                   crypto_size) < 0) {
      printf("ERROR: failed to set TLS_RX\n");
      return -1;
    }
  }

  return 0;
}
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

  if (config_ktls(sockfd, ssl) < 0) {
    printf("ERROR: failed to configure KTLS\n");
    goto end;
  }

  len = strnlen(buff, sizeof(buff));

  printf("len %d\n", len);
  do {
    CHECK_TIME({
      ret = send(sockfd, buff, len, 0);
    },
               "send time");
    printf("sent: %d\n", ret);
    // err = wolfSSL_get_error(ssl, ret);
  } while (ret == -1);
  if (ret < 0) {
    fprintf(stderr, "ERROR %d: failed to write\n", ret);
    goto end;
  }
  char string_read[255];
  int times = 0;
  int n = recv(sockfd, string_read, strnlen(buff, sizeof(string_read)), 0);
  printf("ret: %d\nServer: %s\n", n, string_read);

  // start:
  //   if (n == -1) {
  //     if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
  //       goto start;
  //     }
  //     // perror("recv");

  //     // return -1;
  //   }

  // printf("fdsafdsa\n\n\n\n");
  // times++;
  // if (times < 10) {
  //   printf("fdsaf\n");
  //   goto start;
  // }

  // char buffer[16384];
  // char cmsg_size[CMSG_SPACE(sizeof(unsigned char))];
  // struct msghdr msg = {0};
  // msg.msg_control = cmsg_size;
  // msg.msg_controllen = sizeof(cmsg_size);

  // struct iovec msg_iov;
  // msg_iov.iov_base = buffer;
  // msg_iov.iov_len = 16384;

  // msg.msg_iov = &msg_iov;
  // msg.msg_iovlen = 1;
  // do {

  //   ret = recvmsg(sockfd, &msg, MSG_DONTWAIT /* flags */);

  //   struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  //   if (cmsg->cmsg_level == SOL_TLS &&
  //       cmsg->cmsg_type == TLS_GET_RECORD_TYPE) {
  //     int record_type = *((unsigned char *)CMSG_DATA(cmsg));
  //     // Do something with record_type, and control message data in
  //     // buffer.
  //     //
  //     // Note that record_type may be == to application data (23).
  //   } else {
  //     // printf("code : %d\n read: %s\n", ret, msg.msg_iov->iov_base);
  //     // Buffer contains application data.
  //   }

  // } while (ret == -1);
  // printf("code : %d\n read: %s\n", ret, msg.msg_iov->iov_base);

  /* Read the server data into our buff array */
  // memset(buff, 0, sizeof(buff));
  // do {
  //   CHECK_TIME({
  //     if (ktls_rx) {
  //       ret = recvmsg(sockfd, &msg, 0);
  //     } else {
  //       ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
  //       err = wolfSSL_get_error(ssl, ret);
  //     }
  //   },
  //              "read");
  // } while (err == -1);
  // if (ret < 0) {
  //   fprintf(stderr, "ERROR %d: failed to read\n", ret);
  //   goto end;
  // }

  /* Print to stdout any data the server sends */
  // printf("Server: %s\n", buff);

  // /* Read the server data into our buff array */
  // memset(buff, 0, sizeof(buff));
  // do {
  //   CHECK_TIME({
  //     ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
  //     err = wolfSSL_get_error(ssl, ret);
  //   },
  //              "second_read");
  // } while (err == WOLFSSL_ERROR_WANT_READ);
  // if (ret < 0) {
  //   fprintf(stderr, "ERROR %d: failed to read\n", ret);
  //   goto end;
  // }

  /* Print to stdout any data the server sends */
  // printf("Server: %s\n", buff);

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