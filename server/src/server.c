#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SSLCERT_PATH "/etc/letsencrypt/live/zybooks.eliasmurcray.me/fullchain.pem"
#define SSLKEY_PATH "/etc/letsencrypt/live/zybooks.eliasmurcray.me/privkey.pem"

void handle_connection(SSL *ssl, struct sockaddr_in *client_addr) {
  char buffer[1024], *request = NULL;
  size_t total_bytes = 0;
  for (;;) {
    ssize_t bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
      perror("read");
      return;
    }
    if (bytes_read == 0) break;
    buffer[bytes_read] = '\0';
    char *new_request = realloc(request, total_bytes + bytes_read + 1);
    if (!new_request) {
      perror("realloc");
      free(request);
      return;
    }
    request = new_request;
    memcpy(request + total_bytes, buffer, bytes_read);
    total_bytes += bytes_read;
    request[total_bytes] = '\0';
    if (strstr(request, "\r\n\r\n")) break;
  }
  printf("%s\n", request);
  char client_ip[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    free(request);
    return;
  }
  char *method = NULL, *path = NULL;
  if (request && strstr(request, "\r\n\r\n")) {
    method = strtok(request, " ");
    path = strtok(NULL, " ");
    if (!method || !path) {
      free(request);
      return;
    }
  }
  printf("%s %s %s\n", method, path, client_ip);
  /*if (strcmp(method, "POST") != 0) {
    free(request);
    return;
  }*/
  free(request);
  const char *response =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 11\r\n"
    "\r\n"
    "Hello world";
  SSL_write(ssl, response, strlen(response));
}

int main() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    return 1;
  }
  if (SSL_CTX_use_certificate_file(ctx, SSLCERT_PATH, SSL_FILETYPE_PEM) <= 0 ||
      SSL_CTX_use_PrivateKey_file(ctx, SSLKEY_PATH, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return 1;
  }
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("Socket creation failed");
    return 1;
  }
  int opt = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt");
    return 1;
  }
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(443),
    .sin_addr.s_addr = INADDR_ANY};
  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(server_fd);
    return 1;
  }
  if (listen(server_fd, 1) < 0) {
    perror("listen");
    close(server_fd);
    return 1;
  }
  printf("Listening on port 443...\n");
  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
      perror("accept");
      continue;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
    } else {
      handle_connection(ssl, &client_addr);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
  }
  close(server_fd);
}
