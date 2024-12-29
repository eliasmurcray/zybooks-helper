#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <time.h>

#define MAX_EVENTS 16
#define SSLCERT_PATH "/etc/letsencrypt/live/zybooks.eliasmurcray.me/fullchain.pem"
#define SSLKEY_PATH "/etc/letsencrypt/live/zybooks.eliasmurcray.me/privkey.pem"

void handle_connection(SSL *ssl, struct sockaddr_in *client_addr) {
  char buffer[1024], *request = NULL;
  size_t total_bytes = 0;
  for (;;) {
    ssize_t bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
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
  char *method = NULL, *path = NULL;
  if (request && strstr(request, "\r\n\r\n")) {
    method = strtok(request, " ");
    path = strtok(NULL, " ");
    if (!method || !path) {
      free(request);
      return;
    }
  }
  char client_ip[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    free(request);
    return;
  }
  time_t now;
  time(&now);
  struct tm *tm_info = localtime(&now);
  char timestamp[20];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info);
  const char *log_entry_fmt = "[%s] %s %s %s\n";
  size_t log_entry_length = snprintf(NULL, 0, log_entry_fmt, timestamp, method, path, client_ip);
  char *log_entry = malloc(log_entry_length + 1);
  if (snprintf(log_entry, log_entry_length, log_entry_fmt, timestamp, method, path, client_ip) < 0) {
    perror("snprintf");
    free(request);
    return;
  }
  free(request);
  log_entry[log_entry_length] = '\0';
  printf("%s\n", log_entry);
  const char *response_fmt =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: %zu\r\n"
    "\r\n"
    "%s";
  size_t response_length = snprintf(NULL, 0, response_fmt, log_entry_length - 2, log_entry);
  char *response = malloc(response_length + 1);
  if (snprintf(response, response_length, response_fmt, log_entry_length - 2, log_entry) < 0) {
    perror("snprintf");
    free(log_entry);
    return;
  }
  /* TODO: Add retries for writes */
  if (SSL_write(ssl, response, strlen(response)) < 0) {
    perror("SSL_write");
  }
  free(log_entry);
  free(response);
}

int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
  if (set_nonblocking(server_fd) < 0) {
    perror("set_nonblocking server");
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
  if (listen(server_fd, SOMAXCONN) < 0) {
    perror("listen");
    close(server_fd);
    return 1;
  }
  printf("Listening on port 443...\n");
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
    close(server_fd);
    return 1;
  }
  struct epoll_event event, events[MAX_EVENTS];
  event.events = EPOLLIN;
  event.data.fd = server_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
    perror("epoll_ctl");
    close(server_fd);
    return 1;
  }
  for (;;) {
    int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1), i = 0;
    for (; i < n; i ++) {
      if (events[i].data.fd != server_fd) continue;
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
        perror("SSL_accept");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        continue;
      }
      if (set_nonblocking(client_fd) < 0) {
        perror("set_nonblocking client");
        close(client_fd);
        SSL_free(ssl);
        continue;
      }
      struct epoll_event client_event;
      client_event.events = EPOLLIN | EPOLLET;
      client_event.data.fd = client_fd;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_event);
      handle_connection(ssl, &client_addr);
      SSL_free(ssl);
      close(client_fd);
    }
  }
  close(server_fd);
}
