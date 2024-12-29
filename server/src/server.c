#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void handle_connection(int client_fd, struct sockaddr_in *client_addr) {
  char buffer[1024];
  size_t total_bytes = 0;
  char *request = NULL;
  for (;;) {
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) return;
    if (bytes_read == 0) break;
    buffer[bytes_read] = '\0';
    char *new_request = realloc(request, total_bytes + bytes_read + 1);
    if (!new_request) {
      perror("realloc");
      free(request);
      goto internal_server_error;
      return;
    }
    request = new_request;
    memcpy(request + total_bytes, buffer, bytes_read);
    total_bytes += bytes_read;
    request[total_bytes] = '\0';
    if (strstr(request, "\r\n\r\n")) {
      break;
    }
  }
  char client_ip[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    free(request);
    goto internal_server_error;
  }
  char *method = NULL, *path = NULL;
  if (request && strstr(request, "\r\n\r\n")) {
    method = strtok(request, " ");
    path = strtok(NULL, " ");
    if (!method || !path) {
      free(request);
      goto internal_server_error;
    }
  }
  printf("%s %s %s\n", method, path, client_ip);
  if (strcmp(method, "POST") != 0) {
    free(request);
    goto internal_server_error;
  }
  free(request);
  const char *response =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: 13\r\n"
      "\r\n"
      "{\"foo\":\"bar\"}";
  write(client_fd, response, strlen(response));
  return;
internal_server_error: {
  const char *response =
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 0\r\n"
      "\r\n";
  write(client_fd, response, strlen(response));
  return;
}
}

int main() {
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
      .sin_port = htons(3000),
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
  printf("Listening on port 3000...\n");
  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
      perror("accept");
      continue;
    }
    handle_connection(client_fd, &client_addr);
    close(client_fd);
  }
  close(server_fd);
}
