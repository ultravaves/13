#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

#define BUFFER_SIZE 1024

char current_file[256] = {0};
int shift = 0;

typedef unsigned int DES_LONG;
typedef unsigned char DES_cblock[8];

void DES_set_key(const DES_cblock key, DES_LONG *schedule);
void DES_round(DES_LONG *data, const DES_LONG *ks, int round);
void DES_crypt(DES_LONG *data, const DES_LONG *ks, int encrypt);
void DES_ecb_encrypt(const DES_cblock input, DES_cblock output, const DES_cblock key);

/* ====================== DES IMPLEMENTATION ====================== */

/* Initial Permutation Table */
static const int IP[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                           62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                           57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
                           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

static const int FP[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                           38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                           36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                           34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25};

static const int PC1[56] = {57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
                            35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
                            46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};

static const int PC2[48] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
                            26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
                            51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

static const int shifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static const int S[8][64] = {
    {14, 4,  13, 1, 2,  15, 11, 8, 3, 10, 6, 12, 5,  9,  0,  7,  0,  15, 7,  4,  14, 2,
     13, 1,  10, 6, 12, 11, 9,  5, 3, 8,  4, 1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,
     3,  10, 5,  0, 15, 12, 8,  2, 4, 9,  1, 7,  5,  11, 3,  14, 10, 0,  6,  13},
    {15, 1,  8,  14, 6,  11, 3,  4, 9,  7,  2, 13, 12, 0,  5,  10, 3,  13, 4,  7, 15, 2,
     8,  14, 12, 0,  1,  10, 6,  9, 11, 5,  0, 14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,
     9,  3,  2,  15, 13, 8,  10, 1, 3,  15, 4, 2,  11, 6,  7,  12, 0,  5,  14, 9},
    {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7, 11, 4,  2,  8,  13, 7, 0,  9, 3, 4,
     6,  10, 2,  8,  5, 14, 12, 11, 15, 1,  13, 6, 4,  9,  8,  15, 3,  0, 11, 1, 2, 12,
     5,  10, 14, 7,  1, 10, 13, 0,  6,  9,  8,  7, 4,  15, 14, 3,  11, 5, 2,  12},
    {7, 13, 14, 3, 0, 6,  9, 10, 1,  2, 8,  5, 11, 12, 4,  15, 13, 8,  11, 5, 6, 15,
     0, 3,  4,  7, 2, 12, 1, 10, 14, 9, 10, 6, 9,  0,  12, 11, 7,  13, 15, 1, 3, 14,
     5, 2,  8,  4, 3, 15, 0, 6,  10, 1, 13, 8, 9,  4,  5,  11, 12, 7,  2,  14},
    {2,  12, 4, 1,  7,  10, 11, 6, 8, 5,  3, 15, 13, 0,  14, 9,  14, 11, 2,  12, 4,  7,
     13, 1,  5, 0,  15, 10, 3,  9, 8, 6,  4, 2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,
     6,  3,  0, 14, 11, 8,  12, 7, 1, 14, 2, 13, 6,  15, 0,  9,  10, 4,  5,  3},
    {12, 1,  10, 15, 9,  2,  6, 8,  0, 13, 3,  4,  14, 7,  5, 11, 10, 15, 4, 2, 7, 12,
     9,  5,  6,  1,  13, 14, 0, 11, 3, 8,  9,  14, 15, 5,  2, 8,  12, 3,  7, 0, 4, 10,
     1,  13, 11, 6,  4,  3,  2, 12, 9, 5,  15, 10, 11, 14, 1, 7,  6,  0,  8, 13},
    {4, 11, 2,  14, 15, 0,  8,  13, 3, 12, 9,  7, 5,  10, 6,  1,  13, 0,  11, 7,  4, 9,
     1, 10, 14, 3,  5,  12, 2,  15, 8, 6,  1,  4, 11, 13, 12, 3,  7,  14, 10, 15, 6, 8,
     0, 5,  9,  2,  6,  11, 13, 8,  1, 4,  10, 7, 9,  5,  0,  15, 14, 2,  3,  12},
    {13, 2, 8,  4, 6, 15, 11, 1,  10, 9,  3, 14, 5,  0,  12, 7,  1,  15, 13, 8, 10, 3,
     7,  4, 12, 5, 6, 11, 0,  14, 9,  2,  7, 11, 4,  1,  9,  12, 14, 2,  0,  6, 10, 13,
     15, 3, 5,  8, 2, 1,  14, 7,  4,  10, 8, 13, 15, 12, 9,  0,  3,  5,  6,  11}};

static const int P[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
                          2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25};

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define PERM_OP(a, b, t, n, m) ((t) = ((a) >> (n)) ^ (b), (b) ^= (m), (a) ^= (t) << (n))

void DES_set_key(const DES_cblock key, DES_LONG *schedule) {
    DES_LONG c, d, t;
    DES_cblock pc1m = {0};

    for (int i = 0; i < 56; i++) {
        int bit = PC1[i] - 1;
        int byte_pos = bit / 8;
        int bit_pos = 7 - (bit % 8);
        int val = (key[byte_pos] & (1 << bit_pos)) ? 1 : 0;

        if (val) {
            int out_byte = i / 8;
            int out_bit = 7 - (i % 8);
            pc1m[out_byte] |= (1 << out_bit);
        }
    }

    c = (pc1m[0] << 24) | (pc1m[1] << 16) | (pc1m[2] << 8) | pc1m[3];
    d = (pc1m[4] << 24) | (pc1m[5] << 16) | (pc1m[6] << 8) | pc1m[7];

    PERM_OP(d, c, t, 4, 0x0f0f0f0f);

    for (int i = 0; i < 16; i++) {
        c = ROTATE_LEFT(c, shifts[i]);
        d = ROTATE_LEFT(d, shifts[i]);

        DES_LONG cd = (d << 16) | (c & 0xffff);
        schedule[i] = 0;

        for (int j = 0; j < 48; j++) {
            int bit = PC2[j] - 1;
            if (cd & (1L << (31 - bit))) {
                schedule[i] |= (1L << (47 - j));
            }
        }
    }
}

void DES_round(DES_LONG *data, const DES_LONG *ks, int round) {
    DES_LONG r = data[1];
    DES_LONG l = data[0];
    DES_LONG t;

    /* Исправленный расчет с проверкой на переполнение */
    t = ((r & 0x00000001) << 23) | ((r & 0xf8000000) >> 9) | ((r & 0x1f800000) >> 11) |
        ((r & 0x01f80000) >> 13) | ((r & 0x001f8000) >> 15);

    t ^= ks[round];

    /* Исправленный расчет s_row и s_col */
    DES_LONG s_out = 0;
    for (int i = 0; i < 8; i++) {
        int shift1 = 26 - 6 * i;
        int shift2 = 27 - 6 * i;
        int shift3 = 28 - 6 * i;

        if (shift1 >= 0 && shift1 < 32) {
            int s_row = ((t >> shift1) & 0x20) | ((t >> shift2) & 0x01);
            int s_col = (t >> shift3) & 0x0f;
            s_out <<= 4;
            s_out |= (S[i][(s_row << 4) | s_col] & 0x0f);
        }
    }

    /* Permutation P */
    DES_LONG p_out = 0;
    for (int i = 0; i < 32; i++) {
        if (s_out & (1 << (31 - P[i]))) {
            p_out |= (1 << (31 - i));
        }
    }

    data[0] = r;
    data[1] = l ^ p_out;
}

void DES_permute(DES_LONG *data, const int *table, int len) {
    DES_LONG result[2] = {0};

    for (int i = 0; i < len; i++) {
        int bit_pos = table[i] - 1;
        int word = bit_pos / 32;
        int bit = bit_pos % 32;

        if (data[word] & (1 << (31 - bit))) {
            int res_word = i / 32;
            int res_bit = i % 32;
            result[res_word] |= (1 << (31 - res_bit));
        }
    }

    data[0] = result[0];
    data[1] = result[1];
}

void DES_crypt(DES_LONG *data, const DES_LONG *ks, int encrypt) {
    DES_permute(data, IP, 64);

    for (int i = 0; i < 16; i++) {
        DES_round(data, ks, encrypt ? i : 15 - i);
    }

    DES_LONG t = data[0];
    data[0] = data[1];
    data[1] = t;

    DES_permute(data, FP, 64);
}

void DES_ecb_encrypt(const DES_cblock input, DES_cblock output, const DES_cblock key) {
    DES_LONG schedule[16];
    DES_LONG data[2];

    /* Convert input to 64-bit block - исправленное приведение типов */
    data[0] = ((DES_LONG)input[0] << 24) | ((DES_LONG)input[1] << 16) | ((DES_LONG)input[2] << 8) |
              (DES_LONG)input[3];
    data[1] = ((DES_LONG)input[4] << 24) | ((DES_LONG)input[5] << 16) | ((DES_LONG)input[6] << 8) |
              (DES_LONG)input[7];

    /* Generate key schedule */
    DES_set_key(key, schedule);

    /* Encrypt block */
    DES_crypt(data, schedule, 1);

    /* Convert back to bytes - исправленное присваивание */
    output[0] = (unsigned char)((data[0] >> 24) & 0xff);
    output[1] = (unsigned char)((data[0] >> 16) & 0xff);
    output[2] = (unsigned char)((data[0] >> 8) & 0xff);
    output[3] = (unsigned char)(data[0] & 0xff);
    output[4] = (unsigned char)((data[1] >> 24) & 0xff);
    output[5] = (unsigned char)((data[1] >> 16) & 0xff);
    output[6] = (unsigned char)((data[1] >> 8) & 0xff);
    output[7] = (unsigned char)(data[1] & 0xff);
}

void print_file_content(const char *filepath) {
    logcat(INFO, "Attempting to open file for reading");
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        logcat(ERROR, "Failed to open file");
        printf("n/a\n");
        return;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    if (size == 0) {
        logcat(WARNING, "File is empty");
        printf("n/a\n");
        fclose(file);
        return;
    }
    fseek(file, 0, SEEK_SET);

    char *content = malloc(size + 1);
    if (content == NULL) {
        logcat(ERROR, "Memory allocation failed");
        printf("n/a\n");
        fclose(file);
        return;
    }

    size_t read_size = fread(content, 1, size, file);
    if (read_size != size) {
        logcat(ERROR, "File read error");
        printf("n/a\n");
        free(content);
        fclose(file);
        return;
    }

    content[size] = '\0';
    printf("%s\n", content);
    logcat(INFO, "File content printed successfully");

    free(content);
    fclose(file);
}

void append_to_file(const char *filepath, const char *text) {
    logcat(INFO, "Attempting to append to file");
    FILE *test = fopen(filepath, "r");
    if (test == NULL) {
        logcat(ERROR, "File doesn't exist");
        printf("n/a\n");
        return;
    }
    fclose(test);

    FILE *file = fopen(filepath, "a");
    if (file == NULL) {
        logcat(ERROR, "Failed to open file for appending");
        printf("n/a\n");
        return;
    }

    fprintf(file, "%s", text);
    fclose(file);
    logcat(INFO, "Text appended to file successfully");

    print_file_content(filepath);
}

void caesar_cipher(const char *input, char *output, int shift) {
    for (int i = 0; input[i] != '\0'; i++) {
        if (isalpha(input[i])) {
            char base = islower(input[i]) ? 'a' : 'A';
            output[i] = (input[i] - base + shift) % 26 + base;
        } else {
            output[i] = input[i];
        }
    }
    output[strlen(input)] = '\0';
}

void process_directory_with_caesar(const char *dirpath, int shift) {
    DIR *dir = opendir(dirpath);
    if (dir == NULL) {
        logcat(ERROR, "Failed to open directory");
        printf("n/a\n");
        return;
    }

    const struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);

            FILE *file = fopen(filepath, "r");
            if (file == NULL) {
                logcat(ERROR, "Failed to open file for reading");
                continue;
            }

            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            fseek(file, 0, SEEK_SET);

            char *content = malloc(size + 1);
            if (content == NULL) {
                logcat(ERROR, "Memory allocation failed");
                fclose(file);
                continue;
            }

            fread(content, 1, size, file);
            content[size] = '\0';
            fclose(file);

            char *encrypted_content = malloc(size + 1);
            if (encrypted_content == NULL) {
                logcat(ERROR, "Memory allocation failed");
                free(content);
                continue;
            }

            caesar_cipher(content, encrypted_content, shift);

            file = fopen(filepath, "w");
            if (file == NULL) {
                logcat(ERROR, "Failed to open file for writing");
                free(content);
                free(encrypted_content);
                continue;
            }

            fwrite(encrypted_content, 1, size, file);
            fclose(file);

            free(content);
            free(encrypted_content);
        }
    }

    closedir(dir);
}

void process_directory_with_des(const char *dirpath, const DES_cblock key) {
    DIR *dir = opendir(dirpath);
    if (dir == NULL) {
        logcat(ERROR, "Failed to open directory");
        printf("n/a\n");
        return;
    }

    const struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);

            FILE *file = fopen(filepath, "rb");
            if (file == NULL) {
                logcat(ERROR, "Failed to open file for reading");
                continue;
            }

            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            fseek(file, 0, SEEK_SET);

            unsigned char *content = malloc(size);
            if (content == NULL) {
                logcat(ERROR, "Memory allocation failed");
                fclose(file);
                continue;
            }

            fread(content, 1, size, file);
            fclose(file);

            unsigned char *encrypted_content = malloc(size);
            if (encrypted_content == NULL) {
                logcat(ERROR, "Memory allocation failed");
                free(content);
                continue;
            }

            for (long i = 0; i < size; i += 8) {
                DES_ecb_encrypt(content + i, encrypted_content + i, key);
            }

            file = fopen(filepath, "wb");
            if (file == NULL) {
                logcat(ERROR, "Failed to open file for writing");
                free(content);
                free(encrypted_content);
                continue;
            }

            fwrite(encrypted_content, 1, size, file);
            fclose(file);

            free(content);
            free(encrypted_content);
        }
    }

    closedir(dir);
}

int main() {
    log_init("program.log");
    logcat(INFO, "Program started");

    int choice;
    char input[BUFFER_SIZE];

    while (1) {
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }

        if (choice == -1) {
            logcat(INFO, "Program terminated by user");
            break;
        }

        switch (choice) {
            case 1: {
                if (scanf("%255s", current_file) != 1) {
                    logcat(ERROR, "Invalid file name input");
                    printf("n/a\n");
                    while (getchar() != '\n');
                    break;
                }
                char log_msg[300];
                snprintf(log_msg, sizeof(log_msg), "Opening file: %s", current_file);
                logcat(INFO, log_msg);
                print_file_content(current_file);
                break;
            }
            case 2: {
                if (strlen(current_file) == 0) {
                    logcat(WARNING, "No file selected for append");
                    printf("n/a\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n');
                if (fgets(input, sizeof(input), stdin) == NULL) {
                    logcat(ERROR, "Failed to read input string");
                    printf("n/a\n");
                    break;
                }
                input[strcspn(input, "\n")] = '\0';
                char log_msg[300];
                snprintf(log_msg, sizeof(log_msg), "Appending to file: %s", current_file);
                logcat(INFO, log_msg);
                append_to_file(current_file, input);
                break;
            }
            case 3: {
                char dirpath[256];
                if (scanf("%255s", dirpath) != 1) {
                    logcat(ERROR, "Invalid directory path input");
                    printf("n/a\n");
                    while (getchar() != '\n');
                    break;
                }
                if (scanf("%d", &shift) != 1) {
                    logcat(ERROR, "Invalid shift value input");
                    printf("n/a\n");
                    while (getchar() != '\n');
                    break;
                }
                char log_msg[300];
                snprintf(log_msg, sizeof(log_msg), "Processing directory: %s with shift: %d", dirpath, shift);
                logcat(INFO, log_msg);
                process_directory_with_caesar(dirpath, shift);
                printf("OK\n");
                break;
            }
            case 4: {
                char dirpath[256];
                DES_cblock key;
                if (scanf("%255s", dirpath) != 1) {
                    logcat(ERROR, "Invalid directory path input");
                    printf("n/a\n");
                    while (getchar() != '\n');
                    break;
                }
                for (int i = 0; i < 8; i++) {
                    if (scanf("%hhx", &key[i]) != 1) {
                        logcat(ERROR, "Invalid key input");
                        printf("n/a\n");
                        while (getchar() != '\n');
                        break;
                    }
                }
                char log_msg[300];
                snprintf(log_msg, sizeof(log_msg), "Processing directory with DES: %s", dirpath);
                logcat(INFO, log_msg);
                process_directory_with_des(dirpath, key);
                printf("OK\n");
                break;
            }
            default: {
                logcat(WARNING, "Invalid menu option selected");
                printf("n/a\n");
                while (getchar() != '\n');
                break;
            }
        }
    }

    log_close();
    return 0;
}
