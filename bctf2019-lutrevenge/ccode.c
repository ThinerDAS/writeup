#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum { false,
    true } bool;

int hexc_to_val(int x)
{
    if (x >= '0' && x <= '9')
        return x - '0';
    if (x >= 'a' && x <= 'f')
        return x - 'a' + 10;
    return x - 'A' + 10;
}
int val_to_hexc(unsigned int x)
{
    if (x < 10)
        return '0' + x;
    return 'a' + x - 10;
}

bool good_chr(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool check_good(char* buf)
{
    for (int i = 0; i < 20; i++) {
        if (!good_chr(buf[i])) {
            return false;
        }
    }
    return true;
}

void hex_to_str(unsigned char* dst, char* src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = (hexc_to_val(src[2 * i]) << 4) | hexc_to_val(src[2 * i + 1]);
    }
}
void str_to_hex(char* dst, unsigned char* src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[2 * i] = val_to_hexc((src[i] >> 4) & 0xf);
        dst[2 * i + 1] = val_to_hexc((src[i]) & 0xf);
    }
    dst[2 * n] = 0;
}

unsigned char lut[10][256][10];
void (*const enc)(unsigned char*) = (void*)0x400820;

void debug_hexdump(unsigned char* buf, int n, const char* hint)
{
    char s[n * 2 + 3];
    str_to_hex(s, buf, n);
    printf("%s", hint);
    puts(s);
}

void enc_guessing(unsigned char* dst, unsigned char* buf)
{
    memcpy(dst, lut[0][0], 10);
    for (int i = 0; i < 10; i++) {
        printf("i=%#x,buf[i]=%#x", i, buf[i]);
        debug_hexdump(lut[i][buf[i]], 10, "lut rxor");
        for (int k = 0; k < 10; k++) {
            dst[k] ^= lut[i][buf[i]][k];
        }
    }
}

void main_loop()
{
    char query[21];
    unsigned char target[32];
    unsigned char target_guesstrans[32];
    puts("[*] Assuming that the function only touch the 10 bytes");
    while (scanf("%20s", query) == 1) {
        if (!check_good(query)) {
            puts("[!] Input format error: expected [0-9a-fA-F]{20}");
            continue;
        }
        hex_to_str(target, query, 10);
        enc_guessing(target_guesstrans, target);
        str_to_hex(query, target_guesstrans, 10);
        printf("[+] Result_obsved: %s\n", query);
        enc(target);
        str_to_hex(query, target, 10);
        printf("[+] Result_actual: %s\n", query);
    }
}

int main()
{
    if (((long)main) <= 0x600000) {
        fprintf(stderr, "Cannot use the util: main address is %p\n", main);
        return -1;
    }
    int fd = open("lutr", 0);
    if (fd < 0) {
        fprintf(stderr, "Cannot find lutr file\n");
        return -2;
    }
    mmap((void*)0x400000, 0x156000, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 256; j++) {
            unsigned char target[10] = {};
            target[i] = j;
            enc(target);
            memcpy(lut[i][j], target, 10);
        }
    }
    FILE* f = fopen("dump.bin", "w");
    fwrite(lut, 1, sizeof(lut), f);
    fclose(f);
    main_loop(); //printf("Hello, C!");
    return 0;
}
