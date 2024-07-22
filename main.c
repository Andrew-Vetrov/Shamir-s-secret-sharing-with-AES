#define _CRT_SECURE_NO_WARNINGS
#define minn(X, Y) (((X) < (Y)) ? (X) : (Y))
#define maxx(X, Y) (((X) > (Y)) ? (X) : (Y))
#include "shamir.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>

/*static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


static const uint8_t Rcon[11] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C
};

#define Nb 4
#define Nk 4
#define Nr 10

typedef uint8_t state_t[4][4];
static state_t* state;

static uint8_t RoundKey[176];
static uint8_t Key[16];

void KeyExpansion() {
    unsigned i, j, k;
    uint8_t tempa[4];

    for (i = 0; i < Nk; ++i) {
        RoundKey[i * 4] = Key[i * 4];
        RoundKey[i * 4 + 1] = Key[i * 4 + 1];
        RoundKey[i * 4 + 2] = Key[i * 4 + 2];
        RoundKey[i * 4 + 3] = Key[i * 4 + 3];
    }

    for (; (i < (Nb * (Nr + 1))); ++i) {
        for (j = 0; j < 4; ++j) {
            tempa[j] = RoundKey[(i - 1) * 4 + j];
        }
        if (i % Nk == 0) {

            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            {
                tempa[0] = sbox[tempa[0]];
                tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]];
                tempa[3] = sbox[tempa[3]];
            }

            tempa[0] = tempa[0] ^ Rcon[i / Nk - 1];
        }
        for (j = 0; j < 4; ++j) {
            RoundKey[i * 4 + j] = RoundKey[(i - Nk) * 4 + j] ^ tempa[j];
        }
    }
}

void AddRoundKey(uint8_t round) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }
}

void SubBytes() {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = sbox[(*state)[j][i]];
        }
    }
}

void ShiftRows() {
    uint8_t temp;

    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1B);
}

void MixColumns() {
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i) {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1];
        Tm = xtime(Tm);
        (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2];
        Tm = xtime(Tm);
        (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3];
        Tm = xtime(Tm);
        (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t;
        Tm = xtime(Tm);
        (*state)[i][3] ^= Tm ^ Tmp;
    }
}

void Cipher() {
    uint8_t round = 0;

    AddRoundKey(0);

    for (round = 1; round < Nr; ++round) {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }

    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
}

uint8_t multiply(uint8_t x, uint8_t y) {
    return (((y & 1) * x) ^
        ((y >> 1 & 1) * xtime(x)) ^
        ((y >> 2 & 1) * xtime(xtime(x))) ^
        ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
        ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

void InvSubBytes() {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = rsbox[(*state)[j][i]];
        }
    }
}

void InvShiftRows() {
    uint8_t temp;

    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}


void InvMixColumns() {
    uint8_t i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i) {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        (*state)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        (*state)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        (*state)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

void AES_Decrypt() {
    uint8_t round = 0;

    AddRoundKey(Nr);

    for (round = Nr - 1; round > 0; --round) {
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(round);
        InvMixColumns();
    }

    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);
}

void print_state() {
    int i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            printf("%02x ", (*state)[j][i]);
        }
        printf("\n");
    }
}

void print_state_normal() {
    int i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j)
            printf("%c", (*state)[i][j]);
    }
}*/

typedef unsigned long long ul;
typedef long long ll;

int main() {
    int mode, flag_mode = 0;

    do {
        if (flag_mode)
            printf("\033[0;31mERROR: Incorrect data entered.\033[0m\n");
        printf("Select the mode:\n    1 - encryption\n    2 - decryption\n\n>> ");
        scanf("%d", &mode);
        flag_mode = 1;
    } while (mode != 1 && mode != 2);

    if (mode == 1) {
        ll m, n, k, p;
        flag_mode = 0;

        do {
            printf("\nSelect the encryption type:\n    1 - number encryption\n    2 - string encryption\n\n>> ");
            scanf("%d", &mode);
        } while (mode != 1 && mode != 2);

        if (mode == 1) {
            printf("\nEnter three numbers through a space:\n    the secret\n    the number of all participants\n    the number of participants needed to recover the secret\n\n>> ");
            scanf("%lld %lld %lld", &m, &n, &k);
            ll* keys = (ll*)malloc(n * sizeof(ll));

            sharing(m, n, k, &p, keys);

            free(keys);
        }

        else {
            printf("\nEnter two numbers through a space:\n    the number of all participants\n    the number of participants needed to recover the secret\n\n>> ");
            scanf("%lld %lld", &n, &k);
            int now_ptr = 0;
            char st[1005];
            FILE* output;

            flag_mode = 0;
            do {
                if (flag_mode)
                    printf("\033[0;31mERROR: Incorrect data entered.\033[0m\n");
                printf("\nEnter the path to the file and its name without specifying the extension (if the file does not exist, it will be created automatically)\n\n>> ");
            
                scanf("%s", st);

                int len = strlen(st);
                st[len] = '.', st[len + 1] = 'b', st[len + 2] = 'i', st[len + 3] = 'n', st[len + 4] = 0;

                output = fopen(st, "wb");
                flag_mode = 1;
            } while (output == NULL);

            printf("\nEnter the string you want to encrypt. Place a minus sign at the end of the line\n\n>> ");

            char* s = (char*)malloc(1000017 * sizeof(char));
            do {
                scanf("%s", s + now_ptr);
                now_ptr = strlen(s);
                scanf("%c", s + (now_ptr++));
            } while (s[now_ptr - 2] != '-');

            s[now_ptr - 2] = 0;

            int s_len = strlen(s) + 1, now = -16;

            if (s_len % 16 != 0) {
                for (int i = 0; i < 16 - s_len % 16; i++)
                    s[s_len + i] = 0;
            }

            uint8_t key[16];

            for (int i = 0; i < 2; i++) {
                m = rand();
                if (m < 0) m += LLONG_MAX;

                memcpy(key + i * 8, &m, 8);

                ll* keys = (ll*)malloc(n * sizeof(ll));

                sharing(m, n, k, &p, keys);

                free(keys);
            }

            KeyExpansion();

            /*printf("\n\------------------------\n");
            for (int i = 0; i < 16; i++)
                printf("%02x ", key[i]);*/
            
            uint8_t plaintext[16];

            int count_of_blocks = (int)ceil((double)s_len / 16);

            fwrite(&count_of_blocks, 4, 1, output);

            for (int i = 0; i < count_of_blocks; i++) {
                now += 16;
                memcpy(plaintext, s + now, 16);

                state = (state_t*)plaintext;
                memcpy(Key, key, 16);

                Cipher();

                fwrite(state, 1, 16, output);
            }

            fclose(output);
            free(s);
        }
    }

    else {
        ll p, k, ans;

        printf("\nSelect the decryption type:\n    1 - number decryption\n    2 - string decryption\n\n>> ");
        scanf("%d", &mode);

        printf("\nEnter a first unique number and the number of participants separated by a space\n\n>> ");
        scanf("%lld %lld", &p, &k);

        ll* keys = (ll*)malloc(k * sizeof(ll));
        int* arr = (int*)malloc(k * sizeof(int));

        printf("\nEnter the number of participants who want to recover the secret through a space\n\n>> ");
        for (int i = 0; i < k; i++)
            scanf("%d", &arr[i]);

        printf("\nEnter the participant keys through the space in the order corresponding to the participant numbers entered above\n\n>> ");
        for (int i = 0; i < k; i++)
            scanf("%lld", &keys[i]);

        ans = reconstruction(p, k, arr, keys);

        if (mode == 1)
            printf("\nThe secret has been successfully deciphered:    %lld\n", ans);

        else {
            uint8_t key[16];
            memcpy(key, &ans, 8);

            printf("\nEnter a second unique number\n\n>> ");
            scanf("%lld", &p);

            printf("\nEnter the number of participants who want to recover the secret through a space\n\n>> ");
            for (int i = 0; i < k; i++)
                scanf("%d", &arr[i]);

            printf("\nEnter the participant keys through the space in the order corresponding to the participant numbers entered above\n\n>> ");
            for (int i = 0; i < k; i++)
                scanf("%lld", &keys[i]);

            ans = reconstruction(p, k, arr, keys);
            memcpy(key + 8, &ans, 8);

            KeyExpansion();

            /*printf("\n\------------------------\n");
            for (int i = 0; i < 16; i++)
                printf("%02x ", key[i]);*/

            printf("\nEnter the path to the file and its name without specifying the extension\n\n>> ");

            char st[1005];
            scanf("%s", st);

            int len = strlen(st);
            st[len] = '.', st[len + 1] = 'b', st[len + 2] = 'i', st[len + 3] = 'n', st[len + 4] = 0;
            
            FILE* input = fopen(st, "rb");
            uint8_t plaintext[16];

            int count_of_blocks, now = -16;
            fread(&count_of_blocks, 4, 1, input);

            char* s = (char*)malloc(count_of_blocks * 16 * sizeof(char));
            fread(s, 1, count_of_blocks * 16, input);

            for (int i = 0; i < count_of_blocks; i++) {
                now += 16;
                memcpy(plaintext, s + now, 16);

                state = (state_t*)plaintext;
                memcpy(Key, key, 16);

                AES_Decrypt();

                print_state_normal();
            }

            fclose(input);
            free(s);
        }

        free(keys);
        free(arr);
    }

	return 0;
}