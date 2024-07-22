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
