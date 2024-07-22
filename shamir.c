#define maxx(X, Y) (((X) > (Y)) ? (X) : (Y))
#include <stdio.h>
#include <stdlib.h>

typedef long long ll;

ll poww(ll a, ll n, ll m) {
    ll s = 1, delta = a;

    for (int i = 0; i < 64; i++) {
        if (((n >> i) & 1) == 1)
            s = (s * delta) % m;
        delta = (delta * delta) % m;
    }

    return s;
}

void sharing(ll m, ll n, ll k, ll* my_p, ll* keys) {
    ll p = maxx(m, n);
    p = p % 2 == 0 ? p - 1 : p;
    char flag = 1;

    while (flag) {
        flag = 0, p += 2;

        for (ll i = 3; i * i <= p; i += 2) {
            if (p % i == 0) {
                flag = 1;
                break;
            }
        }

    }

    ll* coef = (ll*)malloc((k - 1) * sizeof(ll));

    for (ll i = 0; i < k - 1; i++)
        coef[i] = rand() % p, coef[i] = coef[i] < 0 ? coef[i] + p : coef[i];

    ll sum, now;

    for (ll x = 1; x <= n; x++) {
        sum = m, now = 1;

        for (int i = 0; i < k - 1; i++)
            now *= x, sum += (coef[i] * now) % p, sum %= p, sum = sum < 0 ? sum + p : sum;

        keys[x - 1] = sum;
    }

    *my_p = p;

    printf("\nUnique number:    %lld\n\nKeys:\n", p);
    for (int i = 0; i < n; i++)
        printf("%d:    %lld\n", i + 1, keys[i]);
}

ll reconstruction(ll p, ll k, int* arr, ll* keys) { // arr - номера желающих восстановить секрет
    int indx, flag = k % 2 == 0 ? 1 : 0;
    ll m = 0, prod, denom;

    for (int i = 0; i < k; i++) {
        indx = arr[i], prod = 1, denom = 1;

        for (int w = 0; w < k; w++) {
            if (w == i)
                continue;

            prod *= arr[w], prod %= p;
            denom *= indx - arr[w], denom %= p;
        }

        if (flag) prod = p - prod;
        if (denom < 0) denom += p;

        prod *= poww(denom, p - 2, p), prod %= p;

        m += prod * keys[i], m %= p;

        //printf("%lld ", prod);
    }

    return m;
}