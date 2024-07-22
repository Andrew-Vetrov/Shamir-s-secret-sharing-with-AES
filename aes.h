#include <stdint.h>

const uint8_t sbox[256];

const uint8_t rsbox[256];

const uint8_t Rcon[11];

typedef uint8_t state_t[4][4];
state_t* state;

uint8_t RoundKey[176];
uint8_t Key[16];

void KeyExpansion();

void AddRoundKey(uint8_t round);

void SubBytes();

void ShiftRows();

uint8_t xtime(uint8_t x);

void MixColumns();

void Cipher();

uint8_t multiply(uint8_t x, uint8_t y);

void InvSubBytes();

void InvShiftRows();


void InvMixColumns();

void AES_Decrypt();

void print_state();

void print_state_normal();
