/*ll m, n, k, p, ans;
	scanf("%lld %lld %lld", &m, &n, &k);

	ll* keys = (ll*)malloc(n * sizeof(ll));
	int* arr = (int*)malloc(k * sizeof(int));

	sharing(m, n, k, &p, keys);

	printf("ll keys[n] = {%lld", keys[0]);
	for (int i = 1; i < n; i++)
		printf(", %lld", keys[i]);
	printf("};");


	//for (ll i = 0; i < n; i++)
		//printf("%lld:    %lld\n", i + 1, keys[i]);


	printf("\n%lld\n\nThose who wish to restore the secret: ", p);

	//printf("%lld\n", poww(m, 13 - 2, 13));

	for (int i = 0; i < k; i++)
		scanf("%d", &arr[i]);

	ans = reconstruction(p, k, arr, keys);

	printf("%lld\n", ans);

	free(keys);
	free(arr);*/


	/*uint8_t key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xfe
	};*/

	//uint8_t key[16] = {
	//    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	//};

	/*uint8_t plaintext[16] = {
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};*/

	//uint8_t plaintext[16] = {
	//    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	//};




	/*char st[10] = "I did it.";
	memcpy(plaintext, st, 10);

	for (int i = 10; i < 16; i++)
		plaintext[i] = 0x00;*/



/*uint8_t plaintext[16];

    uint8_t key[16];

    FILE* file = fopen("C:/nsu/new.txt", "wb");
    //remove("C:/nsu/new.txt");

    state = (state_t*)plaintext;
    memcpy(Key, key, 16);

    KeyExpansion();
    Cipher();

    
    fclose(file);
    //printf("Encrypted state:\n");
    //print_state();

    AES_Decrypt();

    printf("\nDecrypted state as bytes:\n");
    print_state();
    printf("\nDecrypted state:\n");
    print_state_normal();
    printf("\n");*/