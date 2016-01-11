typedef struct sha1nfo {

	uint32_t buffer[BLOCK_LENGTH/4];
	uint32_t state[HASH_LENGTH/4];
	uint32_t byteCount;
	uint8_t bufferOffset;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;
void sha1_pad(sha1nfo *s) {
	// Implement SHA-1 padding (fips180-2 §5.1.1)

	// Pad with 0x80 followed by 0x00 until the end of the block
	sha1_addUncounted(s, 0x80);
	while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

	// Append length in the last 8 bytes
	sha1_addUncounted(s, 0); // We're only using 32 bit lengths
	sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
	sha1_addUncounted(s, 0); // So zero pad the top bits
	sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
	sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
	sha1_addUncounted(s, s->byteCount >> 13); // byte.
	sha1_addUncounted(s, s->byteCount >> 5);
	sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t* sha1_result(sha1nfo *s)
{
	// Pad to complete the last block
	sha1_pad(s);

#ifndef SHA_BIG_ENDIAN
	// Swap byte order back
	int i;
	for (i=0; i<5; i++) {
		s->state[i]=
			  (((s->state[i])<<24)& 0xff000000)
			| (((s->state[i])<<8) & 0x00ff0000)
			| (((s->state[i])>>8) & 0x0000ff00)
			| (((s->state[i])>>24)& 0x000000ff);
	}
#endif

	// Return pointer to hash (20 characters)
	return (uint8_t*) s->state;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
	return ((number << bits) | (number >> (32-bits)));
}
void sha1_hashBlock(sha1nfo *s)
{
	uint8_t i;
	uint32_t a,b,c,d,e,t;

	a=s->state[0];
	b=s->state[1];
	c=s->state[2];
	d=s->state[3];
	e=s->state[4];
	for (i=0; i<80; i++) {
		if (i>=16) {
			t = s->buffer[(i+13)&15] ^ s->buffer[(i+8)&15] ^ s->buffer[(i+2)&15] ^ s->buffer[i&15];
			s->buffer[i&15] = sha1_rol32(t,1);
		}
		if (i<20) {
			t = (d ^ (b & (c ^ d))) + SHA1_K0;
		} else if (i<40) {
			t = (b ^ c ^ d) + SHA1_K20;
		} else if (i<60) {
			t = ((b & c) | (d & (b | c))) + SHA1_K40;
		} else {
			t = (b ^ c ^ d) + SHA1_K60;
		}
		t+=sha1_rol32(a,5) + e + s->buffer[i&15];
		e=d;
		d=c;
		c=sha1_rol32(b,30);
		b=a;
		a=t;
	}
	s->state[0] += a;
	s->state[1] += b;
	s->state[2] += c;
	s->state[3] += d;
	s->state[4] += e;
}
/*
 * 
 */
void sha1_addUncounted(sha1nfo *s, uint8_t data)
{
	uint8_t * const b = (uint8_t*) s->buffer;
	//Endian 변환과정
#ifdef SHA_BIG_ENDIAN
	b[s->bufferOffset] = data;
#else
	b[s->bufferOffset ^ 3] = data;
#endif
	s->bufferOffset++;
	if (s->bufferOffset == BLOCK_LENGTH)
	{
		sha1_hashBlock(s);
		s->bufferOffset = 0;
	}
}
/*
 * sha1_write 함수에서 매번 호출되는 함수. 근데 for문 쓸거면 차라리 sha1_write 에서 bytecount 포인터 증가시키지 그랬니?;;;
 */
void sha1_writebyte(sha1nfo *s, uint8_t data)
{
	++s->byteCount;//이런 식으로 짜지 마 ㅜㅜ bytecount를 s sha1nfo 구조체 포인터에서 참조한 후 이 값을 1 증가시킴
	sha1_addUncounted(s, data);
}
/*
 * 아직 for문 종료조건은 모르는 상태
 */
void sha1_write(sha1nfo *s, const uint8_t *data, size_t len)
{
	for (;len--;)
		sha1_writebyte(s, (uint8_t) *data++);
}
/*
 * sha1nfo 구조체의 state배열의 처음 5개의 값을 정해진 대로 초기화하고, byteCount, bufferOffset을 각각 0으로 초기화하는 함수
 */
void sha1_init(sha1nfo *s)
{
	s->state[0] = 0x67452301;
	s->state[1] = 0xefcdab89;
	s->state[2] = 0x98badcfe;
	s->state[3] = 0x10325476;
	s->state[4] = 0xc3d2e1f0;
	s->byteCount = 0;
	s->bufferOffset = 0;
}
/*
 * sha1_init, sha1_write, sha1_result를 호출하는 함수
 */
uint8_t* JV_SHA1(uint8_t* out, const uint8_t* input, const size_t inputlen)
{
	sha1nfo s;
    uint8_t* hash;

	sha1_init(&s);
	sha1_write(&s, input, inputlen);
	hash = sha1_result(&s);
	memcpy(out, hash, 20); // SHA1는 160비트, 20바이트이다.

	return out;
}
uint8_t* JV_PBKDF1(uint8_t* dkey, const uint8_t password[], const size_t pwlen, const uint8_t salt[], const size_t saltlen, const uint32_t itercount)
{
	uint8_t mid_odd[20] = {0}, mid_even[20] = {0};
	// 100 is temporary bytes
	uint8_t kickoff[84] = {0};
	int i = 1;

// First, cat [password] and [salt] into [immediate]
	memcpy(kickoff, password, pwlen);
	memcpy(kickoff + pwlen, salt, saltlen);
    JV_SHA1(mid_even, kickoff, pwlen+saltlen);

    for (i = 1; i < itercount; i++) // 0는 password+salt 한번 돌린 것이다
    {
		if (i % 2) 	// 홀수번째
		{
			JV_SHA1(mid_odd, mid_even, 20);
		}
		else 		// 짝수번째
		{
			JV_SHA1(mid_even, mid_odd, 20);
		}
	}

	if (i % 2) 	// 여기선 홀수번째
	{
		memcpy(dkey, mid_even, 20);
	}
	else 		// 여기선 짝수번째
	{
		memcpy(dkey, mid_odd, 20);
	}

	return dkey;
}

void DumpBinary(const uint8_t buf[], const uint32_t bufsize)
{
	uint32_t base = 0;
	uint32_t interval = 16;
	while (base < bufsize)
	{
		if (base + 16 < bufsize)
			interval = 16;
		else
			interval = bufsize - base;

		printf("0x%04x:   ", base);
		for (uint32_t i = base; i < base + 16; i++) // i for dump
		{
			if (i < base + interval)
				printf("%02x", buf[i]);
			else
			{
				putchar(' ');
				putchar(' ');
			}

			if ((i+1) % 2 == 0)
				putchar(' ');
			if ((i+1) % 8 == 0)
				putchar(' ');
		}
		putchar(' ');
		putchar(' ');
		for (uint32_t i = base; i < base + 16; i++) // i for dump
		{
			if (i < base + interval)
			{
				if (0x20 <= buf[i] && buf[i] <= 0x7E)
					printf("%c", buf[i]);
				else
					putchar('.');
			}
			else
			{
				putchar(' ');
				putchar(' ');
			}

			if ((i+1) % 8 == 0)
				putchar(' ');
		}
		putchar('\n');


		if (base + 16 < bufsize)
			base += 16;
		else
			base = bufsize;
	}

	return;
}
void JV_SEED_CBC128_Decrypt_NoBranch(const uint8_t *virt_in, uint8_t *out, const size_t length, const uint32_t *K)
{
	uint8_t mid[16];

	for (size_t i = 0; i < length; i += 16)
    {
		// SEED Decipher
		JV_SeedDecrypt((uint8_t*) virt_in + i + 16, mid, (uint32_t*) K);

		// CBC XOR
		for (uint32_t x = 0; x < 16 && x < length; x++)
			out[i + x] = mid[x] ^ virt_in[i + x];
    }
}
void NPKIDecrypt (NPKIPrivateKey *pkey, const char* password)
{
    uint8_t dkey[20] = {0}, div[20] = {0}, buf[20] = {0}, iv[16] = {0}, seedkey[20] = {0}; // dkey, div, buf is temporary
	uint32_t roundkey[32] = {0};
    JV_PBKDF1(dkey, (uint8_t*)password, strlen(password), pkey->salt, sizeof(pkey->salt), pkey->itercount);
    memcpy(seedkey, dkey, 16);
    memcpy(buf, dkey+16, 4);
    JV_SHA1(div, buf, 4);
    memcpy(iv, div, 16);

	JV_SeedRoundKey(roundkey, seedkey);

	uint8_t* virt_in = (uint8_t*) malloc(pkey->crypto_len + 16); // len of in + iv
	for (uint32_t x = 0; x < 16; x++)
		virt_in[x] = iv[x];
	for (uint32_t x = 0; x < pkey->crypto_len; x++)
	{
		virt_in[x + 16] = pkey->crypto[x];
	}
	JV_SEED_CBC128_Decrypt_NoBranch(virt_in, pkey->plain, pkey->crypto_len, roundkey);
    free(virt_in);
}
/*
 * NPKPrivateKey를 복사하는 함수. 단순히 memcpy로 처리하기에는 salt가 걸렸던 듯.
 */
void NPK_Duplicate (NPKIPrivateKey *dest, NPKIPrivateKey *src)
{
	dest->rawkey = src->rawkey;
	dest->rawkey_len = src->rawkey_len;
	for (int i = 0; i < 8; i++)
		dest->salt[i] = src->salt[i];
	dest->itercount = src->itercount;
    dest->crypto = src->crypto;
    dest->crypto_len = src->crypto_len;
    dest->plain = src->plain;
}

char* PasswordGenerate (NPKIBruteForce *bforce, char password[])
{
	uint32_t i = 0;
	uint64_t cursor_in_this_len = bforce->pw_cursor;
	uint32_t pw_now_len = 0;
	for (i = bforce->pw_min_len; i <= bforce->pw_max_len; i++)
	{
    if (max_cursor[i] <= cursor_in_this_len)
			cursor_in_this_len -= max_cursor[i];
		else
		{
			pw_now_len = i;
			break;
		}
	}

	for (i = 0; i < pw_now_len; i++)
		password[i] = bforce->pw_charset[(cursor_in_this_len % ipow(charset_len, i+1)) / ipow(charset_len, i)];
	password[i] = '\0';
	return password;
}

/*
 * PKCS5 padding을 체크하는 함수
 * 조건은 1. 0x3082로 시작해야 하며 2. 대칭구조여야 하고 3. 마지막 수가 0이어야 함
 */
int IsPKCS5PaddingOK(const uint8_t* buf, const uint32_t buflen)
{
	if (buf[0] != 0x30 || buf[1] != 0x82)
		return FALSE;//비밀번호 첫번째 char 변수가 0x30이 아니거나 2반째 char 변수가 0x02이 아니면 제대로 padding된게 이미 아님

	for (int i = 1; i < buf[buflen-1]; i++)
	{
		if (buf[buflen-1-i] != buf[buflen-1])//대칭구조가 아니면 제대로 padding된 것이 아님
			return FALSE;
	}

	if (buf[buflen-1] == 0)
		return FALSE;//마지막 수가 0이 아니면 제대로 padding된 것이 아님

	return TRUE;
}

void BruteForceIterate (NPKIPrivateKey *pkey, NPKIBruteForce *bforce)
{
	uint64_t base_cursor = bforce->pw_cursor;
	time_t prev_time = time(NULL) - bforce->print_interval;

	char** passwords = NULL;
	NPKIPrivateKey** ikeys = NULL;
	#pragma omp barrier
	{
		//패스워드 C-string를 가리키는 배열 생성
		passwords = (char**) malloc(omp_get_max_threads() * sizeof(char*));
		ikeys = (NPKIPrivateKey**) malloc(omp_get_max_threads() * sizeof(NPKIPrivateKey*));
		for (uint32_t i = 0; i < omp_get_max_threads(); i++)
		{
			passwords[i] = (char*) malloc(MAX_PASSWORD * sizeof(char));
			ikeys[i] = (NPKIPrivateKey*) malloc(sizeof(NPKIPrivateKey));
			NPK_Duplicate(ikeys[i], pkey);
		}
	}
	#pragma omp parallel
	{
		while (bforce->pw_cursor < max_cursor[MAX_PASSWORD])
		{
			//각 쓰레드를 위한 값 할당
			char *password = passwords[omp_get_thread_num()];
			NPKIPrivateKey *ikey = ikeys[omp_get_thread_num()];
			PasswordGenerate(bforce, password);//case에 맞는 비밀번호를 생성하고
			NPKIDecrypt(ikey, password);//복호화를 시도한다
			if(IsPKCS5PaddingOK(pkey->plain, pkey->crypto_len))//만일 padding이 올바르면
			{
				#pragma omp critical
				{
					strncpy(bforce->password, password, MAX_PASSWORD);
					bforce->password[MAX_PASSWORD-1] = '\0';
					bforce->decrypt = TRUE;
					bforce->pw_cursor = max_cursor[MAX_PASSWORD];
				}//해독 정보를 복사해 옴
			}
			#pragma omp atomic
			bforce->pw_cursor++;//비밀번호 인덱스를 1 증가
		}
	}
	for (uint32_t i = 0; i < omp_get_max_threads(); i++)
	{
		free(passwords[i]);
		free(ikeys[i]);
	}
	free(passwords);
	free(ikeys);//함수 호출이 끝났으므로 모든 메로리 공간을 free
	passwords = NULL;
	ikeys = NULL;
}
