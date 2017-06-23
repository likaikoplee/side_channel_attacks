#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmp.h>
#include <math.h>
#include <openssl/sha.h>

#define BUFFER_SIZE ( 80 )
#define N_length 1024
#define Byte_length 8
#define hLen 20
#define HEX_TRANS 256
#define ARR_LEN 1000
#define C_LEN 4

pid_t pid = 0;    // process ID (of either parent or child) from fork
int target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker
FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream
mpz_t N, e, d, c;

/*Read N, e, c*/
int Readfile(char *file){
	FILE *fp;
	mpz_init(N);
	mpz_init(e);
	mpz_init(c); 
	fp = fopen(file, "r");
	if(fp == NULL){
		perror("Error opening file!\n");
		exit(1);
	}else{
		gmp_fscanf(fp, "%Z0X\n%Z0X\n%Z0X\n", N, e, c);
	}
	fclose(fp);
	gmp_printf("N is :\n%Z0X\ne is :\n%Z0X\nc is :\n%Z0X\n", N, e, c);
	return EXIT_SUCCESS;
}

void interact(int* err, mpz_t f) {
	// Send f to attack target.
	gmp_fprintf(target_in, "%0256ZX\n", f);  fflush(target_in);
	// Receive (err) from attack target.
	fscanf( target_out, "%d", err );
}

int I2OSP(unsigned char EM[ARR_LEN], mpz_t m, int xLen){
	int i;	
	mpz_t tmp;
	mpz_init(tmp);
	mpz_ui_pow_ui(tmp, HEX_TRANS, xLen);
	if(mpz_cmp(m, tmp) >= 0){
		printf("Interger too large!\n");
		exit(1);
	}
	for(i=xLen-1; i>=0; i--){
		EM[i] = mpz_fdiv_q_ui(m, m, HEX_TRANS);	
	}

	mpz_clear(tmp);
	return EXIT_SUCCESS;
}

int MGF1(unsigned char seedMask[hLen], unsigned char *maskedDB,int maskedDBLen, int maskLen){	
	int con;
	int j = 0, k = 0;
	unsigned char C[C_LEN];
	unsigned char hash_tmp[maskedDBLen + C_LEN];
	unsigned char* hashed;
	unsigned char T[ARR_LEN];	
	mpz_t tmp, maskLen_tmp, hLen_tmp, counter_tmp, mpz_counter;

	mpz_init(tmp);
	mpz_init(maskLen_tmp);
	mpz_init(hLen_tmp);
	mpz_init(counter_tmp);
	mpz_init(mpz_counter);

	mpz_ui_pow_ui(tmp, 2, 32);
	mpz_mul_ui(tmp, tmp, hLen);
	mpz_set_ui(maskLen_tmp, maskLen);
	mpz_set_ui(hLen_tmp, hLen);

	if(mpz_cmp(maskLen_tmp, tmp) > 0){
		printf("Mask too long!\n");
	}
	for(int i=0;i<ARR_LEN;i++){
		T[i]=0;
	}
	mpz_cdiv_q(counter_tmp, maskLen_tmp, hLen_tmp);
	mpz_sub_ui(counter_tmp, counter_tmp, 1);
	con = mpz_get_ui(counter_tmp);

	for(int counter = 0; counter<= con; counter++){
		mpz_set_ui(mpz_counter, counter);
		I2OSP(C, mpz_counter, C_LEN);		

		for(int i=0; i<maskedDBLen; i++){
			hash_tmp[i] = maskedDB[i]; 		
		}
		
		for(int i=maskedDBLen; i<maskedDBLen+C_LEN; i++){
			hash_tmp[i] = C[i-maskedDBLen];		
		}

		hashed = SHA1(hash_tmp, maskedDBLen+C_LEN, NULL);

		for(k=j+0; k<20+j; k++){
			T[k] = *(hashed+k-j);
		}
		j+=20;	

	}
	
	for(int i=0; i<maskLen; i++){
		seedMask[i] = T[i];
	}
	
	mpz_clear(tmp);
	mpz_clear(maskLen_tmp);
	mpz_clear(hLen_tmp);
	mpz_clear(counter_tmp);
	mpz_clear(mpz_counter);

	return EXIT_SUCCESS;
}

int XOR(unsigned char *result, unsigned char* tar_1, unsigned char* tar_2, int len){	
	for(int i=0; i<len;i++){
		result[i] = tar_1[i] ^ tar_2[i];
	}
	
	return EXIT_SUCCESS;
}

int get_plaintext(unsigned char *m, unsigned char *DB, int DB_len){
	int i, j, k;	
	
	for(i=hLen+1; i<DB_len; i++){
		if(DB[i] == 1)
			break;
	}
	for(k=i+1; k<=DB_len-1; k++){
		m[k-i-1] = DB[k];
	}

	return DB_len - i -1;
}

void CCA_attack() {
	int err, k;
	mpz_t x, B, f_1, f_1_tmp, f_2, f_2_tmp, f_1_h, m_min, m_max, f_tmp, m_tmp, i, f_3, f_3_tmp, nplusB;
	unsigned char EM[ARR_LEN];
	mpz_init(d);
	mpz_init(x);     	//chosen ciphertext
	mpz_init(B);
	mpz_init(f_1);
	mpz_init(f_1_tmp);
	mpz_init(f_2);
	mpz_init(f_2_tmp);
	mpz_init(f_1_h);
	mpz_init(m_min);
	mpz_init(m_max);
	mpz_init(f_tmp);
	mpz_init(m_tmp);
	mpz_init(i);
	mpz_init(f_3);
	mpz_init(f_3_tmp);
	mpz_init(nplusB);

	/*pre-compute k, B*/
	k = N_length / Byte_length;
	printf("k is :%d\n", k);
	
	mpz_ui_pow_ui(B, 2, 8*(k-1));
	gmp_printf("B is :\n%ZX\n", B);
	/*pre-compute k, B*/

	/*step 1*/
	mpz_set_ui(f_1, 2);                 //1.1 0<= m < B


	mpz_powm(f_1_tmp, f_1, e, N);           //1.2
	mpz_mul(f_1_tmp, f_1_tmp, c);
	mpz_mod(f_1_tmp, f_1_tmp, N);

	interact(&err, f_1_tmp);
	
	while(err != 1){                    //1.3
		mpz_mul_ui(f_1, f_1, 2);

		mpz_powm(f_1_tmp, f_1, e, N);
		mpz_mul(f_1_tmp, f_1_tmp, c);
		mpz_mod(f_1_tmp, f_1_tmp, N);
		interact(&err, f_1_tmp);
	}
	
	/*step 1*/

	/*step 2*/
	mpz_divexact_ui(f_1_h, f_1, 2);
	mpz_add(f_2, N, B);
	mpz_fdiv_q(f_2, f_2, B);
	mpz_mul(f_2, f_2, f_1_h);                                     //get f2

	mpz_powm(f_2_tmp, f_2, e, N);  
	mpz_mul(f_2_tmp, f_2_tmp, c);
	mpz_mod(f_2_tmp, f_2_tmp, N);

	interact(&err, f_2_tmp);
	while(1){
		mpz_add(f_2, f_2, f_1_h);                          //reset f2
		mpz_powm(f_2_tmp, f_2, e, N);           	  
		mpz_mul(f_2_tmp, f_2_tmp, c);
		mpz_mod(f_2_tmp, f_2_tmp, N);
		interact(&err, f_2_tmp);
		if(err != 1){
			break;
		}

	}
	/*step 2*/

	/*step 3*/
		mpz_cdiv_q(m_min, N, f_2);
		mpz_add(m_max, N , B);
		mpz_fdiv_q(m_max, m_max, f_2);
		do{
			mpz_sub(m_tmp, m_max, m_min);
			mpz_mul_ui(f_tmp, B, 2);
			mpz_fdiv_q(f_tmp, f_tmp, m_tmp);
			mpz_mul(i, f_tmp, m_min);
			mpz_fdiv_q(i, i, N);
			mpz_mul(f_3, i, N);
			mpz_cdiv_q(f_3, f_3, m_min);
	
			mpz_powm(f_3_tmp, f_3, e, N);
			mpz_mul(f_3_tmp, f_3_tmp, c);
			mpz_mod(f_3_tmp, f_3_tmp, N);

			interact(&err, f_3_tmp);

			if(err == 1){
				mpz_mul(m_min, i, N);
				mpz_add(m_min, m_min, B);
				mpz_cdiv_q(m_min, m_min, f_3);
	
				mpz_powm(f_3_tmp, f_3, e, N);
				mpz_mul(f_3_tmp, f_3_tmp, c);
				mpz_mod(f_3_tmp, f_3_tmp, N);

				interact(&err, f_3_tmp);
				//printf("3.5a err is %d\n", err);
			}
	
			else if(err != 1){
				mpz_mul(m_max, i, N);
				mpz_add(m_max, m_max, B);
				mpz_fdiv_q(m_max, m_max, f_3);
	
				mpz_powm(f_3_tmp, f_3, e, N);
				mpz_mul(f_3_tmp, f_3_tmp, c);
				mpz_mod(f_3_tmp, f_3_tmp, N);

				interact(&err, f_3_tmp);
				//printf("3.5b err is %d\n", err);
			}
		}while(mpz_cmp(m_min, m_max) < 0);
	gmp_printf("m_min is :\n%Z0X\n", m_min);
	gmp_printf("m_max is :\n%Z0X\n", m_max);
	gmp_printf("m is :\n%Z0X\n", m_min);
	/*step 3*/

	/*Compute EM*/
	printf("EM is :\n");
	I2OSP(EM, m_min, k);
	for(int i=0; i<k; i++)
	{
		printf("%02X ", EM[i]);
	}
	printf("\n");
	/*Compute EM*/
	
	/*EME-OAEP decoding*/
	unsigned char Y = EM[0];
	if(Y != 0){
		printf("Decrypthin error! Y is not 0!\n");
		exit(1);	
	}
	printf("Y is : %02X \n", Y);

	printf("maskedSeed is :\n");
	unsigned char maskedSeed[hLen];
	for(int i=1; i<hLen+1; i++){
		maskedSeed[i-1] = EM[i];
		printf("%02X ", maskedSeed[i-1]);
	}
	printf("\n");

	printf("maskedDB is :\n");
	unsigned char maskedDB[k-hLen-1];
	for(int i=hLen+1; i<k; i++){
		maskedDB[i-21] = EM[i];
		printf("%02X ", maskedDB[i-21]);
	}
	printf("\n");

	unsigned char seedMask[hLen];
	MGF1(seedMask, maskedDB, k-hLen-1, hLen);
	printf("seedMask is :\n");
	for(int i=0; i<hLen; i++){
		printf("%02X ", seedMask[i]);

	}
	printf("\n");

	unsigned char seed[hLen];
	XOR(seed, maskedSeed, seedMask, hLen);
	printf("seed is :\n");
	for(int i=0; i<hLen; i++){
		printf("%02X ", seed[i]);

	}
	printf("\n");

	unsigned char dbMask[k-hLen-1];
	MGF1(dbMask, seed, hLen, k-hLen-1);
	printf("dbMask is :\n");
	for(int i=0; i<k-hLen-1; i++){
		printf("%02X ", dbMask[i]);

	}
	printf("\n");

	unsigned char DB[k-hLen-1];
	XOR(DB, maskedDB, dbMask, k-hLen-1);
	printf("DB is :\n");
	for(int i=0; i<k-hLen-1; i++){
		printf("%02X ", DB[i]);

	}
	printf("\n");
	
	unsigned char m[ARR_LEN];
	int m_len;
	m_len = get_plaintext(m, DB, k-hLen-1);
	printf("M is :\n");
	for(int i=0; i<=m_len-1; i++){
		printf("%02X ", m[i]);

	}
	printf("\n");
	/*EME-OAEP decoding*/
	
	mpz_clear(d);
	mpz_clear(x);     	//chosen ciphertext
	mpz_clear(B);
	mpz_clear(f_1);
	mpz_clear(f_1_tmp);
	mpz_clear(f_2);
	mpz_clear(f_2_tmp);
	mpz_clear(f_1_h);
	mpz_clear(m_min);
	mpz_clear(m_max);
	mpz_clear(f_tmp);
	mpz_clear(m_tmp);
	mpz_clear(i);
	mpz_clear(f_3);
	mpz_clear(f_3_tmp);
	mpz_clear(nplusB);
}
void cleanup( int s ){
	// Close the   buffered communication handles.
	fclose( target_in  );
	fclose( target_out );
	// Close the unbuffered communication handles.
	close( target_raw[ 0 ] ); 
	close( target_raw[ 1 ] ); 
	close( attack_raw[ 0 ] ); 
	close( attack_raw[ 1 ] ); 
	// Forcibly terminate the attack target process.
	if( pid > 0 ) {
		kill( pid, SIGKILL );
	}
	// Forcibly terminate the attacker      process.
	exit( 1 ); 
}
int main( int argc, char* argv[] ) {
	Readfile(argv[2]);
	// Ensure we clean-up correctly if Control-C (or similar) is signalled.
	signal( SIGINT, &cleanup );
	// Create pipes to/from attack target; if it fails the reason is stored
	// in errno, but we'll just abort.
	if( pipe( target_raw ) == -1 ) {
		abort();
	}
	if( pipe( attack_raw ) == -1 ) {
		abort();
	}
	switch( pid = fork() ) { 
		case -1 : {
			// The fork failed; reason is stored in errno, but we'll just abort.
			abort();
		}
		case +0 : {
			// (Re)connect standard input and output to pipes.
			close( STDOUT_FILENO );
			if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
				abort();
			}
			close(  STDIN_FILENO );
			if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
				abort();
			}
			// Produce a sub-process representing the attack target.
			execl( argv[ 1 ], NULL );
			// Break and clean-up once finished.
			break;
		}
		default : {
			// Construct handles to attack target standard input and output.
			if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) {
				abort();
			}
			if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) {
				abort();
			}
			// Execute a function representing the attacker.
			CCA_attack();
			// Break and clean-up once finished.
			break;
		}
	}
	// Clean up any resources we've hung on to.
	cleanup( SIGINT );
	return 0;
}
