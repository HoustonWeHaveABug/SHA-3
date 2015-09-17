unsigned char *keccak_sha3_224(const void *, unsigned long);
unsigned char *keccak_sha3_256(const void *, unsigned long);
unsigned char *keccak_sha3_384(const void *, unsigned long);
unsigned char *keccak_sha3_512(const void *, unsigned long);
unsigned char *keccak(const void *, unsigned long, unsigned long, unsigned long, unsigned long);
void keccak_print_hash(const unsigned char *, unsigned long, const char *, ...);
