#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <stdio.h> // for printf
#include <arpa/inet.h> // for ntohl

int main(int argc, char *argv[]){
	FILE *fp1 = fopen(argv[1], "rb");
	FILE *fp2 = fopen(argv[2], "rb");
	
	uint32_t val1, val2;
	fread(&val1, 1, sizeof(val1), fp1);
	fread(&val2, 1, sizeof(val2), fp2);
	fclose(fp1);
	fclose(fp2);
	uint32_t num1 = ntohl(val1);
	uint32_t num2 = ntohl(val2);
	uint32_t result = num1 + num2;
	
	printf("%u(0x%x) + %u(0x%x) = %u(0x%x)\n", num1, num1, num2, num2, result, result);
}
