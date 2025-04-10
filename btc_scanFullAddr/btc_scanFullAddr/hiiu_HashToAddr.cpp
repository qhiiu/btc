#include <cstdint>
#include <cstddef>
#include <cstring>


//============== BECH_32 - start ================================================================================
	static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	
//----------------------------------------------------------
	static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
	uint32_t val = 0;
	int bits = 0;
	uint32_t maxv = (((uint32_t)1) << outbits) - 1;
	while (inlen--) {
		val = (val << inbits) | *(in++);
		bits += inbits;
		while (bits >= outbits) {
		bits -= outbits;
		out[(*outlen)++] = (val >> bits) & maxv;
		}
	}
	if (pad) {
		if (bits) {
		out[(*outlen)++] = (val << (outbits - bits)) & maxv;
		}
	} else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
		return 0;
	}
	return 1;
	}

//----------------------------------------------------------
	uint32_t hiiu_bech32_polymod_step(uint32_t pre) {
	uint8_t b = pre >> 25;
	return ((pre & 0x1FFFFFF) << 5) ^
		(-((b >> 0) & 1) & 0x3b6a57b2UL) ^
		(-((b >> 1) & 1) & 0x26508e6dUL) ^
		(-((b >> 2) & 1) & 0x1ea119faUL) ^
		(-((b >> 3) & 1) & 0x3d4233ddUL) ^
		(-((b >> 4) & 1) & 0x2a1462b3UL);
	}

//----------------------------------------------------------
	int hiiu_bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len) {
	uint32_t chk = 1;
	size_t i = 0;
	while (hrp[i] != 0) {
		int ch = hrp[i];
		if (ch < 33 || ch > 126) {
		return 0;
		}

		if (ch >= 'A' && ch <= 'Z') return 0;
		chk = hiiu_bech32_polymod_step(chk) ^ (ch >> 5);
		++i;
	}
	if (i + 7 + data_len > 90) return 0;
	chk = hiiu_bech32_polymod_step(chk);
	while (*hrp != 0) {
		chk = hiiu_bech32_polymod_step(chk) ^ (*hrp & 0x1f);
		*(output++) = *(hrp++);
	}
	*(output++) = '1';
	for (i = 0; i < data_len; ++i) {
		if (*data >> 5) return 0;
		chk = hiiu_bech32_polymod_step(chk) ^ (*data);
		*(output++) = charset[*(data++)];
	}
	for (i = 0; i < 6; ++i) {
		chk = hiiu_bech32_polymod_step(chk);
	}
	chk ^= 1; 
	for (i = 0; i < 6; ++i) {
		*(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
	}
	*output = 0;
	return 1;
	}

//----------------------------------------------------------
int hiiu_segwit_addr_encode(char *output, const char *hrp, int witver, const uint8_t *witprog, size_t witprog_len) {
	uint8_t data[65];
	size_t datalen = 0;
	if (witver > 16) return 0;
	if (witver == 0 && witprog_len != 20 && witprog_len != 32) return 0;
	if (witprog_len < 2 || witprog_len > 40) return 0;
	data[0] = witver;
	convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, 1);
	++datalen;
	return hiiu_bech32_encode(output, hrp, data, datalen);
}

//============== BECH_32 - end ================================================================================


//============== HIIU::BITCOIN - start =============================================================================
// #include <iostream>

// class hiiu_Bitcoin 
// {
// 	public:
// 		std::string hash160ToAddr(int type, uint32_t* _hash160); //return STRING 
// };  
//-------------------------------------------------------------------- 

// std::string hiiu_Bitcoin::hash160ToAddr(int type, uint32_t* _hash160){
std::string hash160ToAddr(int type, uint32_t* _hash160){

	Secp256K1* secp = new Secp256K1();   
	secp->Init();	

	unsigned char address[25];

	switch (type) { 
		case P2PKH_C:
		case P2PKH_U:
			address[0] = 0x00;
			break;			
		case P2SH:
			address[0] = 0x05;
			break;	
		case BECH32: // codenow-here
			memcpy(address + 1, _hash160, 20);
			char addr_bech32[128];
			hiiu_segwit_addr_encode(addr_bech32, "bc", 0, address + 1, 20);
			return std::string(addr_bech32);
			break;
	}

	memcpy(address + 1, _hash160, 20);
	sha256_checksum(address, 21, address + 21);
	std::string addr = EncodeBase58(address, address + 25);

	delete secp;
	return addr;
}
//============== HIIU::BITCOIN - end =============================================================================
