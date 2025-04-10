#ifndef GPUENGINEH
#define GPUENGINEH

#include <vector>
#include "../SECP256k1.h"

// Number of key per thread (must be a multiple of GRP_SIZE) per kernel call
#define STEP_SIZE (2048 * 1) 

// #define ITEM_SIZE_A 28
#define ITEM_SIZE_A 32
#define ITEM_SIZE_A32 (ITEM_SIZE_A/4)

 
#define _P2PKH_C 1
#define _P2PKH_U 2
#define _P2SH 	3 
#define _BECH32 4

typedef struct {
	uint32_t thId;
	int16_t  incr;
	uint8_t* hash; 
	uint32_t typeAddr;
} ITEM;

class GPUEngine
{

public:

	GPUEngine(Secp256K1* secp, int nbThreadGroup, int nbThreadPerGroup, int gpuId, uint32_t maxFound,
		const uint32_t* arrData_P2PKH_GPU, const uint32_t* arrData_P2SH_GPU, const uint32_t* arrData_BECH32_GPU);

	~GPUEngine();

	bool SetKeys(Point* list_pubKey);

	bool LaunchSEARCH_MODE_SA(std::vector<ITEM>& dataFound);

	int GetNbThread();
	int GetGroupSize();

	std::string deviceName;

	static void PrintCudaInfo();

private:
	void InitGenratorTable(Secp256K1* secp);

	bool callKernelSEARCH_MODE_SA();

	int nbThread;
	int nbThreadPerGroup;

	uint32_t* input_arrData_P2PKH_GPU;
	uint32_t* input_arrData_P2SH_GPU;
	uint32_t* input_arrData_BECH32_GPU;

	uint32_t* input_arrData_P2PKH_GPU_pinned;
	uint32_t* input_arrData_P2SH_GPU_pinned;
	uint32_t* input_arrData_BECH32_GPU_pinned;

	uint64_t* inputKey;
	uint64_t* inputKeyPinned;

	uint32_t* outputBuffer;
	uint32_t* outputBufferPinned;

	uint64_t* __2Gnx;
	uint64_t* __2Gny;

	uint64_t* _Gx;
	uint64_t* _Gy;

	bool initialised;

	uint32_t outputSize;


	uint32_t n_P2PKH;
	uint32_t n_P2SH;
	uint32_t n_BECH32;

};

#endif // GPUENGINEH
