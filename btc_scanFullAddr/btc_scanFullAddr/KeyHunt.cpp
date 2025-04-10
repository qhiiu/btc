#include "KeyHunt.h"
#include "GmpUtil.h"
#include "Base58.h"
#include "hash/sha256.h"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <pthread.h>
#include "hiiu_HashToAddr.cpp"

using namespace std;

Point Gn[CPU_GRP_SIZE / 2]; 
Point _2Gn;



// ----------------------------------------------------------------------------

KeyHunt::KeyHunt(uint32_t* arrData_P2PKH, uint32_t* arrData_P2SH, uint32_t* arrData_BECH32, const std::string& outputFile,
	const Int rangeStart, const Int rangeEnd, const Int priv_dec,uint64_t xN, bool& should_exit)
{
	this->priv_dec = priv_dec;
	this->xN = xN;
	// this->P = P;

	this->outputFile = outputFile;
	this->nbGPUThread = 0;
	this->rangeStart = rangeStart;
	this->rangeEnd = rangeEnd;
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);

	secp = new Secp256K1();
	secp->Init();

	this->arrData_P2PKH_KEYHUNT = arrData_P2PKH;
	this->arrData_P2SH_KEYHUNT = arrData_P2SH;
	this->arrData_BECH32_KEYHUNT = arrData_BECH32;


	printf("\n");

	InitGenratorTable();
}

// ----------------------------------------------------------------------------

void KeyHunt::InitGenratorTable()
{
	// Compute Generator table G[n] = (n+1)*G 
	Point G_point = secp->G;
	Gn[0] = G_point;
	G_point = secp->DoubleDirect(G_point);
	Gn[1] = G_point;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		G_point = secp->AddDirect(G_point, secp->G);
		Gn[i] = G_point;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("Start Time   : %s", ctimeBuff);
	printf("Global start : %s (%d bit)\n", this->rangeStart.GetBase16().c_str(), this->rangeStart.GetBitLength());
	printf("Global end   : %s (%d bit)\n", this->rangeEnd.GetBase16().c_str(), this->rangeEnd.GetBitLength());
	printf("Global range : %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());
}

// ----------------------------------------------------------------------------

#include <fstream>
KeyHunt::~KeyHunt()
{	
	printf("\n\n");
	// save data
	std::string fileSaveData_name;
	fileSaveData_name = "xData.txt";

	std::cout<<"\nFile save : " << fileSaveData_name;

	std::ofstream saveData(fileSaveData_name, std::ios::app); //create x67.txt to write_append

    Int priv_dec_copy = this->priv_dec;
    for (int i = 0; i < this->xN; i++) // loop to save each priv_dec 
    {
        saveData <<"\n"<< priv_dec_copy.GetBase10(); // write data into file
		std::cout << "\nsaved : "<< priv_dec_copy.GetBase10();
        priv_dec_copy.AddOne(); 
    }

    saveData.close();   // close file

	// print end_time 
	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	std::cout << std::endl << "END TIME : " << ctimeBuff << std::endl;
	std::cout <<"======================================================" << std::endl << std::endl;
	
	delete secp;
}

// ----------------------------------------------------------------------------

void KeyHunt::print_and_save_data(std::string addr, std::string privWif, std::string privHex, std::string pubKey, std::string typeAddr)
{
	FILE* f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("\n\nCannot open %s for writing\n\n\n", outputFile.c_str());
			f = stdout;
		}	else {	needToClose = true; }
	}

	if (!needToClose){ printf("\n"); }

	// save into file 
	fprintf(f, "\n=================================================================================\n\n");
	fprintf(f, "Address: -----> %s <----- ", addr.c_str());
	fprintf(f, "typeAddr : %s\n\n", typeAddr.c_str());
	fprintf(f, "Priv (HEX): %s\n", privHex.c_str());
	fprintf(f, "Priv (WIF): %s\n\n", privWif.c_str());
	// fprintf(f, "PubK (HEX): %s\n", pubKey.c_str());
	fprintf(f, "=================================================================================\n");

	//print info to screen
	fprintf(stdout, "\n=================================================================================\n\n");
	fprintf(stdout, "Address: -----> %s <----- ", addr.c_str());
	fprintf(stdout, "typeAddr : %s\n\n", typeAddr.c_str());
	fprintf(stdout, "Priv (HEX): %s\n", privHex.c_str());
	fprintf(stdout, "Priv (WIF): %s\n\n", privWif.c_str());
	// fprintf(stdout, "PubK (HEX): %s\n", pubKey.c_str()); 
	fprintf(stdout, "=================================================================================\n");

	if (needToClose){ fclose(f); }

	printf("\n.\n.\n.\n.\n.\n --- DONE !! check and take money !! ---- \n.\n.\n.\n.\n.\n.\n");
	// exit(-1);
}

// ----------------------------------------------------------------------------

bool KeyHunt::checkPrivKey(std::string addr, Int& key, int32_t incr, uint32_t typeAddr)
{
	Int priv(&key);
	priv.Add((uint64_t)incr);

	// Check addresses
	Point pubKey = secp->ComputePublicKey(&priv);

	std::string type_addr;
	switch (typeAddr)
	{
	case P2PKH_C:
		type_addr = "P2PKH_C";
		break;
	case P2PKH_U:
		type_addr = "P2PKH_U";
		break;
	case P2SH:
		type_addr = "P2SH";
		break;
	case BECH32:
		type_addr = "BECH32";
		break;
	}
	
	print_and_save_data(addr, secp->GetPrivAddress(1, priv), priv.GetBase16(), secp->GetPublicKeyHex(1, pubKey), type_addr);
	return true;
}

// ----------------------------------------------------------------------------

void* _FindKeyGPU(void* lpParam)
{
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------

void KeyHunt::getGPUStartingKeys(Int & tRangeStart, Int & tRangeEnd, int groupSize, int nbThread, Int * keys, Point * list_pubKey)
{
	Int tRangeDiff(tRangeEnd);
	Int tRangeStart2(tRangeStart);
	Int tRangeEnd2(tRangeStart);

	Int tThreads;
	tThreads.SetInt32(nbThread);
	tRangeDiff.Set(&tRangeEnd);
	tRangeDiff.Sub(&tRangeStart);
	tRangeDiff.Div(&tThreads);

	int rangeShowThreasold = 3;
	int rangeShowCounter = 0;

	for (int i = 0; i < nbThread; i++) {

		tRangeEnd2.Set(&tRangeStart2);
		tRangeEnd2.Add(&tRangeDiff);

		keys[i].Set(&tRangeStart2);

		tRangeStart2.Add(&tRangeDiff);

		Int priv(keys + i);
		priv.Add((uint64_t)(groupSize / 2));	// Starting key is at the middle of the group
		list_pubKey[i] = secp->ComputePublicKey(&priv);
	}

}

void KeyHunt::FindKeyGPU(TH_PARAM * ph)
{
	bool ok = true;

// #ifdef WITHGPU

	// Global init
	int thId = ph->threadId; 
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* gpuEngine;

	gpuEngine = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, this->maxFound,
						arrData_P2PKH_KEYHUNT, arrData_P2SH_KEYHUNT, arrData_BECH32_KEYHUNT); 
	
	// gpuEngine->PrintCudaInfo(); //hiiu

	int nbThread = gpuEngine->GetNbThread();
	printf("nbThread: %d\n", nbThread );
	printf("GPU	: %s\n\n", gpuEngine->deviceName.c_str());
	
		
	Point* list_pubKey = new Point[nbThread];
	Int* keys = new Int[nbThread];
	std::vector<ITEM> found;
	counters[thId] = 0;

	getGPUStartingKeys(tRangeStart, tRangeEnd, gpuEngine->GetGroupSize(), nbThread, keys, list_pubKey);
	ok = gpuEngine->SetKeys(list_pubKey);
 
	ph->hasStarted = true; 

	// ==================== core of process is here ====================================== 
	while (ok && !endOfSearch) { // if found right key --> run inside 
		ok = gpuEngine->LaunchSEARCH_MODE_SA(found);

		// check found : found or not
		for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
			ITEM it = found[i];
			
			//if found : take addr and priv by use checkPrivKey function.
			// hiiu_Bitcoin bitcoin;
			// std::string addr;
			// addr = bitcoin.hash160ToAddr(it.typeAddr, (uint32_t*)it.hash); 

			std::string addr;
			addr = hash160ToAddr(it.typeAddr, (uint32_t*)it.hash); 

			if (checkPrivKey(addr, keys[it.thId], it.incr, it.typeAddr)) {	nbFoundKey++;	}
		}

		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add((uint64_t)STEP_SIZE);
			}
			counters[thId] += (uint64_t)(STEP_SIZE)*nbThread; // Point 
		}
	}

	delete[] keys;
	delete[] list_pubKey;
	delete gpuEngine;

	ph->isRunning = false;

}

// ----------------------------------------------------------------------------

bool KeyHunt::isAlive(TH_PARAM * params)
{
	bool is_Alive = true;
	int total = nbGPUThread;
	for (int i = 0; i < total; i++)
		is_Alive = is_Alive && params[i].isRunning;

	return is_Alive;
}

// ----------------------------------------------------------------------------

bool KeyHunt::hasStarted(TH_PARAM * params)
{
	bool has_Started = true;
	int total = nbGPUThread;
	for (int i = 0; i < total; i++)
		has_Started = has_Started && params[i].hasStarted;

	return has_Started;
}

// ----------------------------------------------------------------------------

uint64_t KeyHunt::getGPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

void KeyHunt::SetupRanges(uint32_t totalThreads)
{
	Int threads;
	threads.SetInt32(totalThreads);
	rangeDiff.Set(&rangeEnd);
	rangeDiff.Sub(&rangeStart);
	rangeDiff.Div(&threads);
}

// ----------------------------------------------------------------------------
void KeyHunt::Search(std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
	double t0, t1;
	endOfSearch = false;
	nbGPUThread = (int)gpuId.size() ;
	
	nbFoundKey = 0;

	// setup ranges
	SetupRanges(nbGPUThread);

	memset(counters, 0, sizeof(counters));

	TH_PARAM* params = (TH_PARAM*)malloc((nbGPUThread) * sizeof(TH_PARAM));
	memset(params, 0, (nbGPUThread) * sizeof(TH_PARAM));

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = 0x80L + i;
		params[i].isRunning = true;
		params[i].gpuId = gpuId[i];
		params[i].gridSizeX = gridSize[2 * i];
		params[i].gridSizeY = gridSize[2 * i + 1];

		params[i].rangeStart.Set(&rangeStart);
		rangeStart.Add(&rangeDiff);
		params[i].rangeEnd.Set(&rangeStart);

		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)(params + (i)));
	}

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("\n");

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

	// Key rate smoothing filter
#define FILTER_SIZE 8
	double lastkeyRate[FILTER_SIZE];
	double lastGpukeyRate[FILTER_SIZE];
	uint32_t filterPos = 0;

	double keyRate = 0.0;
	double gpuKeyRate = 0.0;
	char timeStr[256];

	memset(lastkeyRate, 0, sizeof(lastkeyRate));
	memset(lastGpukeyRate, 0, sizeof(lastkeyRate));

	// Wait that all threads have started
	while (!hasStarted(params)) {
		Timer::SleepMillis(500); //pre_sleep 
	}

	// Reset timer
	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;
	Int p100;
	Int ICount; 
	p100.SetInt32(100);
	double completedPerc = 0;

	while (isAlive(params)) {

		// int delay = 1000;
		int delay = 2000;

		while (isAlive(params) && delay > 0) {
			Timer::SleepMillis(500);
			delay -= 500;
		}

		gpuCount = getGPUCount();
		uint64_t count = gpuCount;
		ICount.SetInt64(count);
		int completedBits = ICount.GetBitLength();
		completedPerc = CalcPercantage(ICount, rangeStart, rangeDiff2);

		t1 = Timer::get_tick();
		keyRate = (double)(count - lastCount) / (t1 - t0);
		gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		// KeyRate smoothing
		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample;
		for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
			avgKeyRate += lastkeyRate[nbSample];
			avgGpuKeyRate += lastGpukeyRate[nbSample];
		}
		avgKeyRate /= (double)(nbSample);
		avgGpuKeyRate /= (double)(nbSample);

		if (isAlive(params)) {
			memset(timeStr, '\0', 256);
			printf("\r[%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %lf %%] [T: %s (%d bit)]  ",
				toTimeStr(t1, timeStr),
				avgKeyRate / 1000000.0,
				avgGpuKeyRate / 1000000.0,
				completedPerc,
				formatThousands(count).c_str(),
				completedBits);
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		if (should_exit || nbFoundKey >= this->maxFound || completedPerc > 100.5)
			endOfSearch = true;
	}

	free(params);

	}

// ----------------------------------------------------------------------------

std::string KeyHunt::formatThousands(uint64_t x)
{
	char buf[32] = "";
	sprintf(buf, "%lu", x);

	std::string s(buf);
	int len = (int)s.length();
	int numCommas = (len - 1) / 3;
	if (numCommas == 0) {		return s;	}

	std::string result = "";
	int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));
	for (int i = 0; i < len; i++) {
		result += s[i];
		if (count++ == 2 && i < len - 1) {
			result += ",";
			count = 0;
		}
	}
	return result;
}

// ----------------------------------------------------------------------------

char* KeyHunt::toTimeStr(int sec, char* timeStr)
{
	int h, m, s;
	h = (sec / 3600);
	m = (sec - (3600 * h)) / 60;
	s = (sec - (3600 * h) - (m * 60));
	sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
	return (char*)timeStr;
}
