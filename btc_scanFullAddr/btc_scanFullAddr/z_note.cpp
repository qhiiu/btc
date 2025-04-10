
// ==================== core of process is here ====================================== 
// ==================== core of process is here ====================================== 
// ==================== core of process is here ====================================== 
// ==================== core of process is here ====================================== 
while (ok && !endOfSearch) { // if found right key --> run inside 
    ok = gpuEngine->LaunchSEARCH_MODE_SA(found);
    for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
        ITEM it = found[i];
                
                        /// test-here 
                        hiiu_Bitcoin bitcoin;

                        //hash160 --> addr 
                        std::string addr;
                        addr = bitcoin.hash160ToAddr(it.typeAddr, (uint32_t*)it.hash); 

            if (checkPrivKey(addr, keys[it.thId], it.incr, it.typeAddr)) {	nbFoundKey++;	}
    }

    if (ok) {
        for (int i = 0; i < nbThread; i++) {
            keys[i].Add((uint64_t)STEP_SIZE);
        }
        counters[thId] += (uint64_t)(STEP_SIZE)*nbThread; // Point 
    }
}
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

bool GPUEngine::SetKeys(Point* list_pubKey) //list_pubKey ở đây có dạng (x=, y= , z=1)
{
	uint64_t thread_id;
	for (int i = 0; i < (nbThread/nbThreadPerGroup); i++) { //nbThread = 6144 -- nbThreadPerGroup = 128 

		for (int j = 0; j < nbThreadPerGroup; j++) {
			
			thread_id = i*nbThreadPerGroup + j;
			
			inputKeyPinned[thread_id * 8 + 0] = list_pubKey[thread_id].x.bits64[0];
			inputKeyPinned[thread_id * 8 + 1] = list_pubKey[thread_id].x.bits64[1];
			inputKeyPinned[thread_id * 8 + 2] = list_pubKey[thread_id].x.bits64[2];
			inputKeyPinned[thread_id * 8 + 3] = list_pubKey[thread_id].x.bits64[3];

			inputKeyPinned[thread_id * 8 + 4] = list_pubKey[thread_id].y.bits64[0];
			inputKeyPinned[thread_id * 8 + 5] = list_pubKey[thread_id].y.bits64[1];
			inputKeyPinned[thread_id * 8 + 6] = list_pubKey[thread_id].y.bits64[2];
			inputKeyPinned[thread_id * 8 + 7] = list_pubKey[thread_id].y.bits64[3];
  		}
	}

	// Fill device memory
	CudaSafeCall(cudaMemcpy(inputKey, inputKeyPinned, nbThread * 32 * 2, cudaMemcpyHostToDevice));

	CudaSafeCall(cudaFreeHost(inputKeyPinned));
	inputKeyPinned = NULL;

	CudaSafeCall(cudaMemset(outputBuffer, 0, 4));

	//core of GPU is this code  <<<block, thread>>
	compute_keys_comp_mode_sa <<< nbThread / nbThreadPerGroup, nbThreadPerGroup >>>(input_arrData_P2PKH_GPU, input_arrData_P2SH_GPU, input_arrData_BECH32_GPU, inputKey, outputBuffer);
	return true;
}
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

bool GPUEngine::LaunchSEARCH_MODE_SA(std::vector<ITEM>& dataFound) 
{
	dataFound.clear(); 

	// Get the result
	cudaEvent_t evt;
	CudaSafeCall(cudaEventCreate(&evt));
	CudaSafeCall(cudaMemcpyAsync(outputBufferPinned, outputBuffer, 4, cudaMemcpyDeviceToHost, 0));
	CudaSafeCall(cudaEventRecord(evt, 0));

	//The function enters a loop where it checks if the event has completed. //If not, it sleeps for 1 millisecond to avoid busy-waiting.
	while (cudaEventQuery(evt) == cudaErrorNotReady) {  	
		Timer::SleepMillis(1);// Sleep 1 ms to free the CPU 
	}
	 
	CudaSafeCall(cudaEventDestroy(evt));

	// Look for data found 
	uint32_t nbFound = outputBufferPinned[0];

	// When can perform a standard copy, the kernel is eneded 
	CudaSafeCall(cudaMemcpy(outputBufferPinned, outputBuffer, nbFound * ITEM_SIZE_A + 4, cudaMemcpyDeviceToHost)); // ITEM_SIZE_A = 32

	for (uint32_t i = 0; i < nbFound; i++) //if found right key-hash-addr
	{ 
		uint32_t* itemPtr = outputBufferPinned + (i * ITEM_SIZE_A32 + 1); // 8 mean : each nbFound take 8 element = 8 bytes ? 
		ITEM it;
		it.thId = itemPtr[0];
		int16_t* ptr = (int16_t*)&(itemPtr[1]);
		it.incr = ptr[1];  
		it.hash = (uint8_t*)(itemPtr + 2);
		it.typeAddr = itemPtr[7];

		dataFound.push_back(it);
	}

	CudaSafeCall(cudaMemset(outputBuffer, 0, 4));

	//core of GPU is this code  <<<block, thread>>
	compute_keys_comp_mode_sa <<< nbThread / nbThreadPerGroup, nbThreadPerGroup >>>(input_arrData_P2PKH_GPU, input_arrData_P2SH_GPU, input_arrData_BECH32_GPU, inputKey, outputBuffer);

	return true;
}





























//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

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
		Timer::SleepMillis(500);
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


