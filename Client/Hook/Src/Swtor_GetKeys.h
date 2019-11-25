class swGetKeys {

public:
	bool GetProcessBaseAddress(DWORD dwPID, DWORD& dwBaseAddress);
	bool GetSWTORKeys(HANDLE hKeysFile, DWORD dwOffset);
	void init(char* cFile, byte* SalsaEnc, byte* SalsaEncSec, byte* SalsaDec, byte* SalsaDecSec);
	bool Getgamefiles(char* ServerFile);
	bool Getloginfiles(char* LoginFile);
};