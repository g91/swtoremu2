// Patcher.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

static std::string newKey = "30820120300D06092A864886F70D01010105000382010D00308201080282010100B23B14D060C30DDB90532994FD63F3570D025541CD086A6FFF0D44E519A804E63C31281C717440AD7BAB8FE33E06F7BD10F53D8E0FA900B8B6A08FE4CBE4133D84BCE919916ECE588450DC7915D316EE6B36ECDF811E8F039B20B18E564E5166EDC7FC7E03C4CCD2CD311CAC1C173EB3F65FB8AA055AAEB5B1503EE890691FBA840EDB6258644A4B64E7B65A2DA36C8E6C2602F608F67A0320C06863B119EF189A60B3DD8921F69A011E3D518F030E5DD89622067C472166F129BC283E8DBEEE4B6B7D57E135186A87B51FCC17AEC74673796EF8A6D9E59852E9E61D8A6D0EEEBC6B93F5F87F7D3069B621503DA1277299C8220051B595B941207EFA93553A31020111";

bool LoadFile(std::string& pData)
{
	std::ifstream myfile("swtor.exe", std::ios::binary);
	if(myfile.is_open())
	{
		long begin,end;

		begin = myfile.tellg();
		myfile.seekg (0, std::ios::end);
		end = myfile.tellg();
		myfile.seekg (0, std::ios::beg);

		pData.resize(end - begin);

		myfile.read(&pData[0], end - begin);
		myfile.close();

		return true;
	}

	return false;
}

unsigned int Convert(std::string& pData)
{
	unsigned int x;
	std::stringstream ss;
	ss << std::hex << pData;
	ss >> x;
	return static_cast<int>(x) & 0xFF;
}

std::string CryptKey(std::string& pData)
{
	std::string key;
	for(auto i = 0; i < pData.size(); i+=2)
	{
		unsigned int c0 = Convert(pData.substr(i,2));
		key.push_back(c0 ^ 0xFF);
	}
	return key;
}

std::string DecryptKey(std::string& pData)
{
	std::ostringstream key;
	for(auto i = 0; i < pData.size(); ++i)
	{
		unsigned int c = ((*(unsigned char*)&pData[i]) & 0xFF) ^ 0xFF;
		key << c;
	}
	return key.str();
}

bool ReplaceKey115(std::string& pData)
{
	size_t size = pData.find("30820120300D0609");

	if(size != std::string::npos)
	{
		std::cout << "Game version : 1.1.5" << std::endl;
		std::cout << "Found the RSA key, replacing it..." << std::endl;
		for(auto i = 0; i < newKey.size(); ++i)
		{
			pData[size + i] = newKey[i];
		}

		std::cout << "Key replaced !" << std::endl;
		return true;
	}

	return false;
}

bool ReplaceKey120(std::string& pData)
{
	static std::string key = "30820120300D0609";
	std::string computedKeyToFind = CryptKey(key);

	size_t size = pData.find(computedKeyToFind);

	if(size != std::string::npos)
	{
		std::cout << "Game version : 1.2" << std::endl;
		std::cout << "Found pattern at " << std::hex << (unsigned int)size << std::endl;
		std::cout << "Found the RSA key, replacing it..." << std::endl;
		std::string computedKey = CryptKey(newKey);
		for(auto i = 0; i < computedKey.size(); ++i)
		{
			pData[size + i] = computedKey[i];
		}

		std::cout << "Key replaced !" << std::endl;
		return true;
	}

	return false;
}

bool ReplaceKey(std::string& pData)
{
	if(!ReplaceKey115(pData))
		return ReplaceKey120(pData);
	else
		return true;
}

#define ByteCompare(offset, data) *(unsigned char*)&pData[offset] == data

bool RevokeExclusivity(std::string& pData)
{
	for(auto i = 0; i < pData.size() - 11; ++i)
	{
		if( ByteCompare(i     , 0x00) && 
			ByteCompare(i + 1 , 0x6A) && 
			ByteCompare(i + 2 , 0x01) && 
			ByteCompare(i + 3 , 0x50) && 
			ByteCompare(i + 4 , 0xE8) && 
			ByteCompare(i + 7 , 0x01) && 
			ByteCompare(i + 9 , 0x33) && 
			ByteCompare(i + 10, 0xDB))
		{
			std::cout << "Found pattern at " << std::hex << i << std::endl;
			pData[i + 2] = 0x00;
			std::cout << "Exclusivity revoked !" << std::endl;
			return true;
		}
	}

	return false;
}

void WriteFile(const std::string& pData)
{
	std::ofstream file("swtor-emu.exe", std::ios::binary);
	file.write(pData.data(), pData.size());
	file.close();
}

int main()
{
	std::string data;
	if(LoadFile(data))
	{
		if(ReplaceKey(data))
		{
			if(RevokeExclusivity(data))
			{
				WriteFile(data);
				std::cout << "Here you go, I made swtor-emu.exe for you, it is nice and warm, you can pet it and it will start purring, we banana people want every kitteh in da world :o)" << std::endl << std::endl;
			}
			else
			{
				std::cout << "Da pattern was never found WTF !!!" << std::endl;
			}
		}
		else
		{
			std::cout << "Impossible to replace the key :(" << std::endl;
		}
	}
	else
	{
		std::cout << "Impossible to open swtor.exe" << std::endl;
	}

	system("PAUSE");

	return 0;
}