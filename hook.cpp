#include "hook.h"
#include "hookutils.h"
#include <stdio.h>
#include <ICommandLine.h>
#include <string>
#include <regex>
#include <sstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <sys/stat.h> // stat
#include <errno.h>    // errno, ENOENT, EEXIST
#if defined(_WIN32)
#include <direct.h>   // _mkdir
#endif

DWORD g_dwEngineBase;
DWORD g_dwEngineSize;

DWORD g_dwMpBase;
DWORD g_dwMpSize;

#define SOCKETMANAGER_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x51\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\x00\x8A\x45"
#define SOCKETMANAGER_MASK_CSNZ "xxxx?x????xx????xxxxxx????xxxxx?xx????xxxx?xx"

#define PACKET_HACK_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x8B\x45\x00\x89\x45"
#define PACKET_HACK_PARSE_MASK_CSNZ "xxxx?x????xx????xxx?xx????xxxxx?xx????xxxx?xx"

#define PACKET_HACK_SEND_SIG_CSNZ "\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00\x74\x00\xE8\x00\x00\x00\x00\xE8"
#define PACKET_HACK_SEND_MASK_CSNZ "x????x????x????x????xx????xx?x????x"

#define BOT_MANAGER_PTR_SIG_CSNZ "\xA3\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x83\xC4"
#define BOT_MANAGER_PTR_MASK_CSNZ "x????xx?????xx????xx"

#define LOGTOERRORLOG_SIG_CSNZ "\x53\x8B\xDC\x83\xEC\x00\x83\xE4\x00\x83\xC4\x00\x55\x8B\x6B\x00\x89\x6C\x24\x00\x8B\xEC\x83\xEC\x00\x56\x57\x8B\x7B\x00\x85\xFF"
#define LOGTOERRORLOG_MASK_CSNZ "xxxxx?xx?xx?xxx?xxx?xxxx?xxxx?xx"

#define GETSSLPROTOCOLNAME_SIG_CSNZ "\xE8\x00\x00\x00\x00\xB9\x00\x00\x00\x00\x8A\x10"
#define GETSSLPROTOCOLNAME_MASK_CSNZ "x????x????xx"

#define SOCKETCONSTRUCTOR_SIG_CSNZ "\xE8\x00\x00\x00\x00\xEB\x00\x33\xC0\xFF\x75\x00\xC7\x45"
#define SOCKETCONSTRUCTOR_MASK_CSNZ "x????x?xxxx?xx"

#define EVP_CIPHER_CTX_NEW_SIG_CSNZ "\xE8\x00\x00\x00\x00\x8B\xF8\x89\xBE"
#define EVP_CIPHER_CTX_NEW_MASK_CSNZ "x????xxxx"

#define PACKET_METADATA_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x89\xB5\x00\x00\x00\x00\x8B\x45\x00\x89\x85"
#define PACKET_METADATA_PARSE_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xxxx????xx?xx"

#define PACKET_ROOM_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89"
#define PACKET_ROOM_PARSE_MASK_CSNZ "xxxx?x????xx????xx????x????x????xxxx?xxxxx?xx????xxx"

#define VOXEL_LOADWORLD_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x57\x8B\x3D\x00\x00\x00\x00\x85\xFF\x0F\x84\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00"
#define VOXEL_LOADWORLD_MASK_CSNZ "xxxxx????x????xxxx?xxx????xxxx????xx????x"

#define VOXELADAPTER_PTR_SIG_CSNZ "\xE8\x00\x00\x00\x00\x8B\xF0\x8B\x47"
#define VOXELADAPTER_PTR_MASK_CSNZ "x????xxxx"

#define VOXELWORLD_PTR_SIG_CSNZ "\x8B\x3D\x00\x00\x00\x00\x85\xFF\x0F\x84\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00"
#define VOXELWORLD_PTR_MASK_CSNZ "xx????xxxx????xx????x"

#define DEDI_API_ADDTEXT_SIG_CSNZ "\xE9\x00\x00\x00\x00\x55\x8B\xEC\x81\xEC"
#define DEDI_API_ADDTEXT_MASK_CSNZ "x????xxxxx"

#define DEDI_API_UPDATESTATUS_SIG_CSNZ "\x55\x8B\xEC\x51\xF2\x0F\x10\x0D\x00\x00\x00\x00\x0F\x57\xC0"
#define DEDI_API_UPDATESTATUS_MASK_CSNZ "xxxxxxxx????xxx"

#define CGAME_INSTANCE_SIG_CSNZ "\x8B\x0D\x00\x00\x00\x00\x56\x8B\x01\xFF\x50\x00\x50\xE8\x00\x00\x00\x00\x8B\xF0"
#define CGAME_INSTANCE_MASK_CSNZ "xx????xxxxx?xx????xx"

#define DEDI_INIT_DWORD_1_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x8B\x45\x00\x56\x57\x89\x85"
#define DEDI_INIT_DWORD_1_MASK_CSNZ "xxxxx????x????xxxx?xx?xxxx"

#define DEDI_INIT_DWORD_3_SIG_CSNZ "\x56\x8B\xF1\x8B\xD6"
#define DEDI_INIT_DWORD_3_MASK_CSNZ "xxxxx"

#define DEDI_INIT_DWORD_5_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x8D\x45\x00\x50\x6A\x00\xFF\x75\x00\x8D\x85\x00\x00\x00\x00\x68\x00\x00\x00\x00\x50"
#define DEDI_INIT_DWORD_5_MASK_CSNZ "xxxxx????x????xxxx?xxxx?xx?xx?xx????x????x"

#define DEDI_INIT_DWORD_EXPORT_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x8D\x45\x00\x50\x6A\x00\xFF\x75\x00\x8D\x85\x00\x00\x00\x00\x68\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x8B\x08\xFF\x70\x00\x83\xC9\x00\x51\xFF\x15\x00\x00\x00\x00\x8B\x0D"
#define DEDI_INIT_DWORD_EXPORT_MASK_CSNZ "xxxxx????x????xxxx?xx?xx?xx?xx????x????xx????xxxx?xx?xxx????xx"

#define CSERVERSTATE_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\xC7\x05"
#define CSERVERSTATE_MASK_CSNZ "xxxxx????x????xxxx?xx"

#define DEDI_API_INIT_FUNC_1_SIG_CSNZ "\x55\x8B\xEC\x53\x56\x57\x6A\x00\xE8\x00\x00\x00\x00\x8B\x7D"
#define DEDI_API_INIT_FUNC_1_MASK_CSNZ "xxxxxxx?x????xx"

#define DEDI_API_INIT_FUNC_2_SIG_CSNZ "\x55\x8B\xEC\xA1\x00\x00\x00\x00\xBA"
#define DEDI_API_INIT_FUNC_2_MASK_CSNZ "xxxx????x"

#define DEDI_API_INIT_FUNC_3_SIG_CSNZ "\x55\x8B\xEC\x8B\x4D\x00\xBA\x00\x00\x00\x00\x2B\xD1"
#define DEDI_API_INIT_FUNC_3_MASK_CSNZ "xxxxx?x????xx"

#define DEDI_API_INIT_FUNC_5_SIG_CSNZ "\x55\x8B\xEC\x8D\x45\x00\x50\x6A\x00\xFF\x75\x00\x6A\x00\xFF\x75\x00\xE8\x00\x00\x00\x00\x8B\x08\xFF\x70\x00\x83\xC9\x00\x51\xFF\x15\x00\x00\x00\x00\x83\xC9"
#define DEDI_API_INIT_FUNC_5_MASK_CSNZ "xxxxx?xx?xx?x?xx?x????xxxx?xx?xxx????xx"

#define DEDI_API_INIT_FUNC_6_SIG_CSNZ "\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\x85\xC9\x74\x00\x8B\x01\x6A"
#define DEDI_API_INIT_FUNC_6_MASK_CSNZ "x????x????xx????xxx?xxx"

#define DEDI_API_INIT_FUNC_8_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\xFF\x75"
#define DEDI_API_INIT_FUNC_8_MASK_CSNZ "xxxx?x????xx????xx????xxxxx?xx????xx"

#define DEDI_API_INIT_FUNC_9_SIG_CSNZ "\x55\x8B\xEC\x51\xA1\x00\x00\x00\x00\x85\xC0\x74\x00\x80\x3D\x00\x00\x00\x00\x00"
#define DEDI_API_INIT_FUNC_9_MASK_CSNZ "xxxxx????xxx?xx????x"

#define DEDI_API_INIT_FUNC_10_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x51\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\xFF\x15"
#define DEDI_API_INIT_FUNC_10_MASK_CSNZ "xxxx?x????xx????xxx????xxxxx?xx????xx"

#define DEDI_API_SHUTDOWN_FUNC_1_SIG_CSNZ "\x55\x8B\xEC\x57\x8B\x7D\x00\x8B\x14\xBD"
#define DEDI_API_SHUTDOWN_FUNC_1_MASK_CSNZ "xxxxxx?xxx"

#define DEDI_API_SHUTDOWN_FUNC_2_SIG_CSNZ "\x8B\x0D\x00\x00\x00\x00\x8B\x01\xFF\x50\x00\xA1\x00\x00\x00\x00\x85\xC0"
#define DEDI_API_SHUTDOWN_FUNC_2_MASK_CSNZ "xx????xxxx?x????xx"

#define FPS_PATCH_SIG_CSNZ "\x77\x00\xF2\x0F\x10\x0D\x00\x00\x00\x00\x66\x0F\x2F\xC8\x76\x00\xF2\x0F\x11\x0D\x00\x00\x00\x00\xB8\x00\x00\x00\x00\x85\xC0"
#define FPS_PATCH_MASK_CSNZ "x?xxxx????xxxxx?xxxx????x????xx"

#define CMAPENTITYMANAGER_SIG_CSNZ "\x55\x8B\xEC\x51\xA1\x00\x00\x00\x00\x85\xC0\x75\x00\x6A\x00\xE8\x00\x00\x00\x00\x83\xC4\x00\x89\x45\x00\x85\xC0\x74\x00\x00\x00\x00\x00\x00\x00\x66\xC7\x40"
#define CMAPENTITYMANAGER_MASK_CSNZ "xxxxx????xxx?x?x????xx?xx?xxx???????xxx"

// ROOM LOW FLAGS
#define	ROOM_LOW_ROOMNAME				(1<<0)
#define	ROOM_LOW_UNK					(1<<1)
#define	ROOM_LOW_PASSWORD				(1<<3)
#define	ROOM_LOW_LEVELLIMIT				(1<<4)
#define	ROOM_LOW_UNK7					(1<<5)
#define	ROOM_LOW_GAMEMODEID				(1<<6)
#define	ROOM_LOW_MAPID					(1<<7)
#define	ROOM_LOW_MAXPLAYERS				(1<<8)
#define ROOM_LOW_WINLIMIT				(1<<9)
#define ROOM_LOW_KILLLIMIT				(1<<10)
#define	ROOM_LOW_GAMETIME				(1<<11)
#define ROOM_LOW_ROUNDTIME				(1<<12)
#define ROOM_LOW_WEAPONLIMIT			(1<<13)
#define ROOM_LOW_HOSTAGEKILLLIMIT		(1<<14)
#define ROOM_LOW_FREEZETIME				(1<<15)
#define	ROOM_LOW_BUYTIME				(1<<16)
#define ROOM_LOW_DISPLAYNICKNAME		(1<<17)
#define ROOM_LOW_TEAMBALANCE			(1<<18)
#define ROOM_LOW_UNK21					(1<<19)
#define ROOM_LOW_FRIENDLYFIRE			(1<<20)
#define ROOM_LOW_FLASHLIGHT				(1<<21)
#define ROOM_LOW_FOOTSTEPS				(1<<22)
#define ROOM_LOW_UNK25					(1<<23)
#define ROOM_LOW_TKPUNISH				(1<<24)
#define ROOM_LOW_AUTOKICK				(1<<25)
#define ROOM_LOW_UNK28					(1<<26)
#define ROOM_LOW_UNK29					(1<<27)
#define ROOM_LOW_VIEWFLAG				(1<<28)
#define ROOM_LOW_VOICECHAT				(1<<29)
#define ROOM_LOW_STATUS					(1<<30)

// ROOM LOW-MID FLAGS
#define	ROOM_LOWMID_C4TIMER				(1<<1)
#define	ROOM_LOWMID_BOT					(1<<2)
#define	ROOM_LOWMID_KDRULE				(1<<3)
#define	ROOM_LOWMID_STARTINGCASH		(1<<4)
#define	ROOM_LOWMID_MOVINGSHOT			(1<<5)
#define	ROOM_LOWMID_BALLNUMBER			(1<<6)
#define	ROOM_LOWMID_STATUSSYMBOL		(1<<7)
#define	ROOM_LOWMID_RANDOMMAP			(1<<8)
#define ROOM_LOWMID_MAPPLAYLIST			(1<<9)
#define ROOM_LOWMID_MAPPLAYLISTINDEX	(1<<10)
#define ROOM_LOWMID_ENHANCERESTRICT		(1<<11)
#define ROOM_LOWMID_SD					(1<<12)
#define ROOM_LOWMID_ZSDIFFICULTY		(1<<13)
#define ROOM_LOWMID_LEAGUERULE			(1<<14)
#define ROOM_LOWMID_MANNERLIMIT			(1<<15)
#define ROOM_LOWMID_MAPID2				(1<<16)
#define ROOM_LOWMID_ZBLIMIT				(1<<17)
#define ROOM_LOWMID_VOXEL				(1<<18)

// Studio mode flags
#define VOXELFLAG_ID				(1<<0)
#define VOXELFLAG_RESOURCEID		(1<<1)
#define VOXELFLAG_RESOURCEMAXPLAYER	(1<<2)
#define VOXELFLAG_TITLE				(1<<3)
#define VOXELFLAG_RESOURCEMODE		(1<<4)
#define VOXELFLAG_PERMISSION		(1<<5)
#define VOXELFLAG_DESCRIPTION		(1<<6)
#define VOXELFLAG_PARENTSSLOTID		(1<<7)
#define VOXELFLAG_IMAGEID			(1<<8)
#define VOXELFLAG_CREATORNICKNAME	(1<<9)
#define VOXELFLAG_CREATORUSERNAME	(1<<10)
#define VOXELFLAG_LIKECOUNT			(1<<11)
#define VOXELFLAG_PLAYCOUNT			(1<<12)
#define VOXELFLAG_BOOKMARKCOUNT		(1<<13)
#define VOXELFLAG_UNK15				(1<<14)
#define VOXELFLAG_CUBECOUNT			(1<<15)
#define VOXELFLAG_UNK17				(1<<16)
#define VOXELFLAG_UNK18				(1<<17)
#define VOXELFLAG_SLOTCATEGORY		(1<<19)
#define VOXELFLAG_SANDBOXSCRIPT		(1<<21)
#define VOXELFLAG_SAVEGROUPID		(1<<22)
#define VOXELFLAG_UNK22				(1<<23)
#define VOXELFLAG_UNK23				(1<<24)
#define VOXELFLAG_SERVERID			(1<<25)

float* g_pFreezeTime;

pfnDediAddTextFunc g_pfnDediAddTextFunc = 0;
pfnDediUpdateStatusFunc g_pfnDediUpdateStatusFunc = 0;

CEngine* g_pCEngine = 0;
CRegistry* g_pCRegistry = 0;
CGame* g_pCGame = 0;

int g_pIsDedicated = 0;
int g_pBaseSocket = 0;
char* g_pDediInitDword5 = 0;
void* g_pDediInitDwordExport = 0;
int g_pServerState = 0;

pfnDediInitFunc1 g_pfnDediInitFunc1 = 0;
pfnDediInitFunc2 g_pfnDediInitFunc2 = 0;
pfnDediInitFunc3 g_pfnDediInitFunc3 = 0;
pfnDediInitFunc5 g_pfnDediInitFunc5 = 0;
pfnDediInitFunc6 g_pfnDediInitFunc6 = 0;
pfnDediInitFunc7 g_pfnDediInitFunc7 = 0;
pfnDediInitFunc8 g_pfnDediInitFunc8 = 0;
pfnDediInitFunc9 g_pfnDediInitFunc9 = 0;
pfnDediInitFunc10 g_pfnDediInitFunc10 = 0;

pfnDediShutdownFunc1 g_pfnDediShutdownFunc1 = 0;
pfnDediShutdownFunc2 g_pfnDediShutdownFunc2 = 0;


char g_pVxlPath[MAX_PATH];
bool g_bUseSSL = false;
std::vector<std::string> voxelVxlURL;
int voxelServerID;

cl_enginefunc_t* g_pEngine;

class CCSBotManager
{
public:
	virtual void Unknown() = NULL;
	virtual void Unknown2() = NULL;
	virtual void Bot_Add(int side) = NULL;
};

CCSBotManager* g_pBotManager = NULL;;

typedef void*(*tEVP_CIPHER_CTX_new)();
tEVP_CIPHER_CTX_new g_pfnEVP_CIPHER_CTX_new;

typedef void* (*tCVoxelAdapter)();
tCVoxelAdapter g_pVoxelAdapter;

class CVoxelWorld
{
};

CVoxelWorld* g_pVoxelWorld = NULL;

#pragma region Nexon NGClient
char NGClient_Return1()
{
	return 1;
}

void NGClient_Void()
{
}
#pragma endregion

CreateHookClass(void*, SocketManagerConstructor, bool useSSL)
{
	return g_pfnSocketManagerConstructor(ptr, g_bUseSSL);
}

int __fastcall Hook_Packet_Hack_Parse(void* _this, int a2, void* packetBuffer, int packetSize)
{
	return 1;
}

void CSO_Bot_Add()
{
	// get current botmgr ptr
	DWORD dwBotManagerPtr = FindPattern(BOT_MANAGER_PTR_SIG_CSNZ, BOT_MANAGER_PTR_MASK_CSNZ, g_dwMpBase, g_dwMpBase + g_dwMpSize, 1);
	if (!dwBotManagerPtr)
	{
		MessageBox(NULL, "dwBotManagerPtr == NULL!!!", "Error", MB_OK);
		return;
	}
	g_pBotManager = **((CCSBotManager***)(dwBotManagerPtr));
	if (!g_pBotManager)
	{
		MessageBox(NULL, "g_pBotManager == NULL!!!", "Error", MB_OK);
		return;
	}

	int side = 0;
	int argc = g_pEngine->Cmd_Argc();
	if (argc > 0)
	{
		side = atoi(g_pEngine->Cmd_Argv(1));
	}
	g_pBotManager->Bot_Add(side);
}

const char* __fastcall Hook_GetSSLProtocolName(void* _this)
{
	return "None";
}

CreateHookClassType(void*, SocketConstructor, int, int a2, int a3, char a4)
{
	*(DWORD*)((int)ptr + 72) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 76) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 80) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 84) = (DWORD)g_pfnEVP_CIPHER_CTX_new();

	return g_pfnSocketConstructor(ptr, a2, a3, a4);
}

CreateHookClass(void, LogToErrorLog, int logFileId, char* buffer, int size)
{
	printf("[%s.log] %.*s", logFileId == 3 ? "Error" : "nxa", size, buffer);

	if (buffer[strlen(buffer) - 1] != '\n')
		printf("\n");

	g_pfnLogToErrorLog(ptr, logFileId, buffer, size);
}

std::string readStr(char* buffer, int offset)
{
	std::string result;

	char curChar = buffer[offset]; offset++;
	while (curChar != '\0')
	{
		result += curChar;
		curChar = buffer[offset]; offset++;
	}

	return result;
}

CreateHookClass(int, Packet_Metadata_Parse, void* packetBuffer, int packetSize)
{
	int type = *(unsigned char*)packetBuffer;
	if (type == 65)
	{
		voxelVxlURL.clear();

		int offset = 1;
		std::string str;
		int size2;
		int size3;

		int size = *((unsigned char*)((char*)packetBuffer + offset)); offset++;

		for (int i = 0; i < size; i++)
		{
			offset++;
			str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			voxelVxlURL.push_back(str);
			str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;

			size2 = *((unsigned char*)((char*)packetBuffer + offset)); offset++;

			for (int j = 0; j < size2; j++)
			{
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;

				size3 = *((unsigned char*)((char*)packetBuffer + offset)); offset++;
				offset += size3 * 2;
			}
		}
	}

	return g_pfnPacket_Metadata_Parse(ptr, packetBuffer, packetSize);
}

CreateHookClass(int, Packet_Room_Parse, void* packetBuffer, int packetSize)
{
	int type = *(unsigned char*)packetBuffer;
	if (type == 0)
	{
		int offset = 13;
		std::string str;

		int lowFlag = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;
		int lowMidFlag = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;
		int highMidFlag = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;
		int HighFlag = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;

		if (lowFlag & ROOM_LOW_ROOMNAME) {
			str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
		}
		if (lowFlag & ROOM_LOW_UNK) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_PASSWORD) {
			str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
		}
		if (lowFlag & ROOM_LOW_LEVELLIMIT) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_UNK7) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_GAMEMODEID) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_MAPID) {
			offset += 2;
		}
		if (lowFlag & ROOM_LOW_MAXPLAYERS) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_WINLIMIT) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_KILLLIMIT) {
			offset += 2;
		}
		if (lowFlag & ROOM_LOW_GAMETIME) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_ROUNDTIME) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_WEAPONLIMIT) {
			int weaponLimit = *((unsigned char*)((char*)packetBuffer + offset)); offset++;
			if (weaponLimit == 18) {
				offset += 128;
			}
		}
		if (lowFlag & ROOM_LOW_HOSTAGEKILLLIMIT) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_FREEZETIME) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_BUYTIME) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_DISPLAYNICKNAME) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_TEAMBALANCE) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_UNK21) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_FRIENDLYFIRE) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_FLASHLIGHT) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_FOOTSTEPS) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_UNK25) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_TKPUNISH) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_AUTOKICK) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_UNK28) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_UNK29) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_VIEWFLAG) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_VOICECHAT) {
			offset++;
		}
		if (lowFlag & ROOM_LOW_STATUS) {
			offset++;
		}

		if (lowMidFlag & ROOM_LOWMID_C4TIMER) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_BOT) {
			offset += 5;
		}
		if (lowMidFlag & ROOM_LOWMID_KDRULE) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_STARTINGCASH) {
			offset += 2;
		}
		if (lowMidFlag & ROOM_LOWMID_MOVINGSHOT) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_BALLNUMBER) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_STATUSSYMBOL) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_RANDOMMAP) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_MAPPLAYLIST) {
			int mapPlaylistSize = *((unsigned char*)((char*)packetBuffer + offset)); offset++;
			offset += mapPlaylistSize * 3;
		}
		if (lowMidFlag & ROOM_LOWMID_MAPPLAYLISTINDEX) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_ENHANCERESTRICT) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_SD) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_ZSDIFFICULTY) {
			offset += 10;
		}
		if (lowMidFlag & ROOM_LOWMID_LEAGUERULE) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_MANNERLIMIT) {
			offset++;
		}
		if (lowMidFlag & ROOM_LOWMID_MAPID2) {
			offset += 2;
		}
		if (lowMidFlag & ROOM_LOWMID_ZBLIMIT) {
			offset += 17;
		}
		if (lowMidFlag & ROOM_LOWMID_VOXEL) {
			int voxelFlag = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;
			if (voxelFlag & VOXELFLAG_ID) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_RESOURCEID) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_RESOURCEMAXPLAYER) {
				offset++;
			}
			if (voxelFlag & VOXELFLAG_TITLE) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_RESOURCEMODE) {
				offset++;
			}
			if (voxelFlag & VOXELFLAG_PERMISSION) {
				offset++;
			}
			if (voxelFlag & VOXELFLAG_DESCRIPTION) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_PARENTSSLOTID) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_IMAGEID) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_CREATORNICKNAME) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_CREATORUSERNAME) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_LIKECOUNT) {
				offset += 4;
			}
			if (voxelFlag & VOXELFLAG_PLAYCOUNT) {
				offset += 4;
			}
			if (voxelFlag & VOXELFLAG_BOOKMARKCOUNT) {
				offset += 4;
			}
			if (voxelFlag & VOXELFLAG_UNK15) {
				int voxel_unk15_size = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;
				for (int i = 0; i < voxel_unk15_size; i++)
				{
					offset += 4;
					str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
				}
			}
			if (voxelFlag & VOXELFLAG_CUBECOUNT) {
				offset += 4;
			}
			if (voxelFlag & VOXELFLAG_UNK17) {
				offset += 4;
			}
			if (voxelFlag & VOXELFLAG_UNK18) {
				offset += 4;
			}
			if (voxelFlag & VOXELFLAG_SLOTCATEGORY) {
				offset++;
			}
			if (voxelFlag & VOXELFLAG_SANDBOXSCRIPT) {
				offset++;
			}
			if (voxelFlag & VOXELFLAG_SAVEGROUPID) {
				str = readStr((char*)packetBuffer, offset); offset += str.size() + 1;
			}
			if (voxelFlag & VOXELFLAG_UNK22) {
				offset++;
			}
			if (voxelFlag & VOXELFLAG_UNK23) {
				offset++;
			}
			if (voxelFlag & VOXELFLAG_SERVERID) {
				voxelServerID = *((unsigned char*)((char*)packetBuffer + offset));
			}
		}
	}

	return g_pfnPacket_Room_Parse(ptr, packetBuffer, packetSize);
}

bool isDirExist(const std::string& path)
{
#if defined(_WIN32)
	struct _stat info;
	if (_stat(path.c_str(), &info) != 0)
	{
		return false;
	}
	return (info.st_mode & _S_IFDIR) != 0;
#else 
	struct stat info;
	if (stat(path.c_str(), &info) != 0)
	{
		return false;
	}
	return (info.st_mode & S_IFDIR) != 0;
#endif
}

bool makePath(const std::string& path)
{
#if defined(_WIN32)
	int ret = _mkdir(path.c_str());
#else
	mode_t mode = 0755;
	int ret = mkdir(path.c_str(), mode);
#endif
	if (ret == 0)
		return true;

	switch (errno)
	{
	case ENOENT:
		// parent didn't exist, try to create it
	{
		int pos = path.find_last_of('/');
		if (pos == std::string::npos)
#if defined(_WIN32)
			pos = path.find_last_of('\\');
		if (pos == std::string::npos)
#endif
			return false;
		if (!makePath(path.substr(0, pos)))
			return false;
	}
	// now, try to create again
#if defined(_WIN32)
	return 0 == _mkdir(path.c_str());
#else 
	return 0 == mkdir(path.c_str(), mode);
#endif

	case EEXIST:
		// done!
		return isDirExist(path);

	default:
		return false;
	}
}

static const int TIMEOUT = 3000;

CreateHookClass(void, Voxel_LoadWorld)
{
	// get current voxelworld ptr
	DWORD dwVoxelWorldPtr = FindPattern(VOXELWORLD_PTR_SIG_CSNZ, VOXELWORLD_PTR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, 2);
	if (!dwVoxelWorldPtr)
	{
		MessageBox(NULL, "dwVoxelWorldPtr == NULL!!!", "Error", MB_OK);
		return g_pfnVoxel_LoadWorld(ptr);
	}
	g_pVoxelWorld = **((CVoxelWorld***)(dwVoxelWorldPtr));

	if (g_pVoxelWorld && g_pVoxelAdapter)
	{
		LPCWCH* lpWideCharStr = (LPCWCH*)malloc(MAX_PATH);

		(*(void(__thiscall**)(int, LPCWCH*))(*(DWORD*)g_pVoxelAdapter() + 252))((int)g_pVoxelAdapter(), lpWideCharStr);

		int size_needed = WideCharToMultiByte(CP_UTF8, 0, lpWideCharStr[0], (int)wcslen(lpWideCharStr[0]), NULL, 0, NULL, NULL);
		std::string vxlFileName(size_needed, 0);
		WideCharToMultiByte(CP_UTF8, 0, lpWideCharStr[0], (int)wcslen(lpWideCharStr[0]), &vxlFileName[0], size_needed, NULL, NULL);

		free(lpWideCharStr);
		lpWideCharStr = NULL;

		std::string voxelVxlDomain;
		std::regex r("https?:\\/\\/(?:www\\.)?([-a-zA-Z0-9@:%._\\+~#=]{1,256})");
		std::smatch sm;
		regex_search(voxelVxlURL[voxelServerID], sm, r);
		voxelVxlDomain = sm[1];

		struct hostent* he;
		he = gethostbyname(voxelVxlDomain.c_str());

		if (he != NULL)
		{
			sockaddr_in servaddr;
			memset(&servaddr, 0, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			if (inet_pton(AF_INET, inet_ntoa(*((struct in_addr*)he->h_addr_list[0])), &servaddr.sin_addr) == 0)
			{
				return g_pfnVoxel_LoadWorld(ptr);
			}
			servaddr.sin_port = htons(80);

			SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

			setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&TIMEOUT), sizeof(TIMEOUT));

			if (sock < 0)
			{
				return g_pfnVoxel_LoadWorld(ptr);
			}

			if (connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
			{
				closesocket(sock);
				return g_pfnVoxel_LoadWorld(ptr);
			}

			std::string voxelVxlSuffix = sm.suffix();
			std::string vxlId = vxlFileName.substr(vxlFileName.size() - 24, 20);

			char buffer[2000];
			snprintf(buffer, 2000, voxelVxlSuffix.c_str(), vxlId.c_str());

			std::stringstream ss;
			ss << "GET " << buffer << " HTTP/1.1\r\n"
				<< "Connection: Keep-Alive\r\n"
				<< "User-Agent: cpprestsdk/2.10.2\r\n"
				<< "Host: " << voxelVxlDomain.c_str() << "\r\n"
				<< "\r\n\r\n";
			std::string request = ss.str();

			if (send(sock, request.c_str(), request.length(), 0) != (int)request.length())
			{
				closesocket(sock);
				return g_pfnVoxel_LoadWorld(ptr);
			}

			std::string response;
			char c;
			while (recv(sock, &c, 1, 0) > 0)
			{
				response.push_back(c);
			}

			closesocket(sock);

			if (!response.empty())
			{
				size_t pos = response.find("csov");
				std::string vxlBuffer = response.substr(pos, response.size() - pos);
				if (!vxlBuffer.empty())
				{
					makePath(vxlFileName.substr(0, vxlFileName.size() - 24));

					FILE* file = fopen(vxlFileName.c_str(), "wb");
					if (file)
					{
						fwrite(vxlBuffer.data(), vxlBuffer.size(), 1, file);
						fclose(file);
					}
					else
					{
						return g_pfnVoxel_LoadWorld(ptr);
					}
				}
			}
		}
	}

	return g_pfnVoxel_LoadWorld(ptr);
}

CreateHook(__cdecl, void*, Mod_FindName, qboolean trackCRC, const char* name)
{
	if (strstr(name, "/v_") != NULL || strstr(name, "/w_") != NULL || strstr(name, "/p_") != NULL || strstr(name, "/d_") != NULL || strstr(name, "/costume") != NULL)
		return g_pfnMod_FindName(trackCRC, "models/null.mdl");

	return g_pfnMod_FindName(trackCRC, name);
}

CreateHookClass(int, CMapEntityManager)
{
	*g_pFreezeTime = 20;
	return g_pfnCMapEntityManager(ptr);
}

void Init(HMODULE hModule)
{
	g_dwEngineBase = GetModuleBase(hModule);
	g_dwEngineSize = GetModuleSize(hModule);

	g_bUseSSL = CommandLine()->CheckParm("-usessl");

	const char* vxlPath;
	if (CommandLine()->CheckParm("-vxlpath", &vxlPath) && vxlPath)
		strncpy(g_pVxlPath, vxlPath, sizeof(g_pVxlPath));
}

DWORD WINAPI HookThread(LPVOID lpThreadParameter)
{
	while (!g_dwMpBase) // wait for mp.dll module
	{
		g_dwMpBase = (DWORD)GetModuleHandle("mp.dll");
		Sleep(500);
	}
	g_dwMpSize = GetModuleSize(GetModuleHandle("mp.dll"));

	// Fix mp_freezetime for modes that start with 20 seconds
	DWORD pushStr = FindPush(g_dwMpBase, g_dwMpBase + g_dwMpSize, (PCHAR)("monster_spawn_point"), 3);
	if (!pushStr)
		MessageBox(NULL, "g_pFreezeTime == NULL!!!", "Error", MB_OK);
	else
	{
		g_pFreezeTime = *(float**)(pushStr + 0x13);

		DWORD find = FindPattern(CMAPENTITYMANAGER_SIG_CSNZ, CMAPENTITYMANAGER_MASK_CSNZ, g_dwMpBase, g_dwMpBase + g_dwMpSize, NULL);
		if (!find)
			MessageBox(NULL, "CMapEntityManager == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_CMapEntityManager, (void*&)g_pfnCMapEntityManager);
	}

	if (g_pEngine)
		g_pEngine->pfnAddCommand("cso_bot_add", CSO_Bot_Add);

	return TRUE;
}

void Hook(HMODULE hModule)
{
	Init(hModule);

	DWORD find = NULL;
	void* dummy = NULL;

	find = FindPattern(DEDI_API_ADDTEXT_SIG_CSNZ, DEDI_API_ADDTEXT_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_ADDTEXT == NULL!!!", "Error", MB_OK);
	else
	{
		DWORD dwDediAddTextAddr = find + 1;
		g_pfnDediAddTextFunc = (pfnDediAddTextFunc)(dwDediAddTextAddr + 4 + *(DWORD*)dwDediAddTextAddr);
	}

	find = FindPattern(DEDI_API_UPDATESTATUS_SIG_CSNZ, DEDI_API_UPDATESTATUS_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_UPDATESTATUS == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediUpdateStatusFunc = (pfnDediUpdateStatusFunc)find;

	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, "QuitLog : GetQuitting [%d]\n");
	if (!find)
		MessageBox(NULL, "CENGINE == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0xC), (BYTE*)b, 4);
		WriteMemory((void*)&g_pCEngine, (BYTE*)b, 4);
		g_pCEngine = *(CEngine**)g_pCEngine;
	}

	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, "ScreenWindowed");
	if (!find)
		MessageBox(NULL, "CREGISTRY == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find - 0x6), (BYTE*)b, 4);
		WriteMemory((void*)&g_pCRegistry, (BYTE*)b, 4);
		g_pCRegistry = *(CRegistry**)g_pCRegistry;
	}

	find = FindPattern(CGAME_INSTANCE_SIG_CSNZ, CGAME_INSTANCE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "CGAME == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x2), (BYTE*)b, 4);
		WriteMemory((void*)&g_pCGame, (BYTE*)b, 4);
		g_pCGame = *(CGame**)g_pCGame;
	}

	find = FindPattern(DEDI_INIT_DWORD_1_SIG_CSNZ, DEDI_INIT_DWORD_1_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_INIT_DWORD_1 == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x40), (BYTE*)b, 4);
		WriteMemory((void*)&g_pIsDedicated, (BYTE*)b, 4);
	}

	find = FindPattern(DEDI_INIT_DWORD_3_SIG_CSNZ, DEDI_INIT_DWORD_3_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_INIT_DWORD_3 == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x15), (BYTE*)b, 4);
		WriteMemory((void*)&g_pBaseSocket, (BYTE*)b, 4);
	}

	find = FindPattern(DEDI_INIT_DWORD_5_SIG_CSNZ, DEDI_INIT_DWORD_5_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_INIT_DWORD_5 == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0xBB), (BYTE*)b, 4);
		WriteMemory((void*)&g_pDediInitDword5, (BYTE*)b, 4);
	}

	find = FindPattern(DEDI_INIT_DWORD_EXPORT_SIG_CSNZ, DEDI_INIT_DWORD_EXPORT_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_INIT_DWORD_EXPORT == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x3E), (BYTE*)b, 4);
		WriteMemory((void*)&g_pDediInitDwordExport, (BYTE*)b, 4);
	}

	find = FindPattern(CSERVERSTATE_SIG_CSNZ, CSERVERSTATE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "CSERVERSTATE == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x15), (BYTE*)b, 4);
		WriteMemory((void*)&g_pServerState, (BYTE*)b, 4);
	}

	find = FindPattern(DEDI_API_INIT_FUNC_1_SIG_CSNZ, DEDI_API_INIT_FUNC_1_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_1 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc1 = (pfnDediInitFunc1)find;

	find = FindPattern(DEDI_API_INIT_FUNC_2_SIG_CSNZ, DEDI_API_INIT_FUNC_2_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_2 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc2 = (pfnDediInitFunc2)find;

	find = FindPattern(DEDI_API_INIT_FUNC_3_SIG_CSNZ, DEDI_API_INIT_FUNC_3_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_3 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc3 = (pfnDediInitFunc3)find;

	find = FindPattern(DEDI_API_INIT_FUNC_5_SIG_CSNZ, DEDI_API_INIT_FUNC_5_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_5 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc5 = (pfnDediInitFunc5)find;

	find = FindPattern(DEDI_API_INIT_FUNC_6_SIG_CSNZ, DEDI_API_INIT_FUNC_6_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_6 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc6 = (pfnDediInitFunc6)(find - 0x10);

	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, "Cbuf_AddText: overflow\n");
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_7 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc7 = (pfnDediInitFunc7)(find - 0x72);

	find = FindPattern(DEDI_API_INIT_FUNC_8_SIG_CSNZ, DEDI_API_INIT_FUNC_8_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_8 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc8 = (pfnDediInitFunc8)find;

	find = FindPattern(DEDI_API_INIT_FUNC_9_SIG_CSNZ, DEDI_API_INIT_FUNC_9_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_9 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc9 = (pfnDediInitFunc9)find;

	find = FindPattern(DEDI_API_INIT_FUNC_10_SIG_CSNZ, DEDI_API_INIT_FUNC_10_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_INIT_FUNC_10 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc10 = (pfnDediInitFunc10)find;


	find = FindPattern(DEDI_API_SHUTDOWN_FUNC_1_SIG_CSNZ, DEDI_API_SHUTDOWN_FUNC_1_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_SHUTDOWN_FUNC_1 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediShutdownFunc1 = (pfnDediShutdownFunc1)find;

	find = FindPattern(DEDI_API_SHUTDOWN_FUNC_2_SIG_CSNZ, DEDI_API_SHUTDOWN_FUNC_2_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_SHUTDOWN_FUNC_2 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediShutdownFunc2 = (pfnDediShutdownFunc2)find;

	find = FindPattern(PACKET_HACK_SEND_SIG_CSNZ, PACKET_HACK_SEND_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Hack_Send == NULL!!!", "Error", MB_OK);
	else
	{
		InlineHookFromCallOpcode((void*)find, NGClient_Void, dummy, dummy);
		InlineHookFromCallOpcode((void*)(find + 0x5), NGClient_Return1, dummy, dummy);
	}

	find = FindPattern(PACKET_HACK_PARSE_SIG_CSNZ, PACKET_HACK_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Hack_Parse == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Packet_Hack_Parse, dummy);

	find = FindPattern(SOCKETMANAGER_SIG_CSNZ, SOCKETMANAGER_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "SocketManagerConstructor == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_SocketManagerConstructor, (void*&)g_pfnSocketManagerConstructor);

	find = FindPattern(LOGTOERRORLOG_SIG_CSNZ, LOGTOERRORLOG_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "LogToErrorLog == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_LogToErrorLog, (void*&)g_pfnLogToErrorLog);

	g_pEngine = (cl_enginefunc_t*)(PVOID) * (PDWORD)(FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("ScreenFade")) + 0x0D);
	if (!g_pEngine)
		MessageBox(NULL, "g_pEngine == NULL!!!", "Error", MB_OK);

	if (!g_bUseSSL)
	{
		// hook GetSSLProtocolName to make Crypt work
		find = FindPattern(GETSSLPROTOCOLNAME_SIG_CSNZ, GETSSLPROTOCOLNAME_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "GetSSLProtocolName == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_GetSSLProtocolName, dummy, dummy);

		// hook SocketConstructor to create ctx objects
		find = FindPattern(SOCKETCONSTRUCTOR_SIG_CSNZ, SOCKETCONSTRUCTOR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "SocketConstructor == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_SocketConstructor, (void*&)g_pfnSocketConstructor, dummy);

		find = FindPattern(EVP_CIPHER_CTX_NEW_SIG_CSNZ, EVP_CIPHER_CTX_NEW_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "EVP_CIPHER_CTX_new == NULL!!!", "Error", MB_OK);
		else
		{
			DWORD dwCreateCtxAddr = find + 1;
			g_pfnEVP_CIPHER_CTX_new = (tEVP_CIPHER_CTX_new)(dwCreateCtxAddr + 4 + *(DWORD*)dwCreateCtxAddr);
		}
	}

	find = FindPattern(PACKET_METADATA_PARSE_SIG_CSNZ, PACKET_METADATA_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Metadata_Parse == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Packet_Metadata_Parse, (void*&)g_pfnPacket_Metadata_Parse);

	find = FindPattern(PACKET_ROOM_PARSE_SIG_CSNZ, PACKET_ROOM_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Room_Parse == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Packet_Room_Parse, (void*&)g_pfnPacket_Room_Parse);

	find = FindPattern(VOXEL_LOADWORLD_SIG_CSNZ, VOXEL_LOADWORLD_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Voxel_LoadWorld == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Voxel_LoadWorld, (void*&)g_pfnVoxel_LoadWorld);

	find = FindPattern(VOXELADAPTER_PTR_SIG_CSNZ, VOXELADAPTER_PTR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "VoxelAdapter_Ptr == NULL!!!", "Error", MB_OK);
	else
	{
		DWORD dwVoxelAdapterAddr = find + 1;
		g_pVoxelAdapter = (tCVoxelAdapter)(dwVoxelAdapterAddr + 4 + *(DWORD*)dwVoxelAdapterAddr);
	}

	// patch 1000 fps limit
	find = FindPattern(FPS_PATCH_SIG_CSNZ, FPS_PATCH_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "1000Fps_Patch == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		WriteMemory((void*)find, (BYTE*)patch, sizeof(patch));
	}

	// patch socket
	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("SocketManager - Max retry reached!!! Server Connection failed \n"));
	if (!find)
		MessageBox(NULL, "Socket_Patch == NULL!!!", "Error", MB_OK);
	else
	{
		find -= 0xE;
		BYTE patch[] = { 0x01 };
		WriteMemory((void*)find, (BYTE*)patch, sizeof(patch));
	}

	// patch dedi models
	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("PF_precache_model_I: Model '%s' failed to precache because the item count is over the %d limit.\nReduce the number of brush models and/or regular models in the map to correct this."));
	if (!find)
		MessageBox(NULL, "Dedi_Models_Patch == NULL!!!", "Error", MB_OK);
	else
	{
		find += 0x48;
		BYTE patch[] = { 0x75 };
		WriteMemory((void*)find, (BYTE*)patch, sizeof(patch));

		InlineHookFromCallOpcode((void*)(find + 0x1D), Hook_Mod_FindName, (void*&)g_pfnMod_FindName, dummy);
	}

	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("PF_precache_model_dynamic_I: Model '%s' failed to precache because the item count is over the %d limit.\nReduce the number of brush models and/or regular models in the map to correct this."));
	if (!find)
		MessageBox(NULL, "Dedi_Models_Patch2 == NULL!!!", "Error", MB_OK);
	else
	{
		find += 0x48;
		BYTE patch[] = { 0x75 };
		WriteMemory((void*)find, (BYTE*)patch, sizeof(patch));
	}

	// create thread to wait for mp.dll
	CreateThread(NULL, 0, HookThread, NULL, 0, 0);
}

void Unhook()
{
	FreeAllHook();
}
