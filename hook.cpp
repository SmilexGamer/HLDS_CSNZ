#include "hook.h"
#include "hookutils.h"
#include <stdio.h>
#include <ICommandLine.h>
#include <string>
#include <regex>
#include <sstream>
#include <winsock2.h>
#include <ws2tcpip.h>

DWORD g_dwEngineBase;
DWORD g_dwEngineSize;

DWORD g_dwMpBase;
DWORD g_dwMpSize;

#define SOCKETMANAGER_SIG_CSNZ23 "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x51\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\x00\x8A\x45"
#define SOCKETMANAGER_MASK_CSNZ23 "xxxx?x????xx????xxxxxx????xxxxx?xx????xxxx?xx"

#define PACKET_HACK_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\x00\x8B\x45\x00\x89\x45\x00\x8B\x45\x00\xC7\x45\x00\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\x89\x45\x00\x6A\x00\x8D\x45\x00\xC7\x45\x00\x00\x00\x00\x00\x50\x8D\x4D\x00\xE8\x00\x00\x00\x00\x0F\xB6\x45\x00\x89\x43\x00\x83\xE8"
#define PACKET_HACK_PARSE_MASK_CSNZ "xxxx?x????xx????xxx?xxxx????xxxxx?xx????xxxx?xx?xx?xx?xx?????xx?????xx?x?xx?xx?????xxx?x????xxx?xx?xx"

#define PACKET_HACK_SEND_SIG_CSNZ "\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xEB\x00\x43\x56\x20\x20\x0D"
#define PACKET_HACK_SEND_MASK_CSNZ "x????x????x?xxxxx"

#define BOT_MANAGER_PTR_SIG_CSNZ "\xA3\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x83\xC4"
#define BOT_MANAGER_PTR_MASK_CSNZ "x????xx?????xx????xx"

#define LOGTOERRORLOG_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x8B\x7D\x00\x8D\x45\x00\x50\x6A"
#define LOGTOERRORLOG_MASK_CSNZ "xxxxx????x????xxxx?xxxx?xx?xx"

#define GETSSLPROTOCOLNAME_SIG_CSNZ "\xE8\x00\x00\x00\x00\xB9\x00\x00\x00\x00\x8A\x10"
#define GETSSLPROTOCOLNAME_MASK_CSNZ "x????x????xx"

#define SOCKETCONSTRUCTOR_SIG_CSNZ "\xE8\x00\x00\x00\x00\xEB\x00\x33\xC0\x53\xC7\x45"
#define SOCKETCONSTRUCTOR_MASK_CSNZ "x????x?xxxxx"

#define EVP_CIPHER_CTX_NEW_SIG_CSNZ "\xE8\x00\x00\x00\x00\x8B\xF8\x89\xBE"
#define EVP_CIPHER_CTX_NEW_MASK_CSNZ "x????xxxx"

#define PACKET_VOXEL_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89\xBD\x00\x00\x00\x00\x8B\x45\x00\x33\xF6\x89\xB5\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x8B\x45\x00\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\x89\xB5\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x6A\x00\x8D\x85\x00\x00\x00\x00\x89\x75\x00\x50\x8D\x8D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x0F\xB6\x8D"
#define PACKET_VOXEL_PARSE_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xxxx????xx?xxxx????xx????xx?xx????????xx????xx????x?xx????xx?xxx????x????xxx"

#define VOXEL_LOADWORLD_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x83\x3D\x00\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00\x56"
#define VOXEL_LOADWORLD_MASK_CSNZ "xxxxx????x????xxxx?xx?????xx????xx?????x"

#define VOXELADAPTER_PTR_SIG_CSNZ "\xE8\x00\x00\x00\x00\x83\xFE\x00\x7C"
#define VOXELADAPTER_PTR_MASK_CSNZ "x????xx?x"

#define VOXELWORLD_PTR_SIG_CSNZ "\x83\x3D\x00\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00\x56"
#define VOXELWORLD_PTR_MASK_CSNZ "xx?????xx????xx?????x"

#define DEDI_API_ADDTEXT_SIG_CSNZ "\x55\x8B\xEC\x8B\x4D\x00\x8B\x81\x00\x00\x00\x00\x3B\x05"
#define DEDI_API_ADDTEXT_MASK_CSNZ "xxxxx?xx????xx"

#define DEDI_API_UPDATESTATUS_SIG_CSNZ "\x55\x8B\xEC\x51\xF2\x0F\x10\x0D\x00\x00\x00\x00\x0F\x57\xC0"
#define DEDI_API_UPDATESTATUS_MASK_CSNZ "xxxxxxxx????xxx"

#define CGAME_INSTANCE_SIG_CSNZ "\x8B\x0D\x00\x00\x00\x00\x56\x8B\x01\xFF\x50\x00\x50\xE8\x00\x00\x00\x00\x8B\xF0"
#define CGAME_INSTANCE_MASK_CSNZ "xx????xxxxx?xx????xx"

#define DEDI_INIT_DWORD_1_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00\x74"
#define DEDI_INIT_DWORD_1_MASK_CSNZ "xxxx?x????xx????xxx?x????xxxx?xxxxx?xx????xx?????x"

#define DEDI_INIT_DWORD_3_SIG_CSNZ "\x56\x8B\xF1\x8B\xD6"
#define DEDI_INIT_DWORD_3_MASK_CSNZ "xxxxx"

#define DEDI_INIT_DWORD_4_SIG_CSNZ "\x83\x3D\x00\x00\x00\x00\x00\x74\x00\xF3\x0F\x10\x05\x00\x00\x00\x00\xE8"
#define DEDI_INIT_DWORD_4_MASK_CSNZ "xx?????x?xxxx????x"

#define DEDI_INIT_DWORD_5_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x8D\x45\x00\x50\x6A\x00\xFF\x75\x00\x8D\x85\x00\x00\x00\x00\x68\x00\x00\x00\x00\x50"
#define DEDI_INIT_DWORD_5_MASK_CSNZ "xxxxx????x????xxxx?xxxx?xx?xx?xx????x????x"

#define DEDI_INIT_DWORD_6_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\x45\x00\x8B\x4D\x00\x8B\x75\x00\x6A"
#define DEDI_INIT_DWORD_6_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xx?xx?xx?x"

#define DEDI_INIT_DWORD_EXPORT_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x8D\x45\x00\x50\x6A\x00\xFF\x75\x00\x8D\x85\x00\x00\x00\x00\x68\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x8B\x08\xFF\x70\x00\x83\xC9\x00\x51\xFF\x15\x00\x00\x00\x00\x8B\x0D"
#define DEDI_INIT_DWORD_EXPORT_MASK_CSNZ "xxxxx????x????xxxx?xx?xx?xx?xx????x????xx????xxxx?xx?xxx????xx"

#define DEDI_INIT_DWORD_8_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\x00\xC7\x03\x00\x00\x00\x00\x83\x3D"
#define DEDI_INIT_DWORD_8_MASK_CSNZ "xxxx?x????xx????xxx?xxxx????xxxxx?xx????xxxx?xx????xx"

#define CSERVERSTATE_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\xC7\x05"
#define CSERVERSTATE_MASK_CSNZ "xxxxx????x????xxxx?xx"

#define DEDI_API_INIT_FUNC_1_SIG_CSNZ "\x55\x8B\xEC\x53\x56\x57\x6A\x00\xE8\x00\x00\x00\x00\x8B\x7D"
#define DEDI_API_INIT_FUNC_1_MASK_CSNZ "xxxxxxx?x????xx"

#define DEDI_API_INIT_FUNC_2_SIG_CSNZ "\x55\x8B\xEC\xA1\x00\x00\x00\x00\xBA"
#define DEDI_API_INIT_FUNC_2_MASK_CSNZ "xxxx????x"

#define DEDI_API_INIT_FUNC_3_SIG_CSNZ "\x55\x8B\xEC\x8B\x4D\x00\xBA\x00\x00\x00\x00\x2B\xD1"
#define DEDI_API_INIT_FUNC_3_MASK_CSNZ "xxxxx?x????xx"

#define DEDI_API_INIT_FUNC_4_SIG_CSNZ "\xE8\x00\x00\x00\x00\x8B\xD0\x83\xC4\x00\x85\xD2\x74\x00\x8B\x0D\x00\x00\x00\x00\x49\x3B\xD1\x7D\x00\xA1\x00\x00\x00\x00\x68\x00\x00\x00\x00\xFF\x74\x90\x00\x8D\x85\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\x83\xC4\x00\xC6\x45\x00\x00\x68"
#define DEDI_API_INIT_FUNC_4_MASK_CSNZ "x????xxxx?xxx?xx????xxxx?x????x????xxx?xx????xx????xx?xx??x"

#define DEDI_API_INIT_FUNC_5_SIG_CSNZ "\x55\x8B\xEC\x8D\x45\x00\x50\x6A\x00\xFF\x75\x00\x6A\x00\xFF\x75\x00\xE8\x00\x00\x00\x00\x8B\x08\xFF\x70\x00\x83\xC9\x00\x51\xFF\x15\x00\x00\x00\x00\x83\xC9"
#define DEDI_API_INIT_FUNC_5_MASK_CSNZ "xxxxx?xx?xx?x?xx?x????xxxx?xx?xxx????xx"

#define DEDI_API_INIT_FUNC_6_SIG_CSNZ "\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\x85\xC9\x74\x00\x8B\x01\x6A"
#define DEDI_API_INIT_FUNC_6_MASK_CSNZ "x????x????xx????xxx?xxx"

#define DEDI_API_INIT_FUNC_8_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\xFF\x75"
#define DEDI_API_INIT_FUNC_8_MASK_CSNZ "xxxx?x????xx????xx????xxxxx?xx????xx"

#define DEDI_API_INIT_FUNC_9_SIG_CSNZ "\x55\x8B\xEC\x8B\x55\x00\x8B\xC2\x56\x57\x8B\xF1\x8D\x78\x00\x90\x8A\x08\x40\x84\xC9\x75\x00\x2B\xC7\x8D\x4E"
#define DEDI_API_INIT_FUNC_9_MASK_CSNZ "xxxxx?xxxxxxxx?xxxxxxx?xxxx"

#define DEDI_API_INIT_FUNC_10_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x51\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\xFF\x15"
#define DEDI_API_INIT_FUNC_10_MASK_CSNZ "xxxx?x????xx????xxx????xxxxx?xx????xx"

#define DEDI_API_SHUTDOWN_FUNC_1_SIG_CSNZ "\x55\x8B\xEC\x57\x8B\x7D\x00\x8B\x14\xBD"
#define DEDI_API_SHUTDOWN_FUNC_1_MASK_CSNZ "xxxxxx?xxx"

#define DEDI_API_SHUTDOWN_FUNC_2_SIG_CSNZ "\x8B\x0D\x00\x00\x00\x00\x8B\x01\xFF\x50\x00\xA1\x00\x00\x00\x00\x85\xC0"
#define DEDI_API_SHUTDOWN_FUNC_2_MASK_CSNZ "xx????xxxx?x????xx"

pfnDediAddTextFunc g_pfnDediAddTextFunc = 0;
pfnDediUpdateStatusFunc g_pfnDediUpdateStatusFunc = 0;

CEngine* g_pCEngine = 0;
CRegistry* g_pCRegistry = 0;
CGame* g_pCGame = 0;

int g_pIsDedicated = 0;
int g_pDediInitDword2 = 0;
int g_pBaseSocket = 0;
void* g_pPacketHostServer = 0;
char* g_pDediInitDword5 = 0;
char* g_pDediInitDword6 = 0;
void* g_pDediInitDwordExport = 0;
int g_pDediInitDword8 = 0;
int g_pServerState = 0;

pfnDediInitFunc1 g_pfnDediInitFunc1 = 0;
pfnDediInitFunc2 g_pfnDediInitFunc2 = 0;
pfnDediInitFunc3 g_pfnDediInitFunc3 = 0;
pfnDediInitFunc4 g_pfnDediInitFunc4 = 0;
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
std::string voxelVxlURL;

cl_enginefunc_t* g_pEngine;

class CCSBotManager
{
public:
	virtual void Unknown() = NULL;
	virtual void Bot_Add(int side) = NULL;
};

CCSBotManager* g_pBotManager = NULL;;

typedef void* (*tEVP_CIPHER_CTX_new)();
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

	int side = 0;
	int argc = g_pEngine->Cmd_Argc();
	if (argc > 0)
	{
		side = atoi(g_pEngine->Cmd_Argv(1));
	}
	g_pBotManager->Bot_Add(side);
}

CreateHookClass(const char*, GetSSLProtocolName)
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

CreateHook(__cdecl, void, LogToErrorLog, char* pLogFile, int logFileId, char* fmt, int fmtLen, ...)
{
	char outputString[1024];

	va_list va;
	va_start(va, fmtLen);
	_vsnprintf_s(outputString, sizeof(outputString), fmt, va);
	outputString[1023] = 0;
	va_end(va);

	printf("[LogToErrorLog][%s.log] %s\n", logFileId == 3 ? "Error" : "nxa", outputString);

	g_pfnLogToErrorLog(pLogFile, logFileId, outputString, fmtLen);
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

CreateHookClass(int, Packet_Voxel_Parse, void* packetBuffer, int packetSize)
{
	int type = *(unsigned char*)packetBuffer;
	if (type == 20)
		voxelVxlURL = readStr((char*)packetBuffer, 1);

	return g_pfnPacket_Voxel_Parse(ptr, packetBuffer, packetSize);
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
		regex_search(voxelVxlURL, sm, r);
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
					CreateDirectory(vxlFileName.substr(0, vxlFileName.size() - 24).c_str(), NULL);

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
		g_pfnDediAddTextFunc = (pfnDediAddTextFunc)(find + 0x30);
	}

	find = FindPattern(DEDI_API_UPDATESTATUS_SIG_CSNZ, DEDI_API_UPDATESTATUS_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_API_UPDATESTATUS == NULL!!!", "Error", MB_OK);
	else
	{
		g_pfnDediUpdateStatusFunc = (pfnDediUpdateStatusFunc)find;
	}

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

	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, "Failed to Initialize DirectX. Please restart launcher");
	if (!find)
		MessageBox(NULL, "CREGISTRY == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find - 0x17), (BYTE*)b, 4);
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
		ReadMemory((void*)(find + 0x2C), (BYTE*)b, 4);
		WriteMemory((void*)&g_pIsDedicated, (BYTE*)b, 4);
		ReadMemory((void*)(find + 0x46), (BYTE*)b, 4);
		WriteMemory((void*)&g_pDediInitDword2, (BYTE*)b, 4);
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

	find = FindPattern(DEDI_INIT_DWORD_4_SIG_CSNZ, DEDI_INIT_DWORD_4_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_INIT_DWORD_4 == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x2), (BYTE*)b, 4);
		WriteMemory((void*)&g_pPacketHostServer, (BYTE*)b, 4);
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

	find = FindPattern(DEDI_INIT_DWORD_6_SIG_CSNZ, DEDI_INIT_DWORD_6_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_INIT_DWORD_6 == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x6B), (BYTE*)b, 4);
		WriteMemory((void*)&g_pDediInitDword6, (BYTE*)b, 4);
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

	find = FindPattern(DEDI_INIT_DWORD_8_SIG_CSNZ, DEDI_INIT_DWORD_8_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "DEDI_INIT_DWORD_8 == NULL!!!", "Error", MB_OK);
	else
	{
		BYTE b[4] = { 0,0,0,0 };
		ReadMemory((void*)(find + 0x35), (BYTE*)b, 4);
		WriteMemory((void*)&g_pDediInitDword8, (BYTE*)b, 4);
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

	find = FindPattern(DEDI_API_INIT_FUNC_4_SIG_CSNZ, DEDI_API_INIT_FUNC_4_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
	{
	}
	//MessageBox(NULL, "DEDI_API_INIT_FUNC_4 == NULL!!!", "Error", MB_OK);
	else
		g_pfnDediInitFunc4 = (pfnDediInitFunc4)find;

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

	find = FindPattern(SOCKETMANAGER_SIG_CSNZ23, SOCKETMANAGER_MASK_CSNZ23, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
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
	else
		g_pEngine->pfnAddCommand("cso_bot_add", CSO_Bot_Add);

	if (!g_bUseSSL)
	{
		// hook GetSSLProtocolName to make Crypt work
		find = FindPattern(GETSSLPROTOCOLNAME_SIG_CSNZ, GETSSLPROTOCOLNAME_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "GetSSLProtocolName == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_GetSSLProtocolName, (void*&)g_pfnGetSSLProtocolName, dummy);

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

	find = FindPattern(PACKET_VOXEL_PARSE_SIG_CSNZ, PACKET_VOXEL_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "Packet_Voxel_Parse == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_Packet_Voxel_Parse, (void*&)g_pfnPacket_Voxel_Parse);

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
	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, "%3i fps -- host(%3.0f) sv(%3.0f) cl(%3.0f) gfx(%3.0f) snd(%3.0f) ents(%d)\n", 2);
	if (!find)
		MessageBox(NULL, "1000Fps_Patch == NULL!!!", "Error", MB_OK);
	else
	{
		DWORD patchAddr = find - 0x43A;
		BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));
	}

	// create thread to wait for mp.dll
	CreateThread(NULL, 0, HookThread, NULL, 0, 0);
}

void Unhook()
{
	FreeAllHook();
}