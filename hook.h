#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include <Windows.h>

typedef float vec_t;
typedef float vec2_t[2];
typedef float vec3_t[3];
typedef int (*pfnUserMsgHook)(const char* pszName, int iSize, void* pbuf);

class CEngine
{
private:
	int m_nQuitting;
	int m_nDLLState;
	int m_nSubState;
	double m_fCurTime;
	double m_fFrameTime;
	double m_fOldTime;
	bool m_bTrapMode;
	bool m_bDoneTrapping;
	int m_nTrapKey;
	int m_nTrapButtons;
public:
	virtual void Destructor() = 0;
	virtual bool Load(bool dedi, const char* basedir, const char* cmdline) = 0;
	virtual void Unload() = 0;
	virtual int SetState(int) = 0;
	virtual int GetState() = 0;
	virtual int SetSubState(int) = 0;
	virtual int GetSubState() = 0;
	virtual int Frame() = 0;
	virtual int GetFrameTime() = 0;
	virtual int GetCurTime() = 0;
	virtual int TrapKey_Event(int, short) = 0;
	virtual int TrapMouse_Event(int, bool) = 0;
	virtual void StartTrapMode() = 0;
	virtual bool IsTrapping() = 0;
	virtual bool CheckDoneTrapping(void*, void*) = 0;
	virtual int GetQuitting() = 0;
	virtual int SetQuitting(int) = 0;
};
class CRegistry
{
public:
	virtual bool Init() = 0;
	virtual LSTATUS RegClose() = 0;
	virtual int ReadInt(LPCSTR, int) = 0;
	virtual LSTATUS WriteInt(LPCSTR, BYTE) = 0;
	virtual BYTE* ReadString(LPCSTR, int) = 0;
	virtual void WriteString(LPCSTR, BYTE*) = 0;
	virtual void Destructor(char) = 0;
};

class CGame
{
private:
	bool m_bActiveApp;
public:
	virtual void* Destructor(char) = 0;
	virtual bool Init(void*) = 0;
	virtual bool Shutdown() = 0;
	virtual bool CreateGameWindow() = 0;
	virtual int Func10() = 0;
	virtual int Func14() = 0;
	virtual bool DestroyWin() = 0;
	virtual bool CreateWin() = 0;
	virtual DWORD _MsgWaitForMultipleObjects(HANDLE, DWORD ms) = 0;
	virtual void* Func24() = 0;
	virtual char* Func28() = 0;
	virtual int SetWindowXY(int, int) = 0;
	virtual int SetWindowSize(int, int) = 0;
	virtual int GetWindowRect(void*, void*, void*, void*) = 0;
	virtual char IsActiveApp() = 0;
	virtual char IsMultiplayer() = 0;
	virtual int PlayStartupVideos() = 0;
	virtual void PlayAVIAndWait(BYTE*) = 0;
	virtual int SetCursorVisible() = 0;
};

typedef char* (*pfnDediAddTextFunc)(char*);
extern pfnDediAddTextFunc g_pfnDediAddTextFunc;

typedef void* (*pfnDediUpdateStatusFunc)(float* fps, int* nActive, void*, int* nMaxPlayers, char* pszMap);
extern pfnDediUpdateStatusFunc g_pfnDediUpdateStatusFunc;


extern CEngine* g_pCEngine;
extern CRegistry* g_pCRegistry;
extern CGame* g_pCGame;


extern int g_pIsDedicated;
extern int g_pDediInitDword2;
extern int g_pBaseSocket;
extern void* g_pPacketHostServer;
extern char* g_pDediInitDword5;
extern char* g_pDediInitDword6;
extern void* g_pDediInitDwordExport;
extern int g_pDediInitDword8;
extern int g_pServerState;

typedef void(__cdecl* pfnDediInitFunc1)(const char*, const char*, int);
extern pfnDediInitFunc1 g_pfnDediInitFunc1;

typedef void (*pfnDediInitFunc2)(char*);
extern pfnDediInitFunc2 g_pfnDediInitFunc2;

typedef int (*pfnDediInitFunc3)(const char*, void*);
extern pfnDediInitFunc3 g_pfnDediInitFunc3;

typedef int (*pfnDediInitFunc4)(const char*);
extern pfnDediInitFunc4 g_pfnDediInitFunc4;

typedef int (*pfnDediInitFunc4)(const char*);
extern pfnDediInitFunc4 g_pfnDediInitFunc4;

typedef int (*pfnDediInitFunc5)(char*, const char*, ...);
extern pfnDediInitFunc5 g_pfnDediInitFunc5;

typedef void* (*pfnDediInitFunc6)(void*);
extern pfnDediInitFunc6 g_pfnDediInitFunc6;

typedef void (*pfnDediInitFunc7)(const char*);
extern pfnDediInitFunc7 g_pfnDediInitFunc7;

typedef void (*pfnDediInitFunc8)(char*, int, int);
extern pfnDediInitFunc8 g_pfnDediInitFunc8;

typedef void(__thiscall* pfnDediInitFunc9)(void*, const char*);
extern pfnDediInitFunc9 g_pfnDediInitFunc9;

typedef void (*pfnDediInitFunc10)(LPCSTR);
extern pfnDediInitFunc10 g_pfnDediInitFunc10;

typedef int (*pfnDediShutdownFunc1)(const char*, int);
extern pfnDediShutdownFunc1 g_pfnDediShutdownFunc1;

typedef HMODULE(*pfnDediShutdownFunc2)();
extern pfnDediShutdownFunc2 g_pfnDediShutdownFunc2;



#include <wrect.h>
#include <cdll_int.h>

void Hook(HMODULE hModule);
void Unhook();

#define CreateHook(funcType, returnType, funcName, ...) \
returnType (funcType* g_pfn##funcName)(__VA_ARGS__); \
returnType funcType Hook_##funcName(__VA_ARGS__)

#define CreateHookClassType(returnType,funcName,classType, ...) \
returnType (__thiscall* g_pfn##funcName)(classType*ptr, __VA_ARGS__); \
returnType __fastcall Hook_##funcName(classType*ptr, int reg, __VA_ARGS__)

#define CreateHookClass(returnType, funcName, ...) CreateHookClassType(returnType, funcName, void, __VA_ARGS__)