// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <Psapi.h>
#include "../external/IniReader/IniReader.h"
#include <algorithm>
#include "dllmain.h"
#include "Logging.h"
#include "UserSettings.h"
#include "GenericPatch.h"
#include <mutex>

void Init()
{
	SetThreadLocale(LOCALE_INVARIANT);
	ClearLogFiles();
	DBOUT(APPNAME << " " << VERSION << " INITIALIZED.");
	DBOUT("Process " << GetCurrentProcessId() << ", thread " << GetCurrentThreadId());

	GetModuleFileName(nullptr, szFileName, MAX_PATH);

	UserSettings::Init();
	GenericPatch::Init();
}

static void InitOnce()
{
	static std::once_flag once;
	std::call_once(once, [] {
		// A second copy of the ASI must not patch the same process again.
		const auto name = L"Local\\SUWSF.Initialize." + std::to_wstring(GetCurrentProcessId());
		static HANDLE owner;
		owner = CreateMutexW(nullptr, FALSE, name.c_str());
		if (owner && GetLastError() == ERROR_ALREADY_EXISTS)
		{
			CloseHandle(owner);
			owner = nullptr;
			return;
		}
		Init();
	});
}

static bool LoadedByUltimateASILoader()
{
	void* frames[64];
	const auto count = CaptureStackBackTrace(0, 64, frames, nullptr);
	for (USHORT i = 0; i < count; ++i)
	{
		HMODULE module = nullptr;
		if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(frames[i]), &module) && GetProcAddress(module, "IsUltimateASILoader"))
			return true;
	}
	return false;
}

extern "C" __declspec(dllexport) void InitializeASI()
{
	// The loader waits here, so startup cannot race ahead of the patches.
	InitOnce();
}

static DWORD WINAPI InitThread(LPVOID)
{
	InitOnce();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// Ultimate ASI Loader calls InitializeASI after LoadLibrary returns.
		if (!LoadedByUltimateASILoader())
			if (auto thread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr))
				CloseHandle(thread);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
