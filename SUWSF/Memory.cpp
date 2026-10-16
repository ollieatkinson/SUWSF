#include "Memory.h"
#include <Windows.h>
#include <cstring>

bool Memory::Write(BYTE* address, const BYTE* bytes, size_t num)
{
	DWORD oldProtection, ignored;
	if (!VirtualProtect(address, num, PAGE_EXECUTE_READWRITE, &oldProtection))
		return false;
	std::memcpy(address, bytes, num);
	const bool flushed = FlushInstructionCache(GetCurrentProcess(), address, num) != FALSE;
	return VirtualProtect(address, num, oldProtection, &ignored) != FALSE && flushed;
}
