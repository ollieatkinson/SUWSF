#pragma once
#include <Windows.h>
#include <cstddef>

class Memory
{
public:
	static bool Write(BYTE* address, const BYTE* bytes, size_t num);
};
