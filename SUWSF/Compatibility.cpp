#include "dllmain.h"
#include "Compatibility.h"
#include "Logging.h"
#include "../external/IniReader/IniReader.h"
#include <bcrypt.h>
#include <array>
#include <filesystem>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "bcrypt.lib")

namespace
{
	std::string FileHash(const wchar_t* path)
	{
		struct Handles
		{
			BCRYPT_ALG_HANDLE algorithm = nullptr;
			BCRYPT_HASH_HANDLE hash = nullptr;
			~Handles()
			{
				if (hash) BCryptDestroyHash(hash);
				if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
			}
		} handles;

		std::ifstream file(std::filesystem::path(path), std::ios::binary);
		if (!file || BCryptOpenAlgorithmProvider(&handles.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
			BCryptCreateHash(handles.algorithm, &handles.hash, nullptr, 0, nullptr, 0, 0) < 0)
			return {};

		std::array<unsigned char, 65536> buffer;
		while (file)
		{
			file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
			if (file.gcount() && BCryptHashData(handles.hash, buffer.data(), static_cast<ULONG>(file.gcount()), 0) < 0)
				return {};
		}
		std::array<unsigned char, 32> digest;
		if (!file.eof() || BCryptFinishHash(handles.hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
			return {};

		std::ostringstream hex;
		hex << std::hex << std::setfill('0');
		for (auto byte : digest) hex << std::setw(2) << static_cast<unsigned int>(byte);
		return hex.str();
	}
}

bool Compatibility::Check()
{
	CIniReader ini(ININAME);
	auto expected = ini.ReadString("Compatibility", "SHA256", "");
	if (expected.empty()) return true;
	std::transform(expected.begin(), expected.end(), expected.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	if (expected.size() != 64 || expected.find_first_not_of("0123456789abcdef") != std::string::npos)
	{
		DBOUT("Invalid Compatibility SHA256; no patches applied.");
		return false;
	}

	auto module = ini.ReadString("Compatibility", "Module", "auto");
	auto handle = GetModuleHandleA(module == "auto" ? nullptr : module.c_str());
	wchar_t path[32768];
	const auto length = handle ? GetModuleFileNameW(handle, path, static_cast<DWORD>(std::size(path))) : 0;
	if (!length || length == std::size(path))
	{
		DBOUT("Could not locate compatibility module " << module << "; no patches applied.");
		return false;
	}
	const auto actual = FileHash(path);
	if (actual != expected)
	{
		DBOUT("Compatibility SHA256 mismatch for " << module << "; no patches applied. Expected " << expected << ", got " << actual);
		return false;
	}
	DBOUT("Compatibility SHA256 verified for " << module);
	return true;
}
