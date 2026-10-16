#pragma once
#include <string>
#include<vector>

class GenericPatch
{
public:
	static void Init();
private:
	struct Config
	{
		std::string name;
		std::string pattern = "";
		int offset = 0;
		std::string val = "";
		std::string valType = "float";
		std::string matches = "all";
		std::string module = "auto";
		int expectedMatches = 0;
	};
	struct Write
	{
		unsigned char* address;
		std::vector<unsigned char> value;
		std::vector<unsigned char> original;
	};
	static std::vector<Config> GetConfigs();
	static bool PlanPatch(const Config& config, std::vector<Write>& writes);
	static void PatchAll(std::vector<Config> configs);
};
