#include "GenericPatch.h"
#include "dllmain.h"
#include "../external/IniReader/IniReader.h"
#include "Logging.h"
#include "boost/algorithm/string/replace.hpp"
#include "Memory.h"
#include "UserSettings.h"
#include <string>
#include "../external/tinyexpr/tinyexpr.h"
#include "../external/Hooking.Patterns/Hooking.Patterns.h"
#include <boost/lexical_cast.hpp>
#include "Compatibility.h"

void GenericPatch::Init()
{
	DBOUT("Initializing GenericPatch patches");
	if (UserSettings::config.enabled && !Compatibility::Check())
		return;
	PatchAll(GetConfigs());
}

std::vector<GenericPatch::Config> GenericPatch::GetConfigs()
{
	CIniReader ini(ININAME);

	std::vector<Config> configs;
	if (!UserSettings::config.enabled)
	{
		DBOUT("Patches disabled by UserSettings");
		return configs;
	}

	DBOUT("Searching for patches...");

	for (auto& entry : ini.data)
	{
		if (entry.first.find("Patch") == std::string::npos)
			continue;

		DBOUT("Found patch " << entry.first);

		Config config;
		config.name = entry.first;

		for (auto& params : entry.second)
		{
			boost::erase_all(params.second, "\"");
			if (params.first == "Pattern")
			{
				DBOUT("Pattern=" << params.second);
				config.pattern = params.second;
				boost::replace_all(config.pattern, "??", "?");
			}
			else if (params.first == "Offset")
			{
				DBOUT("Offset=" << params.second);
				try
				{
					config.offset = std::stoi(params.second);
				}
				catch (std::exception const& e)
				{
					DBOUT("Offset is not an integer, skipping patch...");
					goto CONTINUE;
				}
				if (config.offset < 0)
				{
					DBOUT("Offset invalid, must be greater than or equal to 0. Skipping patch...");
					goto CONTINUE;
				}
			}
			else if (params.first == "Value")
			{
				DBOUT("Value=" << params.second);
				config.val = params.second;
			}
			else if (params.first == "ValueType")
			{
				DBOUT("ValueType=" << params.second);
				config.valType = params.second;
				if (config.valType != "float" && config.valType != "byte" && config.valType != "int" && config.valType != "double")
				{
					DBOUT("ValueType unsupported. Supported types are: float, byte...Skipping patch...");
					goto CONTINUE;
				}
			}
			else if (params.first == "Match")
			{
				DBOUT("Match=" << params.second);
				config.matches = params.second;
			}
			else if (params.first == "ExpectedMatches")
			{
				try
				{
					size_t end;
					config.expectedMatches = std::stoi(params.second, &end);
					if (end != params.second.size() || config.expectedMatches < 1)
						goto CONTINUE;
				}
				catch (const std::exception&)
				{
					goto CONTINUE;
				}
			}
			else if (params.first == "Enabled")
			{
				DBOUT("Enabled=" << params.second);
				if (params.second != "true")
				{
					DBOUT("Patch not enabled, skipping patch...");
					goto SKIP;
				}
			}
			else if (params.first == "Module")
			{
				DBOUT("Module=" << params.second);
				config.module = params.second;
			}
		}
		if (config.pattern.length() == 0)
		{
			DBOUT("No pattern found, skipping patch...");
			goto CONTINUE;
		}
		if (config.valType == "float" || config.valType == "int" || config.valType == "double")
		{
			try
			{
				boost::replace_all(config.val, "width", std::to_string(UserSettings::config.width));
				boost::replace_all(config.val, "height", std::to_string(UserSettings::config.height));
				boost::replace_all(config.val, "aspectratio", boost::lexical_cast<std::string>(UserSettings::config.aspectratio));
				int error = -1;
				double d = te_interp(config.val.c_str(), &error);

				if (error != 0)
				{
					DBOUT("Could not interpret value expression, skipping patch...");
					goto CONTINUE;
				}

				if (config.valType == "float")
				{
					float f = static_cast<float>(d);
					config.val = hexStr(reinterpret_cast<BYTE*>(&f), sizeof(float));
				}
				else if (config.valType == "int")
				{
					int i = static_cast<int>(d);
					config.val = hexStr(reinterpret_cast<BYTE*>(&i), sizeof(int));
				}
				else if (config.valType == "double")
				{
					config.val = hexStr(reinterpret_cast<BYTE*>(&d), sizeof(double));
				}
			}
			catch (std::exception const& e)
			{
				DBOUT("Value is not a float, skipping patch...");
				goto CONTINUE;
			}
		}
		else if (config.valType == "byte")
		{
			if (BytesFromString(config.val).size() == 0)
			{
				DBOUT("Value could not be read as bytes, skipping patch...");
				goto CONTINUE;
			}
		}
		configs.push_back(config);
		continue;
	CONTINUE:
		if (UserSettings::config.atomic)
		{
			DBOUT("Invalid configuration for " << entry.first << "; no patches applied.");
			return {};
		}
	SKIP:
		continue;
	}
	DBOUT(configs.size() << " patches found");
	return configs;
}

bool GenericPatch::PlanPatch(const Config& config, std::vector<Write>& writes)
{
    const auto moduleName = config.module == "auto" ? std::string(szFileName) : config.module;
    const auto module = GetModuleInfo(const_cast<char*>(moduleName.c_str()));
    if (!module.EntryPoint)
    {
        DBOUT("Could not find module " << moduleName);
        return false;
    }
    const auto base = reinterpret_cast<uintptr_t>(module.lpBaseOfDll);
    auto pattern = hook::pattern(base, base + module.SizeOfImage, config.pattern);
    DBOUT(config.name << ": found " << pattern.size() << " matches");
    if (!pattern.size() || (config.expectedMatches && pattern.size() != config.expectedMatches))
        return false;

    size_t first = 0, last = pattern.size();
    if (config.matches != "all")
    {
        int match;
        try
        {
            match = (config.matches == "last" || config.matches == "end") ? static_cast<int>(pattern.size()) : std::stoi(config.matches);
        }
        catch (const std::exception&)
        {
            return false;
        }
        if (match < 1 || match > pattern.size()) return false;
        first = match - 1;
        last = match;
    }

    const auto value = BytesFromString(config.val);
    for (size_t i = first; i < last; ++i)
    {
        auto address = pattern.get(i).get<BYTE>(config.offset);
        const auto offset = reinterpret_cast<uintptr_t>(address) - base;
        if (offset > module.SizeOfImage || value.size() > module.SizeOfImage - offset)
            return false;
        Write write{address, value, {}};
        if (UserSettings::config.atomic)
        {
            write.original.resize(value.size());
            SIZE_T read;
            if (!ReadProcessMemory(GetCurrentProcess(), address, write.original.data(), value.size(), &read) || read != value.size())
                return false;
        }
        writes.push_back(std::move(write));
    }
    return true;
}

void GenericPatch::PatchAll(std::vector<Config> configs)
{
    std::vector<Write> writes;
    for (const auto& config : configs)
    {
        bool valid = false;
        try
        {
            valid = PlanPatch(config, writes);
        }
        catch (const std::exception& e)
        {
            DBOUT("Could not prepare " << config.name << ": " << e.what());
        }
        if (!valid)
        {
            DBOUT("Validation failed for " << config.name);
            if (UserSettings::config.atomic)
            {
                DBOUT("Atomic validation failed; no patches applied.");
                return;
            }
        }
        else if (!UserSettings::config.atomic)
        {
            for (const auto& write : writes)
                if (!Memory::Write(write.address, write.value.data(), write.value.size()))
                    DBOUT("Could not write patch " << config.name);
        }
        if (!UserSettings::config.atomic) writes.clear();
    }

    if (!UserSettings::config.atomic) return;
    for (size_t i = 0; i < writes.size(); ++i)
    {
        const auto& write = writes[i];
        if (Memory::Write(write.address, write.value.data(), write.value.size())) continue;
        DBOUT("Patch write failed; restoring original bytes.");
        for (size_t j = i + 1; j > 0; --j)
        {
            const auto& previous = writes[j - 1];
            if (!Memory::Write(previous.address, previous.original.data(), previous.original.size()))
                DBOUT("Could not restore bytes at " << static_cast<void*>(previous.address));
        }
        return;
    }
    DBOUT("Applied " << writes.size() << " writes after atomic validation.");
}
