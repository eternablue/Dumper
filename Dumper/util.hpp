#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>

uint64_t get_pid_by_name(const char* process_name)
{
    PROCESSENTRY32 process_entry;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &process_entry))
    {
        do {
            if (!strcmp(process_entry.szExeFile, process_name))
            {
                CloseHandle(hSnapshot);
                return (uint64_t)process_entry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &process_entry));
    }
    CloseHandle(hSnapshot);
    return 0;
}

uint64_t get_module_base(uint64_t process_id)
{
    MODULEENTRY32 module_entry;
    module_entry.dwSize = sizeof(MODULEENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;
    
    Module32First(hSnapshot, &module_entry);
    return (uint64_t)module_entry.modBaseAddr;
}