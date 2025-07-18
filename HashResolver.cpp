#include "HashResolver.h"
#include <windows.h>
#include <iostream>

// Typedef for LoadLibraryA
typedef HMODULE(WINAPI *pLoadLibraryA_t)(LPCSTR);

// Custom hash function for obfuscation
DWORD CalculateHash(const char *functionName)
{
    DWORD hash = 0x35;
    while (*functionName)
    {
        hash = (hash * 0xAB10F29F) + (*functionName);
        hash &= 0xFFFFFF;
        functionName++;
    }
    return hash;
}

// resolution of LoadLibraryA (resolved once)
pLoadLibraryA_t ResolveLoadLibraryA()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
        return nullptr;

    auto dosHeader = (PIMAGE_DOS_HEADER)hKernel32;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hKernel32 + dosHeader->e_lfanew);
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA)
        return nullptr;

    auto exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hKernel32 + exportDirRVA);
    DWORD *namesRVA = (DWORD *)((BYTE *)hKernel32 + exportDir->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)hKernel32 + exportDir->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)hKernel32 + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char *funcName = (const char *)((BYTE *)hKernel32 + namesRVA[i]);
        if (CalculateHash(funcName) == 6943297)
        { // Precomputed LoadLibraryA hash
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            return (pLoadLibraryA_t)((BYTE *)hKernel32 + funcRVA);
        }
    }

    return nullptr;
}

// Global resolved LoadLibraryA function pointer
static pLoadLibraryA_t pLoadLibraryA = ResolveLoadLibraryA();

// Function to resolve any function by hash
FARPROC ResolveFunctionByHash(const char *moduleName, DWORD targetHash)
{
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule && pLoadLibraryA)
    {
        hModule = pLoadLibraryA(moduleName);
        if (!hModule)
        {
            std::cout << "[-] Failed to load module: " << moduleName << std::endl;
            return nullptr;
        }
    }

    if (!hModule)
        return nullptr;

    auto dosHeader = (PIMAGE_DOS_HEADER)hModule;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHeader->e_lfanew);
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA)
        return nullptr;

    auto exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule + exportDirRVA);
    DWORD *namesRVA = (DWORD *)((BYTE *)hModule + exportDir->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)hModule + exportDir->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char *funcName = (const char *)((BYTE *)hModule + namesRVA[i]);
        if (CalculateHash(funcName) == targetHash)
        {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            return (FARPROC)((BYTE *)hModule + funcRVA);
        }
    }

    return nullptr;
}
