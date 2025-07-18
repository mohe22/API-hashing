#pragma once
#include <Windows.h>

// Computes a custom hash for a given function name
DWORD CalculateHash(const char *functionName);

// Resolves a function address by comparing hashed export names
FARPROC ResolveFunctionByHash(const char *moduleName, DWORD targetHash);
 