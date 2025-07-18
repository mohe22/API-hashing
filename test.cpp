#include <windows.h>
#include <iostream>
#include "HashResolver.h"

typedef LPVOID(WINAPI *pVirtualAlloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect);
typedef BOOL(WINAPI *pVirtualFree_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType);

int main()
{

    

    FARPROC fnVirt = ResolveFunctionByHash("kernel32.dll", 14736063); // Hash for "VirtualAlloc"
    FARPROC fnfree = ResolveFunctionByHash("kernel32.dll", 423330); // Hash for "VirtualFree"
    if (!fnVirt || !fnfree)
    {
        std::cerr << "Failed to resolve functions." << std::endl;
        return 1;
    }
    pVirtualAlloc_t VirtualAlloc_ = (pVirtualAlloc_t)fnVirt;
    pVirtualFree_t VirtualFree_ = (pVirtualFree_t)fnfree  ;
    

    SIZE_T size = 1024; // 1 KB
    LPVOID allocatedMemory = VirtualAlloc_(
        NULL,                     // Let system decide the address
        size,                     // Size of memory to allocate
        MEM_COMMIT | MEM_RESERVE, // Allocate committed + reserved memory
        PAGE_READWRITE            // Allow read/write access
    );

    if (allocatedMemory == NULL)
    {
        std::cerr << "Memory allocation failed! Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Memory allocated at: " << allocatedMemory << std::endl;

    // Write something to the memory
    strcpy_s((char *)allocatedMemory, size, "Hello, VirtualAlloc!");

    // Print it back
    std::cout << "Content: " << (char *)allocatedMemory << std::endl;

    // Free the allocated memory
    if (!VirtualFree_(allocatedMemory, 0, MEM_RELEASE))
    {
        std::cerr << "Memory free failed! Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Memory successfully freed." << std::endl;
    return 0;
}
