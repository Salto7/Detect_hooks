#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include <dbghelp.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#define SYSCALL_STUB_SIZE 4 // The typical size of syscall stub
#define HOOK_CHECK_SIZE 16   // Read more bytes for jump detection

void debug_print(const char* format, ...) {
    /*va_list args;
    va_start(args, format);
    printf( format, args);
    */
    FILE* file = NULL;
    fopen_s(&file, "mylog.txt", "a");

    if (file == NULL) {
        printf("Error opening file\n");
        return;
    }
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
    fclose(file);
}
void* GetModuleBase(LPCSTR moduleName) {
    return (void*)GetModuleHandleA(moduleName);
}

BOOL IsHooked(LPVOID funcAddr) {
    BYTE* code = (BYTE*)funcAddr;

    if (code[0] != 0x4C || code[1] != 0x8B || code[2] != 0xD1) {
        // mov r10, rcx missing
        return TRUE;
    }

    if (code[3] == 0xE9 || code[3] == 0xE8) {
        // jmp or call after mov r10, rcx —> HOOKED
        return TRUE;
    }

    if (code[3] != 0xB8) {
        // Expect mov eax, syscall_number
        return TRUE;
    }

    return FALSE; // Looks normal
}

void ResolveHookTarget(LPVOID funcAddr) {
    BYTE* code = (BYTE*)funcAddr;
    BYTE* patch = code + 3; // assuming, it comes after mov r10, rcx

    if (patch[0] == 0xE9) {
        // Detected relative jump
		//destination = (address after the jump instruction (ie after E9, which is a signed 32bit value) + relative offset since its a relative jump

        INT32 offset = *(INT32*)(patch + 1);
        BYTE* destination = patch + 5 + offset;

        debug_print("    -> Relative jump to 0x%p\n", destination);

        // Resolve target module
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                MODULEINFO modInfo;
                char szModName[MAX_PATH];
                GetModuleInformation(GetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo));
                GetModuleBaseNameA(GetCurrentProcess(), hMods[i], szModName, sizeof(szModName));
				//find which module it belongs to
                if ((uintptr_t)destination >= (uintptr_t)modInfo.lpBaseOfDll &&
                    (uintptr_t)destination <= (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

                    char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
                    SYMBOL_INFO* symbol = (SYMBOL_INFO*)symbolBuffer;
                    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                    symbol->MaxNameLen = MAX_SYM_NAME;

                    DWORD64 displacement = 0;
                    if (SymFromAddr(GetCurrentProcess(), (DWORD64)destination, &displacement, symbol)) {
                        debug_print("    -> Patch points to %s!%s\n", szModName, symbol->Name);
                    }
                    else {
                        debug_print("    -> Patch points to %s!<unknown symbol>\n", szModName);
                    }
                    return;
                }
            }
        }
    }
    else {
        debug_print("    -> Unknown patch at offset 3 (opcode 0x%02X)\n", patch[0]);
    }
}


void WalkNtdllNtZwFunctions() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        debug_print("[-] Failed to get main handle.\n");
        return;
    }

    ULONG size = 0;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
        hNtdll, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    if (!exportDir) {
        debug_print("[-] Failed to get export.\n");
        return;
    }

    DWORD* names = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)hNtdll + exportDir->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)hNtdll + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = (char*)hNtdll + names[i];

        if (strncmp(funcName, "Nt", 2) == 0) {
            LPVOID funcAddr = (BYTE*)hNtdll + functions[ordinals[i]];

            if (IsHooked(funcAddr)) {
                debug_print("[*] patch in: %s\n", funcName);
                ResolveHookTarget(funcAddr);
            }
        }
    }
}

int main() {
	//try to load more symbols
    if (SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
        WalkNtdllNtZwFunctions();
        SymCleanup(GetCurrentProcess());
    }
    else {
        debug_print("[-] Failed to initialize symbols.\n");
    }

    return 0;
}
extern "C" __declspec(dllexport) void debug_Exceptions() {
    main();
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        break;
    }
    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
