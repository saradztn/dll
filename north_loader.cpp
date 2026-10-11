/**
* ============================================================================
* NORTH LOADER — Behavioral Reimplementation (Result Class R2)
* ============================================================================
* Target Architecture : x86 32-bit (PE32)
* ============================================================================
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")

bool EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool success = false;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            success = true;
    }
    CloseHandle(hToken);
    return success;
}

bool FileExists(const char *path)
{
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) return false;
    return true;
}

DWORD FindProcessByName(const char *exeName)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

DWORD FindThreadInProcess(DWORD pid)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    DWORD tid = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return tid;
}

typedef struct { DWORD pid; DWORD tid; } Ctx;

static BOOL CALLBACK EnumWindowsCb(HWND hWnd, LPARAM lp)
{
    Ctx *c = (Ctx *)lp;
    DWORD wpid = 0;
    GetWindowThreadProcessId(hWnd, &wpid);
    if (wpid == c->pid) {
        c->tid = GetWindowThreadProcessId(hWnd, NULL);
        return FALSE;
    }
    return TRUE;
}

DWORD FindWindowThreadInProcess(DWORD pid)
{
    Ctx ctx = { pid, 0 };
    EnumWindows(EnumWindowsCb, (LPARAM)&ctx);
    return ctx.tid;
}

struct SectionMapper {
    WORD numberOfSections;
    IMAGE_SECTION_HEADER *sections;
};

DWORD rva2off(struct SectionMapper *mapper, DWORD rva)
{
    for (WORD i = 0; i < mapper->numberOfSections; i++) {
        IMAGE_SECTION_HEADER *sec = &mapper->sections[i];
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize) {
            return (rva - sec->VirtualAddress) + sec->PointerToRawData;
        }
    }
    return 0;
}

bool FindExportRvaInFile(const char *dllPath, const char *exportName, DWORD *outRva)
{
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return false; }
    BYTE *pBase = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) { CloseHandle(hMap); CloseHandle(hFile); return false; }

    bool found = false;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pBase;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(pBase + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD exportDirRva = 0;
            if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                exportDirRva = ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                exportDirRva = ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

            WORD numSections = nt->FileHeader.NumberOfSections;
            IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)((BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

            struct SectionMapper mapper;
            mapper.numberOfSections = numSections;
            mapper.sections = sections;

            DWORD exportDirOff = rva2off(&mapper, exportDirRva);
            if (exportDirOff != 0) {
                IMAGE_EXPORT_DIRECTORY *expDir = (IMAGE_EXPORT_DIRECTORY *)(pBase + exportDirOff);
                DWORD namesOff = rva2off(&mapper, expDir->AddressOfNames);
                DWORD funcsOff = rva2off(&mapper, expDir->AddressOfFunctions);
                DWORD ordsOff  = rva2off(&mapper, expDir->AddressOfNameOrdinals);
                if (namesOff && funcsOff && ordsOff) {
                    DWORD *nameRvas = (DWORD *)(pBase + namesOff);
                    DWORD *funcRvas = (DWORD *)(pBase + funcsOff);
                    WORD  *ordinals = (WORD  *)(pBase + ordsOff);
                    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
                        DWORD nameOff = rva2off(&mapper, nameRvas[i]);
                        if (nameOff != 0) {
                            const char *curName = (const char *)(pBase + nameOff);
                            if (strcmp(curName, exportName) == 0) {
                                *outRva = funcRvas[ordinals[i]];
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return found;
}

bool IsModuleLoadedInProcess(DWORD pid, const char *moduleName)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    bool found = false;
    if (K32EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        if (count > 1024) count = 1024;
        for (DWORD i = 0; i < count; i++) {
            char baseName[MAX_PATH];
            baseName[0] = '\0';
            if (K32GetModuleBaseNameA(hProc, hMods[i], baseName, MAX_PATH)) {
                if (_stricmp(baseName, moduleName) == 0) { found = true; break; }
            }
        }
    }
    CloseHandle(hProc);
    return found;
}

int InjectClassic(DWORD pid, const char *dllPath)
{
    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE hProc = OpenProcess(desiredAccess, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        printf("[!] OpenProcess fallo (%lu).\n", err);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID pRemoteBuf = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        DWORD err = GetLastError();
        printf("[!] VirtualAllocEx fallo (%lu)\n", err);
        CloseHandle(hProc);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    if (!WriteProcessMemory(hProc, pRemoteBuf, dllPath, pathLen, NULL)) {
        DWORD err = GetLastError();
        printf("[!] WriteProcessMemory fallo (%lu)\n", err);
        VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLib = hKernel ? GetProcAddress(hKernel, "LoadLibraryA") : NULL;
    if (!pLoadLib) {
        printf("[!] No se resolvio LoadLibraryA\n");
        VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pRemoteBuf, 0, NULL);
    if (!hThread) {
        DWORD err = GetLastError();
        printf("[!] CreateRemoteThread fallo (%lu)\n", err);
        VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (err == ERROR_ACCESS_DENIED) ? 2 : 1;
    }

    DWORD remoteMod = 0;
    if (WaitForSingleObject(hThread, 15000) == WAIT_OBJECT_0)
        GetExitCodeThread(hThread, &remoteMod);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (remoteMod == 0) {
        printf("[!] LoadLibrary remoto devolvio NULL.\n");
        return 1;
    }
    printf("[+] Inyectado OK clasico (modulo=0x%08lX)\n", remoteMod);
    return 0;
}

bool InjectHook(DWORD pid, const char *dllPath)
{
    HMODULE hMod = LoadLibraryA(dllPath);
    HOOKPROC pfn = NULL;

    if (hMod != NULL) {
        pfn = (HOOKPROC)GetProcAddress(hMod, "NVXHookProc");
        if (!pfn) {
            printf("[!] El DLL no exporta NVXHookProc.\n");
            FreeLibrary(hMod);
            return false;
        }
    } else {
        printf("[*] LoadLibrary local fallo (%lu); mapeando sin ejecutar...\n", GetLastError());
        DWORD rva = 0;
        if (!FindExportRvaInFile(dllPath, "NVXHookProc", &rva)) {
            printf("[!] No se hallo el export NVXHookProc en el archivo.\n");
            return false;
        }
        hMod = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hMod) {
            printf("[!] Mapeo sin ejecutar fallo (%lu)\n", GetLastError());
            return false;
        }
        pfn = (HOOKPROC)((BYTE *)hMod + rva);
        printf("[*] Export NVXHookProc en RVA 0x%08lX\n", rva);
    }

    DWORD threadId = FindWindowThreadInProcess(pid);
    if (threadId == 0) {
        printf("[*] No window thread found, falling back to any thread...\n");
        threadId = FindThreadInProcess(pid);
    }
    if (threadId == 0) {
        printf("[!] No se hallo hilo en el proceso.\n");
        FreeLibrary(hMod);
        return false;
    }
    printf("[*] Target thread ID = %lu\n", threadId);

    const int kHookTypes[] = { WH_GETMESSAGE, WH_CALLWNDPROC, WH_CBT };
    const char *kHookNames[] = { "WH_GETMESSAGE", "WH_CALLWNDPROC", "WH_CBT" };

    const char *dllName = strrchr(dllPath, '\\');
    dllName = dllName ? dllName + 1 : dllPath;

    for (int attempt = 0; attempt < 3; ++attempt) {
        int hookType = kHookTypes[attempt];
        printf("[*] Trying hook type: %s\n", kHookNames[attempt]);

        HHOOK hHook = SetWindowsHookExA(hookType, pfn, hMod, threadId);
        if (!hHook) {
            printf("[!] SetWindowsHookEx(%s) fallo (%lu)\n", kHookNames[attempt], GetLastError());
            continue;
        }

        printf("[*] Hook instalado, despertando el hilo del juego...\n");
        for (int i = 0; i < 30; i++) {
            PostThreadMessageA(threadId, WM_NULL, 0, 0);
            PostThreadMessageA(threadId, WM_MOUSEMOVE, 0, 0);
            PostThreadMessageA(threadId, WM_ACTIVATE, WA_ACTIVE, 0);
            Sleep(100);
            if ((i % 5) == 4) {
                if (IsModuleLoadedInProcess(pid, dllName)) {
                    printf("[+] Modulo detectado en proceso tras %d intentos (hook=%s)\n",
                           i + 1, kHookNames[attempt]);
                    UnhookWindowsHookEx(hHook);
                    FreeLibrary(hMod);
                    printf("[+] Inyectado OK por hook (modulo verificado).\n");
                    return true;
                }
            }
        }
        UnhookWindowsHookEx(hHook);
    }

    FreeLibrary(hMod);
    if (IsModuleLoadedInProcess(pid, dllName)) {
        printf("[+] Modulo cargado en el proceso.\n");
        return true;
    }
    printf("[!] El modulo NO fue cargado tras todos los intentos.\n");
    return false;
}

void DiagnoseProcessAccess(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("[diag] OpenProcess(QUERY|READ) fallo (%lu)\n", GetLastError());
    } else {
        printf("[diag] OpenProcess(QUERY|READ) OK\n");
        CloseHandle(hProc);
    }

    HANDLE hProc2 = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProc2) {
        printf("[diag] OpenProcess(WRITE|OPERATION) fallo (%lu) - anti-cheat write protection ACTIVE\n", GetLastError());
    } else {
        printf("[diag] OpenProcess(WRITE|OPERATION) OK\n");
        CloseHandle(hProc2);
    }
}

int main(int argc, char *argv[])
{
    SetConsoleTitleA("NORTH Loader");

    const char *app = "gta_sa.exe";
    char dllPath[MAX_PATH];
    dllPath[0] = '\0';
    bool autoclose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--autoclose") == 0) autoclose = true;
        else if (strcmp(argv[i], "--proc") == 0 && i + 1 < argc) app = argv[++i];
        else if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc) strcpy_s(dllPath, sizeof(dllPath), argv[++i]);
        else if (argv[i][0] != '-' && dllPath[0] == '\0') {
            size_t len = strlen(argv[i]);
            if (len > 4 && _stricmp(argv[i] + len - 4, ".dll") == 0)
                strcpy_s(dllPath, sizeof(dllPath), argv[i]);
        }
    }

    if (dllPath[0] == '\0') {
        char self[MAX_PATH];
        self[0] = '\0';
        GetModuleFileNameA(NULL, self, MAX_PATH);
        char *lastSlash = strrchr(self, '\\');
        size_t dirLen = lastSlash ? (lastSlash - self) : 0;
        char base[MAX_PATH];
        base[0] = '\0';
        if (dirLen > 0 && dirLen < MAX_PATH - 14) {
            memcpy(base, self, dirLen);
            base[dirLen] = '\0';
            strcat_s(base, sizeof(base), "\\NRTH.dll");
            strcpy_s(dllPath, sizeof(dllPath), base);
        }
    }

    printf("=== NORTH Loader ===\n");
    printf("DLL : %s\n", dllPath[0] ? dllPath : "(no encontrado)");
    printf("APP : %s\n", app);

    EnableDebugPrivilege();

    if (!FileExists(dllPath)) {
        printf("[!] No existe el DLL.\n");
        if (!autoclose) { printf("ENTER para salir...\n"); getchar(); }
        return 1;
    }

    printf("[*] Esperando a %s (abre el juego DESPUES del loader)...\n", app);

    DWORD pid = 0;
    for (int attempt = 0; attempt < 600 && pid == 0; attempt++) {
        pid = FindProcessByName(app);
        if (pid == 0) Sleep(100);
    }

    if (pid == 0) {
        printf("[!] Tiempo agotado esperando el proceso.\n");
        if (!autoclose) { printf("ENTER para salir...\n"); getchar(); }
        return 1;
    }

    printf("[*] Proceso encontrado (PID %lu)\n", pid);
    DiagnoseProcessAccess(pid);

    printf("[*] Intentando metodo hook (mas compatible con anti-cheat)...\n");
    bool ok = InjectHook(pid, dllPath);

    if (!ok) {
        printf("[*] Hook fallo. Intentando metodo clasico...\n");
        int status = InjectClassic(pid, dllPath);
        ok = (status == 0);
    }

    if (!ok) {
        HMODULE hUser32 = LoadLibraryA("user32.dll");
        if (hUser32) {
            typedef int (WINAPI *PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
            PFN_MessageBoxA pMsgBox = (PFN_MessageBoxA)GetProcAddress(hUser32, "MessageBoxA");
            if (pMsgBox) {
                pMsgBox(NULL,
                        "Injection failed.\n"
                        "Anti-cheat blocked both methods.\n\n"
                        "Check the console for diagnostics.",
                        "NORTH Loader", MB_ICONERROR);
            }
        }
    }

    if (!autoclose) {
        printf("Pulsa ENTER para salir...\n");
        getchar();
    }
    return ok ? 0 : 1;
}