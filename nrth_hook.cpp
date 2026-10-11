/**
* ============================================================================
* NRTH.dll — Behavioral Reimplementation (Result Class R2)
* Reconstructed from reverse engineering of native x86 library "NRTH.dll"
* (SHA-256 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861)
* ============================================================================
* PURPOSE: authorized MTA:SA blue-team private-server validation ONLY.
*
* Evidence map (original VAs / RVAs):
* NVXHookProc VA 0x1000b9e0 (RVA 0x0b9e0) export ordinal 1
* DllMain VA 0x1000ba00 (RVA 0x0ba00) pin + init thread
* MainInitThread VA 0x1000a850 (RVA 0x0a850) MinHook on ntdll!LdrLoadDll
* Hooked_LdrLoadDll VA 0x1000a640 (RVA 0x0a640) trigger on client.dll/netc.dll
* FeatureInit1 VA 0x10005b80 (RVA 0x05b80) 11 pattern scans + 11 MH_CreateHook
* FeatureInit2 VA 0x10020640 (RVA 0x20640) 6 patches + 4 hooks
* GetD3D9DeviceVTable VA 0x10012980 (RVA 0x12980) d3d9 vtable
* InstallD3D9Hooks VA 0x10016500 (RVA 0x16500) Present idx 17 / Reset idx 16
* Hooked_Present VA 0x10014d50 (RVA 0x14d50) Dear ImGui overlay
* Hooked_Reset VA 0x1001a3c0 (RVA 0x1a3c0) device-loss handling
* LuaExecute VA 0x1013c94c (RVA 0x13c94c) game VM trampoline
* ============================================================================
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d9.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "MinHook.h"
#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include "nrth_hook.h"
#include "nrth_ui.h"

// ---------------------------------------------------------------------------
// Minimal NT types
// ---------------------------------------------------------------------------
typedef LONG NTSTATUS;
typedef struct _NVX_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NVX_UNICODE_STRING;

typedef NTSTATUS (NTAPI *PFN_LdrLoadDll)(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
typedef HRESULT (WINAPI *PFN_Present)(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
typedef HRESULT (WINAPI *PFN_Reset)(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
typedef IDirect3D9 *(WINAPI *PFN_Direct3DCreate9)(UINT);

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
static PFN_LdrLoadDll gp_OrigLdrLoadDll = NULL;
static PFN_Present    gp_OrigPresent    = NULL;
static PFN_Reset      gp_OrigReset      = NULL;
static bool           g_bMtaArmed       = false;
static bool           g_bOverlayInit    = false;
static bool           g_bMenuOpen       = false;
static IDirect3DDevice9 *g_pDevice      = NULL;
static HWND           g_hGameWnd        = NULL;
static WNDPROC        g_pOrigWndProc    = NULL;

static HMODULE g_hClientDll = NULL;
static HMODULE g_hNetcDll   = NULL;

#define MAX_FEATURE_HOOKS 11
#define MAX_NETC_HOOKS    4
static LPVOID g_pClientTargets[MAX_FEATURE_HOOKS]   = {0};
static LPVOID g_pNetcTargets[MAX_NETC_HOOKS]        = {0};
static LPVOID g_pClientOriginals[MAX_FEATURE_HOOKS] = {0};
static LPVOID g_pNetcOriginals[MAX_NETC_HOOKS]      = {0};

typedef int  (__cdecl *PFN_LuaExecute)(void *L, const char *code, size_t len, const char *chunkName);
typedef int  (__cdecl *PFN_LuaClose)(void *L, int, int, int);
static PFN_LuaExecute g_pfnLuaExecute = NULL;
static PFN_LuaClose   g_pfnLuaClose   = NULL;
static void          *g_pGameLuaState = NULL;

// ---------------------------------------------------------------------------
// Encrypted strings (positional XOR, keys 0x2D / 0x20)
// ---------------------------------------------------------------------------
static const uint8_t ct_client_dll[]  = { 0xb0, 0xb8, 0xbc, 0xb3, 0xb9, 0xac, 0xf7, 0xbe, 0xb7, 0xb0 };
static const uint8_t ct_netc_dll[]    = { 0x8e, 0x84, 0x96, 0x80, 0xca, 0x81, 0x8a, 0x8b };
static const uint8_t ct_d3d9_dll[]    = { 0x9a, 0x9d, 0x99, 0x94, 0xfa, 0x9a, 0x9d, 0x9d };
static const uint8_t ct_ntdll_dll[]   = { 0xb2, 0xbc, 0xba, 0xb9, 0xb9, 0xfa, 0x9a, 0x9d, 0x9d };
static const uint8_t ct_LdrLoadDll[]  = { 0x3f, 0x4b, 0x4b, 0x44, 0x4b, 0x40, 0x4b, 0x4b, 0x4b, 0x4b };
static const uint8_t ct_NVX_dir[]     = { 0x4e, 0x53, 0x5f, 0x83, 0x8a, 0x5f, 0x5f };

// ---------------------------------------------------------------------------
// Helper: decode encrypted string
// ---------------------------------------------------------------------------
static void DecodeString(const uint8_t *ct, size_t len, uint8_t key, char *out, size_t outCap)
{
    if (len >= outCap) len = outCap - 1;
    for (size_t i = 0; i < len; ++i) {
        out[i] = (char)(ct[i] ^ (uint8_t)(i - key));
    }
    out[len] = '\0';
}

// ---------------------------------------------------------------------------
// Pattern scanner (matches original resolver at 0x10002960)
// ---------------------------------------------------------------------------
typedef struct {
    uint8_t  bytes[256];
    uint8_t  mask[256];
    uint32_t len;
} Pattern;

static bool CompilePattern(const char *text, Pattern *p)
{
    p->len = 0;
    const char *s = text;
    while (*s && p->len < 256) {
        while (*s == ' ') s++;
        if (!*s) break;
        if (*s == '?') {
            p->bytes[p->len] = 0;
            p->mask[p->len]  = 0;
            p->len++;
            while (*s && *s != ' ') s++;
            continue;
        }
        int hi = -1, lo = -1;
        if (*s >= '0' && *s <= '9') hi = *s - '0';
        else if (*s >= 'A' && *s <= 'F') hi = *s - 'A' + 10;
        else if (*s >= 'a' && *s <= 'f') hi = *s - 'a' + 10;
        if (hi < 0) { s++; continue; }
        s++;
        if (*s && *s != ' ') {
            if (*s >= '0' && *s <= '9') lo = *s - '0';
            else if (*s >= 'A' && *s <= 'F') lo = *s - 'A' + 10;
            else if (*s >= 'a' && *s <= 'f') lo = *s - 'a' + 10;
            if (lo >= 0) s++;
        }
        p->bytes[p->len] = (uint8_t)((hi << 4) | (lo >= 0 ? lo : 0));
        p->mask[p->len]  = 0xFF;
        p->len++;
    }
    return p->len > 0;
}

static LPVOID ScanPattern(HMODULE hMod, const char *patternText)
{
    if (!hMod) return NULL;
    Pattern pat;
    if (!CompilePattern(patternText, &pat)) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    BYTE *base = (BYTE *)hMod;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE  *start = base + sec->VirtualAddress;
        SIZE_T size  = sec->Misc.VirtualSize;
        if (size < pat.len) continue;
        for (SIZE_T off = 0; off + pat.len <= size; ++off) {
            bool match = true;
            for (uint32_t j = 0; j < pat.len; ++j) {
                if (pat.mask[j] && start[off + j] != pat.bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return start + off;
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Exported hook procedure (ordinal 1)
// ---------------------------------------------------------------------------
extern "C" LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
static DWORD WINAPI MainInitThread(LPVOID lpParam);
static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
static void **GetD3D9DeviceVTable(void);
static bool InstallD3D9Hooks(void **vtable);
static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
static LRESULT CALLBACK GameWndProc(HWND, UINT, WPARAM, LPARAM);
static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice);
static void UpdateOverlayInput(void);
static const char *BaseNameA(const char *path);

static bool InstallClientFeatureHooks(HMODULE hClient);
static bool InstallNetcKillPatches(HMODULE hNetc);
static bool ResolveGameLuaVM(HMODULE hClient);

static void __cdecl Hook_FeatureAction(int idx);

// ===========================================================================
// DllMain — evidence VA 0x1000ba00
// ===========================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        HMODULE hPinned = NULL;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            (LPCSTR)DllMain,
            &hPinned);

        HANDLE hThread = CreateThread(NULL, 0, MainInitThread, hModule, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}

// ===========================================================================
// MainInitThread — evidence VA 0x1000a850
// ===========================================================================
static DWORD WINAPI MainInitThread(LPVOID lpParam)
{
    (void)lpParam;

    char nvxDir[64];
    DecodeString(ct_NVX_dir, sizeof(ct_NVX_dir), 0x2D, nvxDir, sizeof(nvxDir));
    DWORD attr = GetFileAttributesA(nvxDir);
    (void)attr;

    char ntdllName[32], ldrName[32];
    DecodeString(ct_ntdll_dll, sizeof(ct_ntdll_dll), 0x20, ntdllName, sizeof(ntdllName));
    DecodeString(ct_LdrLoadDll, sizeof(ct_LdrLoadDll), 0x20, ldrName, sizeof(ldrName));

    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    if (!hNtdll) return 1;
    FARPROC pLdrLoadDll = GetProcAddress(hNtdll, ldrName);
    if (!pLdrLoadDll) return 1;

    if (MH_Initialize() != MH_OK) return 1;
    if (MH_CreateHook((LPVOID)pLdrLoadDll, (LPVOID)&Hooked_LdrLoadDll, (LPVOID *)&gp_OrigLdrLoadDll) != MH_OK) return 1;
    if (MH_EnableHook((LPVOID)pLdrLoadDll) != MH_OK) return 1;
    return 0;
}

// ===========================================================================
// Hooked_LdrLoadDll — evidence VA 0x1000a640
// ===========================================================================
static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR SearchPath, PULONG DllCharacteristics,
                                        NVX_UNICODE_STRING *ModuleFileName, PVOID *DllHandle)
{
    NTSTATUS status = gp_OrigLdrLoadDll(SearchPath, DllCharacteristics, ModuleFileName, DllHandle);

    if (status >= 0 && DllHandle && *DllHandle) {
        char name[MAX_PATH] = {0};
        if (GetModuleFileNameA((HMODULE)*DllHandle, name, MAX_PATH) != 0) {
            const char *base = BaseNameA(name);

            char clientName[32], netcName[32];
            DecodeString(ct_client_dll, sizeof(ct_client_dll), 0x2D, clientName, sizeof(clientName));
            DecodeString(ct_netc_dll,   sizeof(ct_netc_dll),   0x20, netcName,   sizeof(netcName));

            if (_stricmp(base, clientName) == 0) {
                g_hClientDll = (HMODULE)*DllHandle;
                InstallClientFeatureHooks(g_hClientDll);
                ResolveGameLuaVM(g_hClientDll);
                NVX_SetClientModule(g_hClientDll);
                g_bMtaArmed = true;

                void **vtable = GetD3D9DeviceVTable();
                if (vtable) InstallD3D9Hooks(vtable);
            }
            else if (_stricmp(base, netcName) == 0) {
                g_hNetcDll = (HMODULE)*DllHandle;
                InstallNetcKillPatches(g_hNetcDll);
            }
        }
    }
    return status;
}

// ===========================================================================
// InstallClientFeatureHooks — evidence VA 0x10005b80
// ===========================================================================
static bool InstallClientFeatureHooks(HMODULE hClient)
{
    if (!hClient || g_pClientTargets[0] != NULL) return false;

    static const char *kClientPatterns[MAX_FEATURE_HOOKS] = {
        "55 8B EC 56 8B 75 ? 85 F6 75 ? 89 35",
        "55 8B EC 83 EC ? A1 ? ? ? ? 33 C5 89 45",
        "55 8B EC 83 EC ? 56 8B 75 ? 57 8B F9 85 F6",
        "55 8B EC 8B 45 ? A3 ? ? ? ? 8B 45 ? A3",
        "55 8B EC 56 8B F1 8B 0D ? ? ? ? 57 ? ? FF 50",
        "55 8B EC 51 53 56 57 8B 7D ? 85 FF 75",
        "55 8B EC 51 8B 45 ? 56 50",
        "55 8B EC 8B 45 ? 56 8B 70",
        "55 8B EC 56 FF 75 ? 8B 75 ? 56 E8",
        "55 8B EC 83 EC ? FF 75 ? FF 75 ? E8",
        "55 8B EC 56 8B 75 ? 8B 4E ? 8B 41 ? 3B 41",
    };

    static void *kHookStubs[MAX_FEATURE_HOOKS] = {
        (void*)Hook_FeatureAction, (void*)Hook_FeatureAction,
        (void*)Hook_FeatureAction, (void*)Hook_FeatureAction,
        (void*)Hook_FeatureAction, (void*)Hook_FeatureAction,
        (void*)Hook_FeatureAction, (void*)Hook_FeatureAction,
        (void*)Hook_FeatureAction, (void*)Hook_FeatureAction,
        (void*)Hook_FeatureAction,
    };

    int installed = 0;
    for (int i = 0; i < MAX_FEATURE_HOOKS; ++i) {
        LPVOID target = ScanPattern(hClient, kClientPatterns[i]);
        if (!target) continue;
        g_pClientTargets[i] = target;
        if (MH_CreateHook(target, kHookStubs[i], &g_pClientOriginals[i]) == MH_OK) {
            MH_EnableHook(target);
            installed++;
        }
    }
    return installed > 0;
}

// ===========================================================================
// InstallNetcKillPatches — evidence VA 0x10020640
// ===========================================================================
static bool InstallNetcKillPatches(HMODULE hNetc)
{
    if (!hNetc || g_pNetcTargets[0] != NULL) return false;

    static const char *kNetcPatterns[MAX_NETC_HOOKS] = {
        "55 8B EC 53 56 57 8B 7D ? 33 F6 32 DB",
        "55 8B EC 53 56 57 8B 7D",
        "55 8B EC 83 EC ? 53 56 57",
        "55 8B EC 8B 45 ? 85 C0",
    };
    static void *kNetcStubs[MAX_NETC_HOOKS] = {
        (void*)Hook_FeatureAction, (void*)Hook_FeatureAction,
        (void*)Hook_FeatureAction, (void*)Hook_FeatureAction,
    };

    int installed = 0;
    for (int i = 0; i < MAX_NETC_HOOKS; ++i) {
        LPVOID target = ScanPattern(hNetc, kNetcPatterns[i]);
        if (!target) continue;
        g_pNetcTargets[i] = target;
        if (MH_CreateHook(target, kNetcStubs[i], &g_pNetcOriginals[i]) == MH_OK) {
            MH_EnableHook(target);
            installed++;
        }
    }

    static const char *kPatchPatterns[6] = {
        "55 8B EC 83 EC ? 53 56 8B 75",
        "55 8B EC 83 EC ? 56 8B 75 ? 57",
        "55 8B EC 56 8B 75 ? 85 F6 75",
        "55 8B EC 8B 45 ? 85 C0 74",
        "55 8B EC 83 EC ? 53 8B 5D",
        "55 8B EC 56 8B 75 ? 83 EC",
    };
    for (int i = 0; i < 6; ++i) {
        LPVOID target = ScanPattern(hNetc, kPatchPatterns[i]);
        if (!target) continue;
        DWORD oldProtect = 0;
        if (VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *(BYTE *)target = 0xC3;
            VirtualProtect(target, 1, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), target, 1);
        }
    }
    return installed > 0;
}

// ===========================================================================
// ResolveGameLuaVM — locate game's Lua state and trampoline
// ===========================================================================
static bool ResolveGameLuaVM(HMODULE hClient)
{
    if (!hClient || g_pGameLuaState) return false;

    static const char *kLuaTrampolinePattern =
        "55 8B EC 83 EC ? 53 56 57 8B 7D ? 85 FF 75 ? 33 C0";
    LPVOID trampoline = ScanPattern(hClient, kLuaTrampolinePattern);
    if (!trampoline) return false;
    g_pfnLuaExecute = (PFN_LuaExecute)trampoline;

    static const char *kLuaStatePattern = "A1 ? ? ? ? 8B 4D ? 50 51 E8";
    LPVOID stateRef = ScanPattern(hClient, kLuaStatePattern);
    if (stateRef) {
        DWORD stateAddr = *(DWORD *)((BYTE *)stateRef + 1);
        if (stateAddr > 0x10000000 && stateAddr < 0x80000000)
            g_pGameLuaState = *(void **)stateAddr;
    }
    return g_pfnLuaExecute != NULL;
}

// ===========================================================================
// Feature hook stub
// ===========================================================================
static volatile LONG g_FeatureCallCount = 0;

static void __cdecl Hook_FeatureAction(int idx)
{
    InterlockedIncrement(&g_FeatureCallCount);
    (void)idx;
}

// ===========================================================================
// GetD3D9DeviceVTable — evidence VA 0x10012980
// ===========================================================================
static void **GetD3D9DeviceVTable(void)
{
    static void **pCachedVTable = NULL;
    if (pCachedVTable) return pCachedVTable;

    char d3d9Name[16];
    DecodeString(ct_d3d9_dll, sizeof(ct_d3d9_dll), 0x20, d3d9Name, sizeof(d3d9Name));

    HMODULE hD3D = GetModuleHandleA(d3d9Name);
    if (!hD3D) hD3D = LoadLibraryA(d3d9Name);
    if (!hD3D) return NULL;

    static const char *kVtablePatterns[] = {
        "C7 06 ? ? ? ? 8B 46 ? 89 86 ? ? ? ? 8B 46",
        "89 86 ? ? ? ? 8B 46 ? 89 86",
    };
    for (int i = 0; i < 2; ++i) {
        LPVOID site = ScanPattern(hD3D, kVtablePatterns[i]);
        if (site && *(BYTE *)site == 0xC7) {
            DWORD vtableAddr = *(DWORD *)((BYTE *)site + 2);
            if (vtableAddr > 0x10000000) {
                pCachedVTable = (void **)vtableAddr;
                return pCachedVTable;
            }
        }
    }

    PFN_Direct3DCreate9 pCreate = (PFN_Direct3DCreate9)GetProcAddress(hD3D, "Direct3DCreate9");
    if (!pCreate) return NULL;

    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = DefWindowProcA;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = "NVXD3DDummyWnd";
    RegisterClassA(&wc);
    HWND hWnd = CreateWindowExA(0, wc.lpszClassName, "", WS_OVERLAPPED,
                                0, 0, 32, 32, NULL, NULL, wc.hInstance, NULL);
    if (!hWnd) return NULL;

    IDirect3D9 *pD3D = pCreate(D3D_SDK_VERSION);
    if (!pD3D) { DestroyWindow(hWnd); return NULL; }

    D3DPRESENT_PARAMETERS pp;
    ZeroMemory(&pp, sizeof(pp));
    pp.Windowed   = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hWnd;

    IDirect3DDevice9 *pDev = NULL;
    HRESULT hr = pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd,
                                    D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &pDev);
    if (FAILED(hr) || !pDev) {
        pD3D->Release();
        DestroyWindow(hWnd);
        return NULL;
    }

    pCachedVTable = *(void ***)pDev;
    pDev->Release();
    pD3D->Release();
    DestroyWindow(hWnd);
    UnregisterClassA(wc.lpszClassName, wc.hInstance);
    return pCachedVTable;
}

// ===========================================================================
// InstallD3D9Hooks — evidence VA 0x10016500
// ===========================================================================
static bool InstallD3D9Hooks(void **vtable)
{
    if (!vtable) return false;
    if (MH_CreateHook(vtable[17], (LPVOID)&Hooked_Present, (LPVOID *)&gp_OrigPresent) != MH_OK) return false;
    if (MH_CreateHook(vtable[16], (LPVOID)&Hooked_Reset,   (LPVOID *)&gp_OrigReset)   != MH_OK) return false;
    MH_EnableHook(vtable[17]);
    MH_EnableHook(vtable[16]);
    return true;
}

// ===========================================================================
// ImGui overlay
// ===========================================================================
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT CALLBACK GameWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return 1;
    return CallWindowProcA(g_pOrigWndProc, hWnd, msg, wParam, lParam);
}

static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice)
{
    if (g_bOverlayInit) return;
    g_pDevice  = pDevice;
    g_hGameWnd = GetForegroundWindow();
    if (!g_hGameWnd) return;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    NrthUI_ApplyTheme();
    ImGui_ImplWin32_Init(g_hGameWnd);
    ImGui_ImplDX9_Init(pDevice);
    g_pOrigWndProc = (WNDPROC)SetWindowLongA(g_hGameWnd, GWL_WNDPROC, (LONG)GameWndProc);
    g_bOverlayInit = true;
}

static void UpdateOverlayInput(void)
{
    ImGuiIO &io = ImGui::GetIO();
    if (!g_bMenuOpen) { io.MouseDrawCursor = false; return; }
    io.MouseDrawCursor = true;
    POINT pt;
    if (GetCursorPos(&pt) && g_hGameWnd) {
        ScreenToClient(g_hGameWnd, &pt);
        io.MousePos = ImVec2((float)pt.x, (float)pt.y);
    }
    io.MouseDown[0] = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    io.MouseDown[1] = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
    io.MouseDown[2] = (GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0;
}

// ===========================================================================
// Hooked_Present — evidence VA 0x10014d50
// ===========================================================================
static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *pDevice, const RECT *pSrc,
                                     const RECT *pDest, HWND hDestWindow, const RGNDATA *pDirty)
{
    EnsureOverlayInitialized(pDevice);
    if (g_bOverlayInit) {
        bool wasOpen = g_bMenuOpen;
        if (GetAsyncKeyState(VK_INSERT) & 1) g_bMenuOpen = !g_bMenuOpen;
        if (g_bMenuOpen != wasOpen) {
            if (g_bMenuOpen) {
                while (ShowCursor(TRUE) < 0) {}
                ClipCursor(NULL);
                ReleaseCapture();
            } else {
                while (ShowCursor(FALSE) >= 0) {}
            }
        }
        UpdateOverlayInput();
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        if (g_bMenuOpen) NrthUI_Build();
        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    }
    return gp_OrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
}

// ===========================================================================
// Hooked_Reset — evidence VA 0x1001a3c0
// ===========================================================================
static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *pDevice, D3DPRESENT_PARAMETERS *pParams)
{
    if (g_bOverlayInit) ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = gp_OrigReset(pDevice, pParams);
    if (SUCCEEDED(hr) && g_bOverlayInit) ImGui_ImplDX9_CreateDeviceObjects();
    return hr;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const char *BaseNameA(const char *path)
{
    const char *slash = strrchr(path, '\\');
    return slash ? slash + 1 : path;
}

// ===========================================================================
// Public API for Lua execution through game VM
// ===========================================================================
extern "C" bool NVX_ExecuteGameLua(const char *code, size_t len, const char *chunkName)
{
    if (!g_pfnLuaExecute || !g_pGameLuaState) return false;
    int rc = g_pfnLuaExecute(g_pGameLuaState, code, len, chunkName ? chunkName : "@custom");
    if (rc == 0 && g_pfnLuaClose) {
        g_pfnLuaClose(g_pGameLuaState, 0, 0, 0);
    }
    return rc == 0;
}

extern "C" bool NVX_HasGameLuaVM(void)
{
    return g_pfnLuaExecute != NULL && g_pGameLuaState != NULL;
}