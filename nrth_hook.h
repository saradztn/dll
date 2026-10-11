#pragma once
/**
* ============================================================================
* NRTH.dll — Interface & Hook Reconstruction Header (Result Class R2)
* ============================================================================
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Exported hook procedure required by SetWindowsHookEx injection mechanism.
LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam);

// Lua VM bridge — implemented in nrth_hook.cpp, called from nrth_ui.cpp.
bool NVX_ExecuteGameLua(const char *code, size_t len, const char *chunkName);
bool NVX_HasGameLuaVM(void);
void NVX_SetClientModule(HMODULE h);

#ifdef __cplusplus
}
#endif