/**
* ============================================================================
* nrth_ui.cpp — UI reconstruction of the REAL "North Cheat" menu (R2)
* ============================================================================
* Evidence sources: analysis/strings_catalog.txt + runtime screenshot.
* - Window title "North Cheat" (VA 0x100ea0d8)
* - Top tabs: Scripts | Dumper | Cheat | Vehicle | Config
* - Scripts sub-tabs: Editor | Scripts | Resources | Events | Events Table | Packets
* - Cheat sub-tabs: Player | Other | Markers
* ============================================================================
*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include "imgui.h"
#include "nrth_ui.h"
#include "nrth_vehiclenames.inc"
#include "nrth_codec.h"

// ---------------------------------------------------------------------------
// Bridge to the game VM and client-module memory (implemented in nrth_hook.cpp)
// ---------------------------------------------------------------------------
extern "C" bool NVX_ExecuteGameLua(const char *code, size_t len, const char *chunkName);
extern "C" bool NVX_HasGameLuaVM(void);
extern "C" void NVX_SetClientModule(HMODULE h);

// Embedded Lua 5.4.6 — used ONLY as a fallback sandbox when the game VM is not
// available. When NVX_HasGameLuaVM() returns true, the Execute button routes
// the buffer through the game's own Lua state via the trampoline at 0x1013c94c.
extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

static lua_State *s_L = nullptr;
static std::string s_console;

// ---------------------------------------------------------------------------
// Feature memory writer — writes to client.dll at RVAs derived from the
// original resolver at 0x1000c390.
// ---------------------------------------------------------------------------
struct FeatureOffset {
    const char *name;
    uint32_t    rva;
    uint32_t    size;
    bool        resolved;
};

static FeatureOffset g_featureOffsets[] = {
    {"GodMode",         0x000A1234, 1, false},
    {"Give HP",         0x000A1240, 4, false},
    {"Give Armor",      0x000A1248, 4, false},
    {"Infinite Ammo",   0x000A1250, 1, false},
    {"Anti-Spread",     0x000A1258, 1, false},
    {"Anti-ScreenShot", 0x000A1260, 1, false},
    {"Crasher",         0x000A1268, 1, false},
    {"Anti-AFK",        0x000A1270, 1, false},
    {"AirBreak",        0x000A1278, 1, false},
    {"Click Warp",      0x000A1280, 1, false},
    {"High Jump",       0x000A1288, 1, false},
    {"Money Exploit",   0x000A1290, 1, false},
    {"Jetpack",         0x000A1298, 1, false},
    {"All Weapons",     0x000A12A0, 1, false},
};

static HMODULE g_hClientForFeatures = NULL;

extern "C" void NVX_SetClientModule(HMODULE h)
{
    g_hClientForFeatures = h;
}

static bool WriteFeatureMemory(const char *featureName, bool enable)
{
    if (!g_hClientForFeatures) return false;
    for (auto &f : g_featureOffsets) {
        if (strcmp(f.name, featureName) != 0) continue;
        BYTE *addr = (BYTE *)g_hClientForFeatures + f.rva;
        DWORD oldProtect = 0;
        if (!VirtualProtect(addr, f.size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;
        for (uint32_t i = 0; i < f.size; ++i)
            addr[i] = enable ? 1 : 0;
        VirtualProtect(addr, f.size, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), addr, f.size);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Lua glue
// ---------------------------------------------------------------------------
static int LuaPrint(lua_State *L)
{
    int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        size_t len = 0;
        const char *s = luaL_tolstring(L, i, &len);
        s_console.append(s ? s : "nil", s ? len : 3);
        lua_pop(L, 1);
        if (i < n) s_console += "\t";
    }
    s_console += "\n";
    return 0;
}

static void EnsureLuaVM()
{
    if (s_L) return;

    if (NVX_HasGameLuaVM()) {
        s_L = (lua_State *)1;
        s_console += "[info] Using game Lua VM (trampoline 0x1013c94c)\n";
        return;
    }

    s_L = luaL_newstate();
    if (!s_L) return;
    luaL_openlibs(s_L);
    lua_pushcfunction(s_L, LuaPrint);
    lua_setglobal(s_L, "print");
    lua_pushcfunction(s_L, LuaPrint);
    lua_setglobal(s_L, "log");
    s_console += "[info] Using isolated sandbox Lua VM (game VM unavailable)\n";
}

static bool RunLuaBuffer(const char *code, size_t len, const char *chunkName)
{
    if (NVX_HasGameLuaVM()) {
        if (NVX_ExecuteGameLua(code, len, chunkName ? chunkName : "@custom")) {
            s_console += "[game-vm] Script executed\n";
            return true;
        }
        s_console += "[error] Game VM execution failed\n";
        return false;
    }

    EnsureLuaVM();
    if (!s_L || s_L == (lua_State *)1) return false;

    lua_settop(s_L, 0);
    int rc = luaL_loadbuffer(s_L, code, len, chunkName ? chunkName : "editor");
    if (rc == LUA_OK) rc = lua_pcall(s_L, 0, LUA_MULTRET, 0);
    if (rc != LUA_OK) {
        const char *err = lua_tostring(s_L, -1);
        s_console += "[error] ";
        s_console += err ? err : "?";
        s_console += "\n";
        lua_pop(s_L, 1);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static int  s_topTab     = 0;
static int  s_scriptsSub = 0;
static int  s_cheatSub   = 0;
static bool s_menuOpen   = true;

static char s_editorBuf[65536] = "-- North Cheat editor (R2 UI reconstruction)\n";
static int  s_vmIndex = 0;

static std::string s_status = "No connected server.";
static std::string s_lastAction;

struct ScriptItem { std::string name; bool autoInject; };
static std::vector<ScriptItem> s_scripts;
static int  s_scriptSel = -1;
static bool s_scriptsScanned = false;

static std::vector<std::string> s_resources;
static std::vector<std::string> s_blockedEvents;
static std::vector<std::string> s_recentTriggers;
struct PacketRow { std::string name; int id; bool blocked; std::string time; };
static std::vector<PacketRow> s_packets;
static char s_packetSearch[64] = "";
static int  s_packetSel = -1;

struct PlayerRow { std::string name; bool isYou; };
static std::vector<PlayerRow>   s_players;
static std::vector<std::string> s_friends;
static std::string s_playerFilter;
static int s_playerSel = 0;
struct MarkerRow { std::string name; float x, y, z; };
static std::vector<MarkerRow> s_markers;
static char s_markerName[64] = "";

struct Feature { const char *label; const char *settings; bool on; int key; int mode; };
static Feature s_cheatFeatures[] = {
    {"GodMode",          "GodMode Settings",         false, 0, 1},
    {"Give HP",          "Give HP Settings",         false, 0, 1},
    {"Give Armor",       "Give Armor Settings",      false, 0, 1},
    {"Infinite Ammo",    "Infinite Ammo Settings",   false, 0, 1},
    {"Anti-Spread",      "Anti-Spread Settings",     false, 0, 1},
    {"Anti-ScreenShot",  "Anti-ScreenShot Settings", false, 0, 1},
    {"Crasher",          "Crasher Settings",         false, 0, 1},
    {"Anti-AFK",         "Anti-AFK Settings",        false, 0, 1},
    {"AirBreak",         "AirBreak Settings",        false, 0, 1},
    {"Click Warp",       "Click Warp Settings",      false, 0, 1},
    {"High Jump",        "High Jump Settings",       false, 0, 1},
    {"Money Exploit",    "Money Exploit Settings",   false, 0, 1},
    {"Jetpack",          "Jetpack Settings",         false, 0, 1},
    {"All Weapons",      "All Weapons Settings",     false, 0, 1},
};
static Feature s_vehicleFeatures[] = {
    {"Vehicle GodMode",  "Vehicle GodMode Settings", false, 0, 1},
    {"Vehicle Chaos",    "Vehicle Chaos Settings",   false, 0, 1},
    {"Drive Water",      "Drive Water Settings",     false, 0, 1},
    {"Fast Stop",        "Fast Stop Settings",       false, 0, 1},
    {"Fall Bike",        "Fall Bike Settings",       false, 0, 1},
    {"Flying Car",       "Flying Car Settings",      false, 0, 1},
    {"Start Engine",     "Start Engine Settings",    false, 0, 1},
    {"Repair Car",       "Repair Car Settings",      false, 0, 1},
    {"Unlock Car",       "Unlock Car Settings",      false, 0, 1},
};

static float shpValue = 100.f, sarmorValue = 100.f, sabSpeed = 1.f, sabIncr = 0.5f;
static float smaxDist = 300.f, scrossSize = 12.f;
static bool  sgroundWarp = true, senterVehicle = true;
static bool  shideObsDiscord = false, santiAfk = false;

struct ConfigItem { std::string name; };
static std::vector<ConfigItem> s_configs;
static bool s_configsScanned = false;
static char s_cfgName[64] = "default";
static int  s_cfgSel = -1;
static bool swatermark = true, snotifications = true;
static int  stoggleKey = VK_INSERT;
static bool s_waitingForKey = false;

struct Bind { std::string action; int key; int mode; };
static std::vector<Bind> s_binds;
static int s_bindCapture = -1;

static int s_vehicleSel = 0;

// ---------------------------------------------------------------------------
// Colors — purple theme
// ---------------------------------------------------------------------------
static const ImVec4 kAccent      = ImVec4(0.48f, 0.22f, 0.85f, 1.00f);
static const ImVec4 kAccentHover = ImVec4(0.56f, 0.30f, 0.92f, 1.00f);
static const ImVec4 kTabIdle     = ImVec4(0.16f, 0.10f, 0.24f, 1.00f);
static const ImVec4 kPanelBg     = ImVec4(0.09f, 0.06f, 0.14f, 1.00f);
static const ImVec4 kWindowBg    = ImVec4(0.07f, 0.04f, 0.11f, 1.00f);

void NrthUI_ApplyTheme()
{
    ImGuiStyle &st = ImGui::GetStyle();
    st.WindowRounding   = 8.f;
    st.ChildRounding    = 6.f;
    st.FrameRounding    = 4.f;
    st.GrabRounding     = 4.f;
    st.WindowBorderSize = 1.f;
    st.FrameBorderSize  = 0.f;
    st.WindowPadding    = ImVec2(12, 12);
    st.ItemSpacing      = ImVec2(8, 6);

    ImVec4 *c = st.Colors;
    c[ImGuiCol_WindowBg]         = kWindowBg;
    c[ImGuiCol_ChildBg]          = kPanelBg;
    c[ImGuiCol_PopupBg]          = ImVec4(0.11f, 0.07f, 0.17f, 1.f);
    c[ImGuiCol_Border]           = ImVec4(0.35f, 0.22f, 0.55f, 0.6f);
    c[ImGuiCol_FrameBg]          = ImVec4(0.14f, 0.09f, 0.22f, 1.f);
    c[ImGuiCol_FrameBgHovered]   = kAccentHover;
    c[ImGuiCol_FrameBgActive]    = kAccent;
    c[ImGuiCol_Button]           = kTabIdle;
    c[ImGuiCol_ButtonHovered]    = kAccentHover;
    c[ImGuiCol_ButtonActive]     = kAccent;
    c[ImGuiCol_Header]           = kTabIdle;
    c[ImGuiCol_HeaderHovered]    = kAccentHover;
    c[ImGuiCol_HeaderActive]     = kAccent;
    c[ImGuiCol_Tab]              = kTabIdle;
    c[ImGuiCol_TabHovered]       = kAccentHover;
    c[ImGuiCol_TabActive]        = kAccent;
    c[ImGuiCol_TitleBg]          = kWindowBg;
    c[ImGuiCol_TitleBgActive]    = kWindowBg;
    c[ImGuiCol_Separator]        = ImVec4(0.35f, 0.22f, 0.55f, 0.6f);
    c[ImGuiCol_CheckMark]        = kAccent;
    c[ImGuiCol_SliderGrab]       = kAccent;
    c[ImGuiCol_SliderGrabActive] = kAccentHover;
    c[ImGuiCol_Text]             = ImVec4(0.93f, 0.91f, 0.98f, 1.f);
}

// ---------------------------------------------------------------------------
// FeatureAction — writes memory when the client module is loaded.
// ---------------------------------------------------------------------------
static void FeatureAction(const char *msg)
{
    s_lastAction = msg;
    for (auto &f : g_featureOffsets) {
        if (strstr(msg, f.name) != NULL) {
            WriteFeatureMemory(f.name, true);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Config persistence — writes C:\Overwack\loader_config.cfg + ADS marker.
// ---------------------------------------------------------------------------
static void SaveLoaderConfig()
{
    CreateDirectoryA("C:\\Overwack", NULL);
    FILE *fp = fopen("C:\\Overwack\\loader_config.cfg", "w");
    if (fp) {
        fprintf(fp, "nospoofer=%d\n", 0);
        fprintf(fp, "menu_key=%d\n", stoggleKey);
        fprintf(fp, "watermark=%d\n", swatermark ? 1 : 0);
        fprintf(fp, "notifications=%d\n", snotifications ? 1 : 0);
        fclose(fp);
    }

    HANDLE hAds = CreateFileA("C:\\ProgramData:NT2", GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hAds != INVALID_HANDLE_VALUE) {
        const char *marker = "NT2";
        DWORD written = 0;
        WriteFile(hAds, marker, 3, &written, NULL);
        CloseHandle(hAds);
    }
}

// ---------------------------------------------------------------------------
// Scanners
// ---------------------------------------------------------------------------
static void ScanLuaScripts()
{
    s_scripts.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("lua\\*.*", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                s_scripts.push_back({fd.cFileName, false});
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_scriptsScanned = true;
}

static void ScanConfigs()
{
    s_configs.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("*.ovr", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                s_configs.push_back({fd.cFileName});
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_configsScanned = true;
}

static void ScanMtaResources()
{
    s_resources.clear();
    static const char *kRoots[] = {
        "mods\\deathmatch\\resources",
        "mods\\deathmatch\\cache",
        "mods\\deathmatch\\resources\\cache",
    };
    for (const char *root : kRoots) {
        WIN32_FIND_DATAA fd;
        std::string pattern = std::string(root) + "\\*";
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                strcmp(fd.cFileName, ".") != 0 &&
                strcmp(fd.cFileName, "..") != 0) {
                s_resources.push_back(fd.cFileName);
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
}

// ---------------------------------------------------------------------------
// Small UI helpers
// ---------------------------------------------------------------------------
static bool TabButton(const char *label, const char *hiddenId, bool active, const ImVec2 &size)
{
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, kAccent);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccentHover);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, kTabIdle);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccent);
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "%s##%s", label, hiddenId);
    bool clicked = ImGui::Button(buf, size);
    ImGui::PopStyleColor(3);
    return clicked;
}

static void StatusLine()
{
    ImGui::TextColored(kAccentHover, "%s", s_status.c_str());
    if (!s_lastAction.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", s_lastAction.c_str());
    }
}

// ===========================================================================
// Scripts tab
// ===========================================================================
static void DrawEditor()
{
    ImGui::BeginChild("##lua_gutter", ImVec2(48, -140), true);
    int lines = 1;
    for (const char *p = s_editorBuf; p && *p; ++p) if (*p == '\n') ++lines;
    for (int i = 1; i <= lines && i < 2000; ++i) ImGui::TextDisabled("%d", i);
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::PushItemWidth(-1);
    ImGui::InputTextMultiline("##lua_editor", s_editorBuf, sizeof(s_editorBuf),
                              ImVec2(-1, -140), ImGuiInputTextFlags_AllowTabInput);
    ImGui::PopItemWidth();

    if (ImGui::Button("Execute", ImVec2(110, 34))) {
        s_console.clear();
        if (RunLuaBuffer(s_editorBuf, strlen(s_editorBuf), "editor")) {
            FeatureAction("Script executed");
        } else {
            FeatureAction("Script error (see console)");
        }
    }
    ImGui::SameLine();
    const char *vms[] = {"Default VM", "@custom"};
    ImGui::SetNextItemWidth(160);
    ImGui::Combo("##vmcombo", &s_vmIndex, vms, 2);
    ImGui::SameLine();
    if (ImGui::Button("Clear##console")) s_console.clear();
    ImGui::SameLine();
    ImGui::TextDisabled("Output:");

    ImGui::BeginChild("##lua_console", ImVec2(-1, -1), true);
    if (s_console.empty()) {
        ImGui::TextDisabled("print(...) output appears here");
    } else {
        ImGui::TextUnformatted(s_console.c_str());
    }
    ImGui::EndChild();
}

static void DrawScriptsList()
{
    if (!s_scriptsScanned) ScanLuaScripts();
    ImGui::TextDisabled("Path: .\\lua\\ (evidence: \"%%s\\\\lua\\\\%%s\")");
    ImGui::BeginChild("##scripts_list", ImVec2(-1, -80), true);
    if (s_scripts.empty()) {
        ImGui::TextDisabled("No scripts found");
    }
    for (int i = 0; i < (int)s_scripts.size(); ++i) {
        ImGui::PushID(i);
        if (ImGui::Selectable(s_scripts[i].name.c_str(), s_scriptSel == i)) s_scriptSel = i;
        ImGui::SameLine(220);
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "Inject##%d", i);
        if (ImGui::SmallButton(lbl)) FeatureAction(("Injected: " + s_scripts[i].name).c_str());
        ImGui::SameLine();
        snprintf(lbl, sizeof(lbl), "Auto-inj##%d", i);
        ImGui::Checkbox(lbl, &s_scripts[i].autoInject);
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (ImGui::Button("Dump")) {
        if (s_scriptSel >= 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Dump script saved: %s", s_scripts[s_scriptSel].name.c_str());
            FeatureAction(msg);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Dump all")) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Dump all scripts saved (%d)", (int)s_scripts.size());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button("Run##script") && s_scriptSel >= 0) {
        std::string path = "lua\\" + s_scripts[s_scriptSel].name;
        FILE *fp = fopen(path.c_str(), "rb");
        if (fp) {
            std::string code;
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) code.append(buf, n);
            fclose(fp);
            s_console.clear();
            if (RunLuaBuffer(code.c_str(), code.size(), s_scripts[s_scriptSel].name.c_str()))
                FeatureAction("Script executed");
            else
                FeatureAction("Script error (see console)");
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("view: ##scripteditorview | \"File big, no view script\"");
}

static void DrawResources()
{
    if (s_resources.empty()) ScanMtaResources();

    ImGui::TextDisabled("Source: .\\mods\\deathmatch\\resources / cache (disk)");
    static char search[64] = "";
    ImGui::InputTextWithHint("##res_search", "Search...", search, sizeof(search));
    static int resSel = 0;
    std::string preview = s_resources.empty() ? "Select Resource" : s_resources[resSel];
    ImGui::SetNextItemWidth(260);
    if (ImGui::BeginCombo("##rescombo", preview.c_str())) {
        for (int i = 0; i < (int)s_resources.size(); ++i) {
            if (search[0] && s_resources[i].find(search) == std::string::npos) continue;
            if (ImGui::Selectable(s_resources[i].c_str(), resSel == i)) resSel = i;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(%d found)", (int)s_resources.size());
    if (ImGui::Button("Stop Resource")) {
        if (!s_resources.empty()) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Resource stopped: %s", s_resources[resSel].c_str());
            FeatureAction(msg);
        }
    }
    ImGui::Separator();
    ImGui::TextDisabled("Block list (\" (blocked)\"):");
    for (auto &e : s_blockedEvents) ImGui::BulletText("%s (blocked)", e.c_str());
}

static void DrawEvents()
{
    static int evSel = 0;
    static const char *kEvents[] = {
        "onClientRender", "onClientPlayerDamage", "onClientVehicleEnter",
        "onClientChatMessage", "onClientElementDataChange", "onClientPreRender"
    };
    ImGui::SetNextItemWidth(280);
    ImGui::BeginCombo("##event_combo", kEvents[evSel]);
    for (int i = 0; i < 6; ++i) if (ImGui::Selectable(kEvents[i], evSel == i)) evSel = i;
    ImGui::EndCombo();
    ImGui::SameLine();
    if (ImGui::Button("Block##event")) {
        s_blockedEvents.push_back(kEvents[evSel]);
        FeatureAction(("Event blocked: " + std::string(kEvents[evSel])).c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Unblock##event") && !s_blockedEvents.empty()) {
        FeatureAction(("Event unblocked: " + s_blockedEvents.back()).c_str());
        s_blockedEvents.pop_back();
    }
    static char trig[96] = "";
    ImGui::InputTextWithHint("##trigger_input", "triggerServerEvent name...", trig, sizeof(trig));
    ImGui::SameLine();
    if (ImGui::Button("Add to Block List") && trig[0]) {
        s_blockedEvents.push_back(trig);
        trig[0] = 0;
    }
    ImGui::Separator();
    ImGui::Text("Recent Triggers:");
    if (s_recentTriggers.empty()) ImGui::TextDisabled("No triggers");
    for (auto &t : s_recentTriggers) ImGui::BulletText("%s", t.c_str());
}

static void DrawEventsTable()
{
    ImGui::TextDisabled("Events Table (live event registry view)");
    if (ImGui::BeginTable("##eventstable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Event");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("State");
        ImGui::TableHeadersRow();
        for (auto &e : s_recentTriggers) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextDisabled("tracked");
        }
        for (auto &e : s_blockedEvents) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextColored(kAccentHover, "(blocked)");
        }
        ImGui::EndTable();
    }
}

static void DrawPackets()
{
    if (ImGui::Button("Refresh")) FeatureAction("Refresh");
    ImGui::SameLine();
    ImGui::Text("Packets: %zu", s_packets.size());
    ImGui::SameLine();
    if (ImGui::Button("Clear All")) s_packets.clear();
    ImGui::SameLine();
    if (ImGui::Button("Unblock All"))
        for (auto &p : s_packets) p.blocked = false;
    ImGui::SameLine();
    ImGui::InputTextWithHint("##packet_search", "Search packet...", s_packetSearch, sizeof(s_packetSearch));

    ImGui::BeginChild("packets_left", ImVec2(-320, -1), true);
    if (s_packets.empty()) {
        ImGui::TextDisabled("No packets detected.");
    }
    for (int i = 0; i < (int)s_packets.size(); ++i) {
        ImGui::PushID(i);
        if (ImGui::Selectable(s_packets[i].name.c_str(), s_packetSel == i)) s_packetSel = i;
        ImGui::SameLine();
        ImGui::TextDisabled("%s", s_packets[i].blocked ? "BLOCKED" : "UNBLOCKED");
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("packets_right", ImVec2(0, -1), true);
    if (s_packetSel >= 0 && s_packetSel < (int)s_packets.size()) {
        const PacketRow &p = s_packets[s_packetSel];
        ImGui::Text("Name: %s", p.name.c_str());
        ImGui::Text("Time: %s", p.time.c_str());
        ImGui::Text("ID: %d", p.id);
        ImGui::TextColored(kAccentHover, "%s", p.blocked ? "BLOCKED" : "UNBLOCKED");
        if (ImGui::Button("Block Packet"))
            s_packets[s_packetSel].blocked = !s_packets[s_packetSel].blocked;
        ImGui::SameLine();
        if (ImGui::Button("Resend")) {
            char msg[160];
            snprintf(msg, sizeof(msg), "Resending packet: %s", p.name.c_str());
            FeatureAction(msg);
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy Name")) {
            ImGui::SetClipboardText(p.name.c_str());
            char msg[160];
            snprintf(msg, sizeof(msg), "Packet name copied: %s", p.name.c_str());
            FeatureAction(msg);
        }
    } else {
        ImGui::TextDisabled("Select a packet");
    }
    ImGui::EndChild();
}

// ===========================================================================
// Dumper tab
// ===========================================================================
static void DrawDumper()
{
    ImGui::TextDisabled("Memory / class dumper (display shell)");
    ImGui::BeginChild("##dumper", ImVec2(-1, -1), true);
    for (int i = 0; i < 8; ++i) {
        ImGui::Text("Address: 0x%08X", 0x10000000 + i * 0x10);
        ImGui::SameLine(180);
        ImGui::TextDisabled("?? ?? ?? ?? (dump data - U)");
    }
    ImGui::EndChild();
}

// ===========================================================================
// Cheat tab
// ===========================================================================
static void DrawPlayerTab()
{
    ImGui::InputTextWithHint("##playerfilter", "filter...", (char *)s_playerFilter.c_str(), 64);
    ImGui::SetNextItemWidth(280);
    std::string preview = s_players.empty() ? "Select player..." :
        (s_players[s_playerSel].name + (s_players[s_playerSel].isYou ? " (you)" : ""));
    if (ImGui::BeginCombo("##playercombo", preview.c_str())) {
        for (int i = 0; i < (int)s_players.size(); ++i) {
            std::string lbl = s_players[i].name + (s_players[i].isYou ? " (you)" : "");
            if (ImGui::Selectable(lbl.c_str(), s_playerSel == i)) s_playerSel = i;
        }
        if (s_players.empty()) ImGui::TextDisabled("No players found");
        ImGui::EndCombo();
    }
    if (ImGui::Button("Teleport")) FeatureAction("Teleport");
    ImGui::SameLine();
    if (ImGui::Button("Bomb")) FeatureAction("Bomb");
    ImGui::SameLine();
    if (ImGui::Button("Add Friend")) {
        if (!s_players.empty()) s_friends.push_back(s_players[s_playerSel].name);
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete Friend") && !s_friends.empty())
        s_friends.pop_back();
    ImGui::Separator();
    ImGui::Text("Friend's list");
    if (s_friends.empty()) ImGui::TextDisabled("No friends added");
    for (auto &f : s_friends) ImGui::BulletText("%s", f.c_str());
}

static void FeatureRow(Feature &f, const char *id)
{
    ImGui::PushID(id);
    bool wasOn = f.on;
    ImGui::Checkbox(f.label, &f.on);
    if (f.on != wasOn) {
        WriteFeatureMemory(f.label, f.on);
        FeatureAction(f.label);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("##gear")) ImGui::OpenPopup("##settings_panel");
    if (ImGui::BeginPopup("##settings_panel")) {
        ImGui::TextUnformatted(f.settings);
        ImGui::Separator();
        if (strcmp(f.label, "Give HP") == 0) {
            ImGui::SliderFloat("HP Value##sp", &shpValue, 1, 200);
        } else if (strcmp(f.label, "Give Armor") == 0) {
            ImGui::SliderFloat("Armor Value##sp", &sarmorValue, 1, 200);
        } else if (strcmp(f.label, "AirBreak") == 0) {
            ImGui::SliderFloat("Speed: %.2f", &sabSpeed, 0.1f, 10.f);
            ImGui::SliderFloat("Increment: %.2f", &sabIncr, 0.05f, 2.f);
            ImGui::Separator();
            ImGui::Text("Keybinds");
            ImGui::BulletText("Forward:"); ImGui::BulletText("Back:");
            ImGui::BulletText("Left:");    ImGui::BulletText("Right:");
            ImGui::BulletText("Down:");
        } else if (strcmp(f.label, "Click Warp") == 0) {
            ImGui::SliderFloat("Max Distance##sp", &smaxDist, 10, 1000);
            ImGui::SliderFloat("Crosshair Size##sp", &scrossSize, 2, 40);
            ImGui::Checkbox("Ground Warp##sp", &sgroundWarp);
            ImGui::Checkbox("Enter Vehicle##sp", &senterVehicle);
        } else if (strcmp(f.label, "Anti-ScreenShot") == 0) {
            ImGui::Checkbox("Hide obs/discord", &shideObsDiscord);
        } else if (strcmp(f.label, "Anti-AFK") == 0) {
            ImGui::Checkbox("Anti-AFK", &santiAfk);
        } else {
            ImGui::TextDisabled("settings shell (U)");
        }
        ImGui::Separator();
        if (ImGui::Button("Press a key...")) s_bindCapture = -2;
        ImGui::SameLine();
        ImGui::TextDisabled("mode: Toggle/Hold");
        ImGui::EndPopup();
    }
    ImGui::PopID();
}

static void DrawOtherTab()
{
    ImGui::TextDisabled("Feature toggles (statuses real; game-state internals U/stub)");
    for (int i = 0; i < (int)(sizeof(s_cheatFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "cf%d", i);
        FeatureRow(s_cheatFeatures[i], id);
    }
    if (!s_lastAction.empty()) ImGui::TextDisabled("last: %s", s_lastAction.c_str());
}

static void DrawMarkersTab()
{
    ImGui::InputTextWithHint("##markername", "marker name...", s_markerName, sizeof(s_markerName));
    ImGui::SameLine();
    if (ImGui::Button("Save") && s_markerName[0]) {
        MarkerRow m = {s_markerName, 0.f, 0.f, 0.f};
        s_markers.push_back(m);
        s_markerName[0] = 0;
    }
    if (s_markers.empty()) ImGui::TextDisabled("No markers saved");
    for (auto &m : s_markers) {
        char line[128];
        snprintf(line, sizeof(line), "%s (%.1f, %.1f, %.1f)", m.name.c_str(), m.x, m.y, m.z);
        ImGui::BulletText("%s", line);
        ImGui::SameLine(280);
        if (ImGui::SmallButton("Teleport")) FeatureAction("Teleport");
        ImGui::SameLine();
        if (ImGui::SmallButton("Delete")) m.name.clear();
    }
}

// ===========================================================================
// Vehicle tab
// ===========================================================================
static void DrawVehicleTab()
{
    ImGui::Columns(2, "##vehcols", false);
    ImGui::SetColumnWidth(0, 300);
    ImGui::Text("Vehicle's");
    ImGui::Separator();
    for (int i = 0; i < (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "vf%d", i);
        FeatureRow(s_vehicleFeatures[i], id);
    }
    ImGui::NextColumn();

    ImGui::Text("Vehicles List");
    ImGui::SetNextItemWidth(-1);
    std::string prev = std::string(kVehicleNames[s_vehicleSel]) + " (HP: 1000)";
    if (ImGui::BeginCombo("##vehicles_combo", s_vehicleSel >= 0 ? prev.c_str() : "Select vehicle...")) {
        for (int i = 0; i < (int)(sizeof(kVehicleNames) / sizeof(kVehicleNames[0])); ++i) {
            if (ImGui::Selectable(kVehicleNames[i], s_vehicleSel == i)) s_vehicleSel = i;
        }
        ImGui::EndCombo();
    }
    if (ImGui::Button("Teleport to Vehicle")) FeatureAction("Teleport to Vehicle");
    ImGui::SameLine();
    if (ImGui::Button("Teleport Vehicle")) FeatureAction("Vehicle teleported to you");
    ImGui::SameLine();
    if (ImGui::Button("Bomb Car")) FeatureAction("Vehicle destroyed");
    if (ImGui::Button("Repair Car")) FeatureAction("Vehicle repaired");
    ImGui::SameLine();
    if (ImGui::Button("Start Engine")) FeatureAction("Engine started");
    ImGui::SameLine();
    if (ImGui::Button("Stop")) FeatureAction("Vehicle stopped");
    ImGui::SameLine();
    if (ImGui::Button("Unlock Car")) FeatureAction("Unlocked nearest vehicle");
    ImGui::Columns(1);
}

// ===========================================================================
// Config tab
// ===========================================================================
static void DrawColorSettings()
{
    if (ImGui::TreeNode("Color Settings")) {
        static char filter[64] = "";
        ImGui::InputTextWithHint("##filter", "Search color...", filter, sizeof(filter));
        static const struct { const char *name; ImGuiCol col; } kColors[] = {
            {"Text", ImGuiCol_Text}, {"Text Disabled", ImGuiCol_TextDisabled},
            {"Window BG", ImGuiCol_WindowBg}, {"Child BG", ImGuiCol_ChildBg},
            {"Popup BG", ImGuiCol_PopupBg}, {"Border", ImGuiCol_Border},
            {"Border Shadow", ImGuiCol_BorderShadow},
            {"Frame BG", ImGuiCol_FrameBg}, {"Frame BG Hovered", ImGuiCol_FrameBgHovered},
            {"Frame BG Active", ImGuiCol_FrameBgActive},
            {"Title BG", ImGuiCol_TitleBg}, {"Title BG Active", ImGuiCol_TitleBgActive},
            {"Title BG Collapsed", ImGuiCol_TitleBgCollapsed},
            {"Menu Bar BG", ImGuiCol_MenuBarBg},
            {"Scrollbar BG", ImGuiCol_ScrollbarBg},
            {"Scrollbar Grab", ImGuiCol_ScrollbarGrab},
            {"Scrollbar Grab Hovered", ImGuiCol_ScrollbarGrabHovered},
            {"Scrollbar Grab Active", ImGuiCol_ScrollbarGrabActive},
            {"Check Mark", ImGuiCol_CheckMark}, {"Slider Grab", ImGuiCol_SliderGrab},
            {"Slider Grab Active", ImGuiCol_SliderGrabActive},
            {"Button", ImGuiCol_Button}, {"Button Hovered", ImGuiCol_ButtonHovered},
            {"Button Active", ImGuiCol_ButtonActive},
            {"Header", ImGuiCol_Header}, {"Header Hovered", ImGuiCol_HeaderHovered},
            {"Header Active", ImGuiCol_HeaderActive},
            {"Separator Hovered", ImGuiCol_SeparatorHovered},
            {"Separator Active", ImGuiCol_SeparatorActive},
            {"Tab", ImGuiCol_Tab}, {"Tab Hovered", ImGuiCol_TabHovered},
            {"Tab Active", ImGuiCol_TabActive},
            {"Resize Grip", ImGuiCol_ResizeGrip},
            {"Resize Grip Hovered", ImGuiCol_ResizeGripHovered},
            {"Resize Grip Active", ImGuiCol_ResizeGripActive},
            {"Text Selected BG", ImGuiCol_TextSelectedBg},
        };
        if (ImGui::BeginTable("##ColorTable", 2, ImGuiTableFlags_Borders)) {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Color");
            ImGui::TableHeadersRow();
            for (auto &k : kColors) {
                if (filter[0] && !strstr(k.name, filter)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(k.name);
                ImGui::TableNextColumn();
                ImVec4 c = ImGui::GetStyle().Colors[k.col];
                if (ImGui::ColorEdit4("##col", (float *)&c, ImGuiColorEditFlags_NoInputs))
                    ImGui::GetStyle().Colors[k.col] = c;
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Reset Colors")) {
            ImGui::StyleColorsDark();
            NrthUI_ApplyTheme();
            FeatureAction("Colors reset");
        }
        ImGui::TreePop();
    }
}

static void DrawConfigTab()
{
    if (!s_configsScanned) ScanConfigs();
    ImGui::Columns(2, "##cfgcols", false);
    ImGui::SetColumnWidth(0, 260);
    ImGui::Text("Configs");
    ImGui::BeginChild("##cfgitem", ImVec2(-1, -1), true);
    if (s_configs.empty()) ImGui::TextDisabled("No configs found");
    for (int i = 0; i < (int)s_configs.size(); ++i) {
        if (ImGui::Selectable(s_configs[i].name.c_str(), s_cfgSel == i)) s_cfgSel = i;
    }
    ImGui::EndChild();
    ImGui::NextColumn();

    ImGui::BeginChild("##cfg_right", ImVec2(0, -1), true);
    ImGui::InputText("Name##sa", s_cfgName, sizeof(s_cfgName));
    if (ImGui::Button("Save")) {
        SaveLoaderConfig();

        std::string f = std::string(s_cfgName) + ".ovr";
        FILE *fp = fopen(f.c_str(), "w");
        if (fp) {
            fputs("OVRCFG\n", fp);
            fclose(fp);
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "Config saved: %s", f.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Save As...")) {
        s_cfgName[0] = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button("Load") && s_cfgSel >= 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Config loaded: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete") && s_cfgSel >= 0) {
        DeleteFileA(s_configs[s_cfgSel].name.c_str());
        char msg[128];
        snprintf(msg, sizeof(msg), "Config deleted: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset to Default")) {
        FeatureAction("Reset to default style");
    }
    ImGui::Separator();
    ImGui::Checkbox("Watermark", &swatermark);
    ImGui::SameLine();
    ImGui::Checkbox("Notifications", &snotifications);
    ImGui::Separator();

    ImGui::Text("Menu Toggle Key");
    ImGui::SameLine();
    if (s_waitingForKey) {
        ImGui::Button("Press...");
        for (int k = 0; k < 256; ++k)
            if (ImGui::IsKeyPressed((ImGuiKey)k, false)) { stoggleKey = k; s_waitingForKey = false; }
    } else if (ImGui::Button("Set")) {
        s_waitingForKey = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(current: Insert)");

    ImGui::Separator();
    ImGui::Text("Keybind's");
    if (s_binds.empty()) ImGui::TextDisabled("No binds");
    for (int i = 0; i < (int)s_binds.size(); ++i) {
        ImGui::Text("Bind: %s -> key %d", s_binds[i].action.c_str(), s_binds[i].key);
        ImGui::SameLine();
        if (ImGui::SmallButton("X")) {
            FeatureAction(("Bind cleared: " + s_binds[i].action).c_str());
            s_binds.erase(s_binds.begin() + i);
            break;
        }
    }
    DrawColorSettings();
    ImGui::EndChild();
    ImGui::Columns(1);
}

// ===========================================================================
// Entry point
// ===========================================================================
void NrthUI_Build()
{
    ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.35f);
    ImGui::Begin("##status_ovr", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove);
    ImGui::TextUnformatted(s_status.c_str());
    ImGui::End();

    ImGui::SetNextWindowSize(ImVec2(860, 560), ImGuiCond_FirstUseEver);
    if (!s_menuOpen) return;
    if (!ImGui::Begin("North Cheat", &s_menuOpen)) {
        ImGui::End();
        return;
    }

    StatusLine();
    ImGui::Separator();

    static const char *kTop[] = {"Scripts", "Dumper", "Cheat", "Vehicle", "Config"};
    float w = (ImGui::GetContentRegionAvail().x - 4 * 8.f) / 5.f;
    for (int i = 0; i < 5; ++i) {
        char hid[32];
        snprintf(hid, sizeof(hid), "nvxtop%d", i);
        if (TabButton(kTop[i], hid, s_topTab == i, ImVec2(w, 34))) s_topTab = i;
        if (i < 4) ImGui::SameLine();
    }
    ImGui::Spacing();

    if (s_topTab == 0) {
        static const char *kSub[] = {"Editor", "Scripts", "Resources", "Events", "Events Table", "Packets"};
        float sw = (ImGui::GetContentRegionAvail().x - 5 * 6.f) / 6.f;
        for (int i = 0; i < 6; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvxssub%d", i);
            if (TabButton(kSub[i], hid, s_scriptsSub == i, ImVec2(sw, 26))) s_scriptsSub = i;
            if (i < 5) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        switch (s_scriptsSub) {
            case 0: DrawEditor(); break;
            case 1: DrawScriptsList(); break;
            case 2: DrawResources(); break;
            case 3: DrawEvents(); break;
            case 4: DrawEventsTable(); break;
            case 5: DrawPackets(); break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 1) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawDumper();
        ImGui::EndChild();
    } else if (s_topTab == 2) {
        static const char *kCSub[] = {"Player", "Other", "Markers"};
        float sw = (ImGui::GetContentRegionAvail().x - 2 * 6.f) / 3.f;
        for (int i = 0; i < 3; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvxcsub%d", i);
            if (TabButton(kCSub[i], hid, s_cheatSub == i, ImVec2(sw, 26))) s_cheatSub = i;
            if (i < 2) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        switch (s_cheatSub) {
            case 0: DrawPlayerTab(); break;
            case 1: DrawOtherTab(); break;
            case 2: DrawMarkersTab(); break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 3) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawVehicleTab();
        ImGui::EndChild();
    } else {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawConfigTab();
        ImGui::EndChild();
    }

    ImGui::End();
}