#pragma once
/**
* NRTH overlay UI — faithful interface reconstruction (R2) of the REAL menu.
*
* Real/local features (functional): tab structure, theme, script file listing
* (.\lua\*.lua), config save/load (.ovr + C:\Overwack\loader_config.cfg),
* style color editor, keybind capture, marker list, vehicle name table,
* status messages, feature toggles that write to client.dll memory when
* the game module is loaded.
*/

// Purple theme matching the runtime screenshot.
void NrthUI_ApplyTheme();

// Called once per frame while the menu is open.
void NrthUI_Build();