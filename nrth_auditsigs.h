/**
* ============================================================================
* nrth_auditsigs.h — GENERATED FILE, do not edit by hand
* ============================================================================
* Every entry is a plaintext byte-signature that the sample keeps obfuscated
* and uses to find a function in an MTA:SA module by code pattern.
* ============================================================================
*/
#ifndef NRTH_AUDIT_SIGS_H
#define NRTH_AUDIT_SIGS_H

#include "nrth_audit.h"

#define NRTH_SIG_COUNT 20

static const NrthSignature g_NrthSigTable[NRTH_SIG_COUNT] = {
    { 1, "55 8B EC 83 EC ? FF 75 ? FF 75 ? E8 ? ? ? ? 83 C4 ? 83 78 ? ? 74 ? 8D 4D ? 51 50 E8 ? ? ? ? 83 C4 ? 85 C0 75 ? ? ? 8B E5",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000e0a0, 120, 0x40, 2, "0x1000ca47" },
    { 2, "55 8B EC 56 FF 75 ? 8B 75 ? 56 E8 ? ? ? ? 83 C4 ? 83 78 ? ? 74 ? C7 05 ? ? ? ? ? ? ? ? 8B 4E ? 83 E9 ? 51 ? ? 56",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000db00, 112, 0x40, 2, "0x1000cfbe" },
    { 3, "55 8B EC 56 8B 75 ? 85 F6 75 ? 89 35 ? ? ? ? 8B 0D ? ? ? ? 56 E8 ? ? ? ? 85 C0 74 ? F3 0F 10 45",
      "client.dll", "Lua-VM / client interface hook installed by resolver at 0x10005b80", 0x100074f0, 95, 0x2D, 2, "0x10005e54" },
    { 4, "55 8B EC 56 8B 75 ? 8B 4E ? 8B 41 ? 3B 41 ? 72 ? 56 E8 ? ? ? ? 83 C4 ? 8B 46 ? 2B 46",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000e5f0, 84, 0x40, 2, "0x1000c52b" },
    { 5, "55 8B EC 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 8B 45 ? 53 8B 5D ? 56 57 8B 7D ? 89 45",
      "client.dll", "Lua-VM / client interface hook installed by resolver at 0x10005b80", 0x10007640, 80, 0x2D, 2, "0x10005d28" },
    { 6, "55 8B EC 83 EC ? 56 8B 75 ? 57 8B F9 85 F6 0F 84 ? ? ? ? 8B CE",
      "client.dll", "Lua-VM / client interface hook installed by resolver at 0x10005b80", 0x10006f90, 62, 0x2D, 2, "0x1000633b" },
    { 7, "55 8B EC 56 FF 75 ? FF 75 ? E8 ? ? ? ? 8B F0 83 C4 ? 8B 4E",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000d700, 58, 0x40, 2, "0x1000d30f" },
    { 8, "55 8B EC FF 75 ? FF 75 ? E8 ? ? ? ? 83 C4 ? 3D ? ? ? ? 75",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000df50, 57, 0x40, 2, "0x1000cc11" },
    { 9, "55 8B EC FF 75 ? FF 75 ? E8 ? ? ? ? 83 C4 ? 8B 48 ? 83 E9",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000df50, 57, 0x40, 2, "0x1000cb35" },
    { 10, "55 8B EC 8B 45 ? A3 ? ? ? ? 8B 45 ? A3 ? ? ? ? 8B 45",
      "client.dll", "Lua-VM / client interface hook installed by resolver at 0x10005b80", 0x10007780, 52, 0x2D, 2, "0x10005c07" },
    { 11, "55 8B EC 83 EC ? 53 56 8B 75 ? 57 8B 46 ? 2B 46",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000e4a0, 47, 0x40, 2, "0x1000c5fc" },
    { 12, "55 8B EC 83 EC ? 53 8B 5D ? 56 8B 75 ? 57 8D 43",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000e4a0, 47, 0x40, 2, "0x1000ce27" },
    { 13, "55 8B EC 56 8B F1 8B 0D ? ? ? ? 57 ? ? FF 50",
      "client.dll", "Lua-VM / client interface hook installed by resolver at 0x10005b80", 0x10006ce0, 44, 0x2D, 2, "0x1000657b" },
    { 14, "55 8B EC 8B 4D ? 8B 41 ? 2B 41 ? C1 F8",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000e350, 38, 0x40, 2, "0x1000c6cb" },
    { 15, "55 8B EC 51 53 56 57 8B 7D ? 85 FF 75",
      "client.dll", "Lua-VM / client interface hook installed by resolver at 0x10005b80", 0x100073a0, 37, 0x2D, 2, "0x10005f56" },
    { 16, "55 8B EC 53 56 57 8B 7D ? 33 F6 32 DB",
      "netc.dll", "located in netc.dll check kill cluster (one-byte 0xC3 writes)", 0x100073a0, 37, 0x2D, 2, "0x10020591" },
    { 17, "55 8B EC 8B 55 ? 56 8B 75 ? 57 8B 7A",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000dd20, 36, 0x40, 2, "0x1000d062" },
    { 18, "55 8B EC 8B 45 ? 85 C0 75 ? 8B 55",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x1000d5b0, 33, 0x40, 2, "0x1000d463" },
    { 19, "55 8B EC 51 8B 45 ? 56 50",
      "client.dll", "Lua-VM / client interface hook installed by resolver at 0x10005b80", 0x10006c00, 25, 0x2D, 2, "0x10006684" },
    { 20, "55 8B EC 8B 45 ? 56 8B 70",
      "client.dll", "offset/pointer resolver at 0x1000c390", 0x10006c00, 25, 0x2D, 2, "0x1000d3c2" }
};

#endif /* NRTH_AUDIT_SIGS_H */