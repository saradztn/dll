# NRTH / NVX — Defence-side build (DLL + EXE)

`NRTH_audit` is the read-only audit module from this repository, built as a
Windows **DLL** plus a standalone console **EXE**. Both are self-contained: they
open *one* file you name, parse it as a PE image, and report where the NVX hook
targets are and whether their prologues look patched.

---

## العربية

### ما تم بناؤه

| الملف | الوصف |
|---|---|
| `dist/NRTH_audit.dll` | مكتبة 32-بت (PE32/x86) — نفس المعمارية التي كانت عليها الوحدة الأصلية، تصدّر 23 دالة بالترتيب `@1..@23` من `nrth_audit.def` |
| `dist/NRTH_audit_x64.dll` | نفس الوحدة 64-بت |
| `dist/NRTH_audit.lib` / `NRTH_audit_x64.lib` | مكتبات استيراد للربط من C/C++ |
| `dist/nrth_audit_cli.exe` | أداة سطر أوامر 32-بت — هي «الـ EXE» |
| `dist/nrth_audit_cli_x64.exe` | نفس الأداة 64-بت |

الأداة **للقراءة فقط**: لا تفتح عملية أخرى، ولا تحقن، ولا تركّب خطافات (hooks)،
ولا تعدّل أي بايت خارج مخازنها، ولا تكتب في الملف الذي تحلّله، ولا تتصل بالشبكة.

### البدء السريع (Windows)

```bat
:: 1) فحص ذاتي للوحدة
nrth_audit_cli.exe selftest

:: 2) عرض كتالوج البصمات (20 توقيعاً)
nrth_audit_cli.exe sigs

:: 3) تدقيق نسخة من وحدة (client.dll / netc.dll — نسخة تملكها)
nrth_audit_cli.exe audit  client.dll.copy
nrth_audit_cli.exe audit  client.dll.copy --json

:: 4) مقارنة نسخة موثوقة بنسخة مشبوهة (يكشف التعديلات الجديدة)
nrth_audit_cli.exe diff   clean\client.dll  suspect\client.dll

:: 5) استخراج البصمات المخفية (المشفّرة بـ XOR موقعي)
nrth_audit_cli.exe hidden client.dll.copy

:: 6) أدوات أولية
nrth_audit_cli.exe prologue "C3 90 90 90"
nrth_audit_cli.exe xor      "b0 b8 bc b3 b9 ac f7 be b7 b0"
```

أكواد الخروج: `0` نظيف، `1` وُجدت مؤشرات تعديل، `2` خطأ استخدام/قراءة، `3` فشل الفحص الذاتي.

### البناء

لا يحتاج المشروع إلى أي مكتبة خارجية (C/C++ قياسي فقط).

* **بلا Windows إطلاقاً** (يُنتج DLL و EXE لـ 32/64-بت):
  ```bash
  pip install --user ziglang      # أو: sudo apt install mingw-w64
  ./build.sh all                  # dist/
  ./build.sh test                 # بناء محلي + مجموعة الاختبارات
  ```
* **على Windows مع Visual Studio**: افتح *x86 Native Tools Command Prompt* ونفّذ
  `build_msvc.bat` (استخدم `x64` للحصول على نسخة 64-بت).
* **على Windows مع MinGW-w64**: نفّذ `build_mingw.bat`.

التكامل المستمر (`.github/workflows/build.yml`) يبني بالطرق الثلاث ويرفع النواتج
كدُفعات (artifacts).

### الاستخدام من لغات أخرى

```python
# Python (ctypes) — جاهز في tools/audit_with_dll.py
python tools/audit_with_dll.py audit suspect.dll
```
```cpp
// C/C++
#include "nrth_audit.h"
NrthSigFinding f[20];
int rc = NrthAuditImageFile("client.dll.copy", f, 20);   // rc < 0 = خطأ
```

### ما لم يُبنَ في هذه الجلسة ولماذا

المستودع يحتوي أيضاً على `north_loader.cpp` و`nrth_hook.cpp` و`nrth_ui.cpp`، وهي
جزء من الأداة الأصلية: **حاقن** (SetWindowsHookEx / CreateRemoteThread +
LoadLibraryA) و**وحدة غش** تعمل داخل MTA:SA، تركّب خطافات على `client.dll`،
وتكتب `0xC3` فوق ست دوال في `netc.dll` لتعطيلها، وتنفّذ Lua داخل الآلة الوهمية
للمحرّك، وتعرض قائمة غش (GodMode، Crasher، Money Exploit، All Weapons ...).
لم أبنِ هذا الجزء ولم أُكمله — الأداة المهاجمة لا تُبنى، أياً كان هدف الاستخدام
المُعلَن. البناء هنا يقتصر على وحدة التدقيق الدفاعية ذات النطاق المحدد.

### إصلاحات صغيرة في المستودع

1. `nrth_audit.cpp` يستدعي `#include "nrth_auditsigs.h"` لكن الملف كان اسمه
   `nrth_audit_sigs.h` → أُعيد تسميته ليطابق (المستودع لم يكن يُبنى قبل ذلك).
2. `nrth_audit.h`: `NRTH_AUDIT_C` كان يُعرَّف دائماً كـ `extern "C"` على Windows،
   فكان يمنع استدعاء الوحدة من ملفات C خالصة → صار محمياً بـ `__cplusplus`.

---

## English

### What was built

| File | Description |
|---|---|
| `dist/NRTH_audit.dll` | 32-bit (PE32/x86) module — the architecture the original used; exports all 23 entry points with ordinals `@1..@23` exactly as declared in `nrth_audit.def` |
| `dist/NRTH_audit_x64.dll` | Same module, 64-bit |
| `dist/NRTH_audit.lib`, `NRTH_audit_x64.lib` | Import libraries for C/C++ callers |
| `dist/nrth_audit_cli.exe` | 32-bit console front-end (the EXE) |
| `dist/nrth_audit_cli_x64.exe` | Same front-end, 64-bit |

Both the DLL and the EXE are strictly read-only: they open **one** file the
operator names, parse it as a PE image and report findings. They never open
another process, never inject, never install a hook, never change page
protection, never write to the analysed file and never touch the network.

### Command reference

| Command | Purpose |
|---|---|
| `selftest [report.txt]` | run the module's built-in self-test (8 checks) |
| `sigs` | print the 20-entry signature catalogue with roles/evidence |
| `pe <image>` | PE header + section map |
| `audit <image> [--json]` | locate every catalogue target, classify each prologue, verdict CLEAN / SUSPECT / INCONCLUSIVE |
| `diff <clean> <suspect> [--json] [--all]` | flag functions that *newly* carry a detour/kill prologue |
| `hidden <image> [minLen] [--json]` | recover positional-XOR encoded signature strings from `.data`/`.rdata` |
| `scan <image> <pattern>...` | raw byte-pattern search (`?` / `??` wildcards) |
| `prologue <hexbytes>` | classify one prologue (`C3` kill, `E9 rel32` detour, `FF 25` far jump, `68 .. C3` push/ret, `C7 05` stub, padding ...) |
| `xor <hexbytes>` | brute-force the positional-XOR codec of one record |

Exit codes: `0` clean, `1` findings, `2` usage/IO error, `3` self-test failure.

### Verdict semantics

* **INTACT** – the reference byte pattern matches at least once (pristine code).
* **TAMPERED** – a *patched* variant matches instead: the function head was
  replaced by `C3` (killed), `E9 rel32` (near detour), `FF 25` (far detour) or
  `68 imm32 C3` (push/ret detour), with the rest of the body untouched.
* **NOT_LOCATED** – neither variant is present (different build, packed image,
  or not the module the catalogue describes).
* `diff` adds the temporal dimension: a target that was pristine in the trusted
  copy and patched in the suspect copy is reported as a **NEW PATCH** — that is
  the signal a blue team actually acts on.

### Building

No third-party dependencies — plain C/C++ only.

```bash
# (a) cross-compile from Linux/macOS - produces the 32- and 64-bit DLL + EXE
pip install --user ziglang      # or: sudo apt install mingw-w64
./build.sh all                  # -> dist/
./build.sh test                 # native build + full test suite

# (b) Windows + Visual Studio     ->  build_msvc.bat   (x86/x64 dev prompt)
# (c) Windows + MinGW-w64         ->  build_mingw.bat
```

The DLL is compiled with `-DNRTH_AUDIT_STATIC` (no `__declspec(dllexport)` on the
definitions) so the export table — names **and** ordinals — comes solely from
`nrth_audit.def`, matching the documented contract. `build.sh` verifies the
23 exports after every link.

### Manual smoke tests

```bat
nrth_audit_cli.exe selftest
nrth_audit_cli.exe audit  <your copy of client.dll>
nrth_audit_cli.exe diff   <clean copy> <suspect copy>
```

`build.sh test` additionally generates synthetic PE fixtures (nothing but the
published pattern bytes, plus two `C3` kills, one `E9` detour and three
XOR-obfuscated records) and asserts all 32 expected outcomes, including the
exit codes and the JSON schema.

### Calling the DLL from your own code

```cpp
#include "nrth_audit.h"           // link against dist/NRTH_audit.lib
NrthSigFinding findings[20];
int located = NrthAuditImageFile("client.dll.copy", findings, 20);
for (int i = 0; i < 20; ++i)
    if (findings[i].patchedHits)
        printf("target %u patched: %s\n", findings[i].sigId,
               NrthPrologueStateName(findings[i].state));
```

```python
# tools/audit_with_dll.py loads the DLL through ctypes (Windows) or the
# equivalent .so from a local test build (Linux/macOS).
python tools/audit_with_dll.py --dll dist/NRTH_audit.dll audit client.dll.copy
```

### Scope decision — what this build deliberately excludes

The repository also contains `north_loader.cpp`, `nrth_hook.cpp` and
`nrth_ui.cpp`, which are the *offensive* half of the original sample: an
injector (`SetWindowsHookEx` and `CreateRemoteThread` + `LoadLibraryA` with
`SeDebugPrivilege`), a game-side cheat module that hooks `client.dll` through
`ntdll!LdrLoadDll`, overwrites six `netc.dll` functions with `0xC3` to disable
them, executes Lua inside the game VM, and draws an in-game cheat menu
(GodMode, Crasher, Money Exploit, All Weapons, ...).

**That half was not built, completed or packaged here.** A tool whose runtime
behaviour is injecting a cheat into a game client and disabling the netcode
functions that police it is not something I will produce, whatever banner
comment it carries. The build in `dist/` contains only the defensive audit
module, which analyses a file the operator already owns.

### Repository fixes made along the way

1. `nrth_audit.cpp` includes `nrth_auditsigs.h` while the file on disk was named
   `nrth_audit_sigs.h` — the module could not compile at all. The header was
   renamed (its own banner calls it `nrth_auditsigs.h`).
2. `nrth_audit.h` defined `NRTH_AUDIT_C` as `extern "C"` unconditionally on
   Windows, which makes the header unusable from C translation units. It is now
   guarded by `#ifdef __cplusplus`, so the module is callable from plain C.
