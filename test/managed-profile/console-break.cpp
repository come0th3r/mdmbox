#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>

// Test-only helper: attach exclusively to a newly created child console.
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    char *end = nullptr;
    const auto value = std::strtoul(argv[1], &end, 10);
    if (!value || !end || *end || value > MAXDWORD) return 2;
    FreeConsole();
    if (!AttachConsole(static_cast<DWORD>(value))) return 3;
    if (!SetConsoleCtrlHandler(nullptr, TRUE)) { FreeConsole(); return 4; }
    const bool sent = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
    // Let delivery finish before helper's console attachment is removed.
    Sleep(200);
    FreeConsole();
    return sent ? 0 : 5;
}
