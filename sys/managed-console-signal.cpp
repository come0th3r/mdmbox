#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cerrno>
#include <cstdlib>

// Dedicated process: never detach/attach the GUI's own console.
int main(int argc, char **argv) {
    if (argc != 2 || !argv[1][0]) return 1;
    for (const char *p = argv[1]; *p; ++p) if (*p < '0' || *p > '9') return 2;
    char *end = nullptr;
    errno = 0;
    const auto value = std::strtoul(argv[1], &end, 10);
    if (errno || !value || !end || *end || value > MAXDWORD || value == GetCurrentProcessId()) return 2;
    const auto target = static_cast<DWORD>(value);
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, target);
    if (!process) return 3;
    FreeConsole();
    if (!AttachConsole(target)) { CloseHandle(process); return 4; }
    DWORD members[3] = {};
    const auto count = GetConsoleProcessList(members, 3);
    bool foundTarget = false, foundSelf = false;
    for (DWORD i = 0; i < count && i < 3; ++i) {
        foundTarget |= members[i] == target;
        foundSelf |= members[i] == GetCurrentProcessId();
    }
    const bool isolated = count == 2 && foundTarget && foundSelf && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    if (!isolated || !SetConsoleCtrlHandler(nullptr, TRUE)) {
        FreeConsole(); CloseHandle(process); return 5;
    }
    const bool sent = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
    Sleep(200);
    FreeConsole();
    CloseHandle(process);
    return sent ? 0 : 6;
}
