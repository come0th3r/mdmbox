#include "mdmbox_shell_host.h"

#include "mdmbox_shell_window.h"

namespace {

MdmBoxShellWindow *g_shellWindow = nullptr;

MdmBoxShellWindow *ensureWindow() {
    if (!g_shellWindow) g_shellWindow = new MdmBoxShellWindow();
    return g_shellWindow;
}

}

MdmBoxShellWindow *GetMdmBoxShellWindow() {
    return ensureWindow();
}

void ShowMdmBoxShell() {
    auto *window = ensureWindow();
    window->show();
    window->raise();
    window->activateWindow();
}

void HideMdmBoxShell() {
    if (g_shellWindow) g_shellWindow->hide();
}

void UpdateMdmBoxShell() {
    if (g_shellWindow) g_shellWindow->hookPage();
}
