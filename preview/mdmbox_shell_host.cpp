#include "mdmbox_shell_host.h"

#include "mdmbox_shell_window.h"
#include "ui/mainwindow.h"
#include <QTimer>

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
    // Source archives may not include the optional HTML shell. Keep the
    // existing native interface reachable instead of presenting a blank view.
    if (!window->hasLocalShell()) {
        // Initial call can occur inside MainWindow's constructor, before its
        // global pointer is assigned by UI_InitMainWindow.
        QTimer::singleShot(0, window, [] {
            if (auto *main = GetMainWindow()) {
                main->show();
                main->raise();
                main->activateWindow();
            }
        });
        return;
    }
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
