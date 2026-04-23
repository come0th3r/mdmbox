#include "mdmbox_shell_bridge.h"

#include "mdmbox_shell_window.h"

MdmBoxShellBridge::MdmBoxShellBridge(MdmBoxShellWindow *window, QObject *parent)
    : QObject(parent), window(window) {}

void MdmBoxShellBridge::navigate(const QString &pageKey) {
    if (window) window->navigate(pageKey);
}

void MdmBoxShellBridge::connectToggle() {
    if (window) window->triggerConnectToggle();
}

void MdmBoxShellBridge::toggleTun() {
    if (window) window->triggerTunToggle();
}

void MdmBoxShellBridge::toggleSystemProxy() {
    if (window) window->triggerSystemProxyToggle();
}

void MdmBoxShellBridge::importClipboard() {
    if (window) window->triggerClipboardImport();
}

void MdmBoxShellBridge::openLegacy() {
    if (window) window->triggerOpenLegacy();
}

void MdmBoxShellBridge::selectServer(int id) {
    if (window) window->triggerSelectServer(id);
}

void MdmBoxShellBridge::selectGroup(int gid) {
    if (window) window->triggerSelectGroup(gid);
}

void MdmBoxShellBridge::routingSetDefault(const QString &policy) {
    if (window) window->triggerRoutingSetDefault(policy);
}

void MdmBoxShellBridge::routingAddRule(int tabIndex) {
    if (window) window->triggerRoutingAddRule(tabIndex);
}

void MdmBoxShellBridge::routingEditRule(int tabIndex, const QString &value, const QString &policy) {
    if (window) window->triggerRoutingEditRule(tabIndex, value, policy);
}

void MdmBoxShellBridge::routingRemoveRule(int tabIndex, const QString &value, const QString &policy) {
    if (window) window->triggerRoutingRemoveRule(tabIndex, value, policy);
}

void MdmBoxShellBridge::routingImportClipboard(int tabIndex) {
    if (window) window->triggerRoutingImportClipboard(tabIndex);
}

void MdmBoxShellBridge::routingExportConfig() {
    if (window) window->triggerRoutingExportConfig();
}

void MdmBoxShellBridge::routingResetRules(int tabIndex) {
    if (window) window->triggerRoutingResetRules(tabIndex);
}

void MdmBoxShellBridge::clearLogs() {
    if (window) window->triggerClearLogs();
}

void MdmBoxShellBridge::exportLogs() {
    if (window) window->triggerExportLogs();
}

void MdmBoxShellBridge::minimizeWindow() {
    if (window) window->showMinimized();
}

void MdmBoxShellBridge::maximizeWindow() {
    if (!window) return;
    if (window->isMaximized()) window->showNormal();
    else window->showMaximized();
}

void MdmBoxShellBridge::closeWindow() {
    if (window) window->close();
}

void MdmBoxShellBridge::exitProgram() {
    if (window) window->triggerExitProgram();
}
