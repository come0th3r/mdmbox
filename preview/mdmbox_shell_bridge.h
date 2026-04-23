#pragma once

#include <QObject>

class MdmBoxShellWindow;

class MdmBoxShellBridge final : public QObject {
    Q_OBJECT

public:
    explicit MdmBoxShellBridge(MdmBoxShellWindow *window, QObject *parent = nullptr);

public slots:
    void navigate(const QString &pageKey);
    void connectToggle();
    void toggleTun();
    void toggleSystemProxy();
    void importClipboard();
    void openLegacy();
    void selectServer(int id);
    void selectGroup(int gid);
    void routingSetDefault(const QString &policy);
    void routingAddRule(int tabIndex);
    void routingEditRule(int tabIndex, const QString &value, const QString &policy);
    void routingRemoveRule(int tabIndex, const QString &value, const QString &policy);
    void routingImportClipboard(int tabIndex);
    void routingExportConfig();
    void routingResetRules(int tabIndex);
    void clearLogs();
    void exportLogs();
    void minimizeWindow();
    void maximizeWindow();
    void closeWindow();
    void exitProgram();

private:
    MdmBoxShellWindow *window = nullptr;
};
