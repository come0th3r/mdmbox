#pragma once

#include <QObject>
#include <QJsonObject>

class MdmBoxShellWindow;

class MdmBoxShellBridge final : public QObject {
    Q_OBJECT

public:
    explicit MdmBoxShellBridge(MdmBoxShellWindow *window, QObject *parent = nullptr);

public slots:
    void navigate(const QString &pageKey);
    void connectToggle();
    // Explicit loopback-only managed commands. requestId is echoed in the
    // result signal so JavaScript can correlate queued operations.
    void managedStart(const QJsonValue &groupId, const QString &requestId);
    void managedStop(const QString &requestId);
    void managedReconnect(const QJsonValue &groupId, const QString &requestId);
    QJsonObject managedSnapshot();
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

signals:
    void managedCommandResult(const QString &requestId, const QJsonObject &result);
    void managedRuntimeEvent(const QJsonObject &event);

private:
    MdmBoxShellWindow *window = nullptr;
};
