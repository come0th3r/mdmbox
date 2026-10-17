#pragma once

#include <QMainWindow>
#include <QString>
#include <QJsonObject>

class QWebChannel;
class QCloseEvent;
class QTimer;
class QWebEngineView;
class MdmBoxShellBridge;

class MdmBoxShellWindow final : public QMainWindow {
    Q_OBJECT

public:
    bool hasLocalShell() const;
    explicit MdmBoxShellWindow(QWidget *parent = nullptr, bool loadContent = true);
    ~MdmBoxShellWindow() override;

    void navigate(const QString &pageKey);
    void hookPage();
    void refreshPageState();
    void triggerConnectToggle();
    QJsonObject managedLoopbackStartResult(int groupId, const QString &requestId);
    QJsonObject managedLoopbackStopResult(const QString &requestId);
    QJsonObject managedLoopbackReconnectResult(int groupId, const QString &requestId);
    QJsonObject managedLoopbackRefreshResult(int groupId, const QString &requestId);
    QJsonObject managedRuntimeSnapshot() const;
    void triggerTunToggle();
    void triggerSystemProxyToggle();
    void triggerOpenBasicSettings();
    void triggerSetAutoStart(bool enabled);
    void triggerSetSubscriptionAutoUpdate(bool enabled, int intervalMinutes);
    void triggerClipboardImport();
    void triggerOpenLegacy();
    void triggerSelectServer(int id);
    void triggerSelectGroup(int gid);
    void triggerRoutingSetDefault(const QString &policy);
    void triggerRoutingAddRule(int tabIndex);
    void triggerRoutingEditRule(int tabIndex, const QString &value, const QString &policy);
    void triggerRoutingRemoveRule(int tabIndex, const QString &value, const QString &policy);
    void triggerRoutingImportClipboard(int tabIndex);
    void triggerRoutingExportConfig();
    void triggerRoutingResetRules(int tabIndex);
    void triggerClearLogs();
    void triggerCopyLogs();
    void triggerExportLogs();
    void triggerExitProgram();

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    QString htmlContentForPage(const QString &pageKey) const;
    QString buildChromeNormalizeScript() const;
    QString buildDashboardScript() const;
    QString buildServersScript() const;
    QString buildRoutingScript() const;
    QString buildLogsScript() const;
    QString buildRefreshScript() const;

    QWebEngineView *view = nullptr;
    QWebChannel *channel = nullptr;
    MdmBoxShellBridge *bridge = nullptr;
    QTimer *refreshTimer = nullptr;
    QString currentPage = QStringLiteral("dashboard");
    bool allowHardClose = false;
    bool connectToggleInFlight = false;
};
