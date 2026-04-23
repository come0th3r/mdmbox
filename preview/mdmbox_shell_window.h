#pragma once

#include <QMainWindow>
#include <QString>

class QWebChannel;
class QCloseEvent;
class QDir;
class QTimer;
class QWebEngineView;
class MdmBoxShellBridge;

class MdmBoxShellWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MdmBoxShellWindow(QWidget *parent = nullptr);
    ~MdmBoxShellWindow() override;

    void navigate(const QString &pageKey);
    void hookPage();
    void refreshPageState();
    void triggerConnectToggle();
    void triggerTunToggle();
    void triggerSystemProxyToggle();
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
    void triggerExportLogs();
    void triggerExitProgram();

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    QString designRootPath() const;
    QString htmlPathForPage(const QString &pageKey) const;
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
