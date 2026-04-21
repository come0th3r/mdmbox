#pragma once

#include <QObject>
#include <QElapsedTimer>
#include <QMainWindow>
#include <QPoint>

class QCheckBox;
class QCloseEvent;
class QComboBox;
class QFrame;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;
class QTableWidget;
class QTextEdit;
class QVBoxLayout;
class QWidget;

class MdmBoxWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MdmBoxWindow(QWidget *parent = nullptr);
    ~MdmBoxWindow() override;

    void updateStatus();

private slots:
    void onConnectClicked();
    void onLegacyModeClicked();
    void onNavButtonClicked(int index);
    void onAboutClicked();
    void onSystemProxyToggled(bool checked);
    void onTunModeToggled(bool checked);
    void onServerClicked(int row, int column);
    void onOpenAddSubscription();
    void onOpenRoutingEditor();
    void onImportRoutingFromClipboard();
    void onExportRoutingConfig();
    void onResetRoutingRules();
    void onRoutingDefaultOutboundChanged(int index);
    void onApplySettings();
    void onResetSettings();
    void onCopySettings();
    void onAddZapretPreset();
    void onClearLogs();
    void onExportLogs();

protected:
    void closeEvent(QCloseEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;

private:
    void setupUi();
    void applyTheme();
    void refreshServers();
    void refreshServerGroups();
    void refreshRoutingPage();
    void refreshSettingsPage();
    void refreshLogsPage();
    void syncCurrentPage();
    void applySettingsFromUi();
    void saveRoutingQuickSettings();
    void openRoutingRuleDialog(const QString &initialValue = QString(), const QString &initialPolicy = QString());
    void removeRoutingRule(const QString &value, const QString &policy);

    QString activeProfileName() const;
    QString activeProfileSubtitle() const;
    QString activeGroupName() const;
    QString prettifyOutbound(const QString &value) const;
    QStringList splitRules(const QString &text) const;

    QWidget *titleBar = nullptr;
    QPoint dragPosition;
    QElapsedTimer sessionTimer;
    bool suppressRoutingSignals = false;
    bool suppressSettingsSignals = false;
    int routingTabIndex = 0;
    bool pendingConnection = false;

    QStackedWidget *stackedWidget = nullptr;

    QPushButton *btnConnect = nullptr;
    QPushButton *btnSidebarConnect = nullptr;
    QLabel *lblConnectionBadge = nullptr;
    QLabel *lblIp = nullptr;
    QLabel *lblStatus = nullptr;
    QLabel *lblDownload = nullptr;
    QLabel *lblUpload = nullptr;
    QLabel *lblPing = nullptr;
    QLabel *lblServerHealthTitle = nullptr;
    QLabel *lblServerHealthSubtitle = nullptr;
    QCheckBox *chkSystemProxy = nullptr;
    QCheckBox *chkTunMode = nullptr;

    QTableWidget *serversTable = nullptr;
    QHBoxLayout *serverFilterLayout = nullptr;

    QList<QPushButton *> navButtons;
    QList<QPushButton *> routingTabButtons;

    QLabel *lblRoutingProfile = nullptr;
    QLabel *lblRoutingCount = nullptr;
    QComboBox *cmbDefaultOutbound = nullptr;
    QVBoxLayout *routingRulesLayout = nullptr;

    QLineEdit *txtRemoteDns = nullptr;
    QLineEdit *txtDirectDns = nullptr;
    QComboBox *cmbTunImplementation = nullptr;
    QLineEdit *txtMtu = nullptr;
    QCheckBox *chkVpnIpv6 = nullptr;
    QCheckBox *chkStrictRoute = nullptr;
    QCheckBox *chkFakeDns = nullptr;
    QCheckBox *chkSingleCore = nullptr;
    QCheckBox *chkHideConsole = nullptr;
    QCheckBox *chkWhitelistMode = nullptr;
    QCheckBox *chkZapretFix = nullptr;
    QTextEdit *txtBypassCidr = nullptr;
    QTextEdit *txtBypassProcesses = nullptr;

    QPlainTextEdit *txtLogs = nullptr;
    QLineEdit *txtLogFilter = nullptr;
    QCheckBox *chkLogAutoscroll = nullptr;
    QLabel *lblLogCount = nullptr;
    QLabel *lblLogErrors = nullptr;
    QLabel *lblLogSize = nullptr;
    QLabel *lblLogUptime = nullptr;
};

MdmBoxWindow *GetMdmBoxWindow();
