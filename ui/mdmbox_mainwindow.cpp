#include "mdmbox_mainwindow.h"

#include "mainwindow.h"
#include "3rdparty/WinCommander.hpp"
#include "db/Database.hpp"
#include "main/NekoGui.hpp"
#include "sub/GroupUpdater.hpp"

#include <QAction>
#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QSvgRenderer>
#include <QTableWidget>
#include <QTextBrowser>
#include <QTextEdit>
#include <QToolButton>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QScrollBar>

namespace {

const QStringList kNavLabels = {QObject::tr("Панель"), QObject::tr("Серверы"), QObject::tr("Маршрутизация"), QObject::tr("Настройки"), QObject::tr("Логи")};
const QStringList kNavIcons = {QStringLiteral("speed"), QStringLiteral("dns"), QStringLiteral("route"), QStringLiteral("settings"), QStringLiteral("terminal")};
const QStringList kPreset = {QStringLiteral("Discord.exe"), QStringLiteral("DiscordCanary.exe"), QStringLiteral("DiscordPTB.exe"), QStringLiteral("DiscordDevelopment.exe"), QStringLiteral("winws.exe"), QStringLiteral("zapret.exe"), QStringLiteral("zapret-discord.exe"), QStringLiteral("GoodbyeDPI.exe"), QStringLiteral("WinDivert.exe")};

QIcon svgIcon(const QString &name, const QColor &color = QColor("#5f6b7a"), int size = 18) {
    QFile file(QStringLiteral(":/neko/icons/%1.svg").arg(name));
    if (!file.open(QFile::ReadOnly)) return {};
    QByteArray svg = file.readAll();
    QByteArray fill = QByteArray("fill=\"") + color.name().toUtf8() + QByteArray("\"");
    svg.replace("fill=\"#1e1e1e\"", fill);
    svg.replace("fill=\"#000000\"", fill);
    svg.replace("fill=\"black\"", fill);
    QSvgRenderer renderer(svg);
    QPixmap pixmap(size, size);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    renderer.render(&painter);
    return QIcon(pixmap);
}

QStringList lines(const QString &text) { return text.split(QRegularExpression("[\r\n]+"), Qt::SkipEmptyParts); }

QString badge(const QString &name) {
    QString out;
    for (const QChar ch : name) if (ch.isLetter()) { out += ch.toUpper(); if (out.size() == 3) break; }
    return out.isEmpty() ? QStringLiteral("VPN") : out;
}

QString uptimeText(qint64 seconds) {
    return QStringLiteral("%1:%2:%3").arg(seconds / 3600, 2, 10, QLatin1Char('0')).arg((seconds / 60) % 60, 2, 10, QLatin1Char('0')).arg(seconds % 60, 2, 10, QLatin1Char('0'));
}

int defaultGroupId() {
    if (!NekoGui::profileManager->groupsTabOrder.isEmpty()) return NekoGui::profileManager->groupsTabOrder.first();
    return NekoGui::dataStore ? NekoGui::dataStore->current_group : 0;
}

int selectedProfileId() {
    return NekoGui::dataStore ? NekoGui::dataStore->selected_id : -1919;
}

void setSelectedProfileId(int id) {
    if (!NekoGui::dataStore) return;
    NekoGui::dataStore->selected_id = id;
    NekoGui::dataStore->Save();
}

class SwitchButton final : public QCheckBox {
public:
    explicit SwitchButton(QWidget *parent = nullptr) : QCheckBox(parent) {
        setCursor(Qt::PointingHandCursor);
        setFixedSize(48, 24);
    }

protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);

        const QRectF trackRect = rect().adjusted(0.5, 0.5, -0.5, -0.5);
        const QColor trackColor = isChecked() ? QColor("#0a72cf") : QColor("#d9dee7");
        const QColor borderColor = isChecked() ? QColor("#0a72cf") : QColor("#c4ccd8");
        painter.setPen(QPen(borderColor, 1));
        painter.setBrush(trackColor);
        painter.drawRoundedRect(trackRect, 12, 12);

        const qreal thumbX = isChecked() ? width() - 20.0 : 4.0;
        const QRectF thumbRect(thumbX, 4.0, 16.0, 16.0);
        painter.setPen(Qt::NoPen);
        painter.setBrush(Qt::white);
        painter.drawEllipse(thumbRect);
    }
};

struct RoutingRuleEntry {
    QString value;
    QString policy;
};

QString normalizedPolicy(const QString &policy) {
    const QString normalized = policy.trimmed().toLower();
    return normalized.isEmpty() ? QStringLiteral("bypass") : normalized;
}

QString displayPolicy(const QString &policy) {
    const QString normalized = normalizedPolicy(policy);
    if (normalized == QStringLiteral("proxy")) return QObject::tr("Proxy");
    if (normalized == QStringLiteral("block")) return QObject::tr("Block");
    return QObject::tr("Bypass");
}

QString displayRuleKind(int tabIndex, const QString &value) {
    if (tabIndex == 1) return QObject::tr("Процесс или путь");
    if (tabIndex == 2) return value.contains('/') ? QObject::tr("CIDR / подсеть") : QObject::tr("IP / адрес");
    if (value.startsWith(QStringLiteral("geosite:"), Qt::CaseInsensitive)) return QObject::tr("Список geosite");
    if (value.startsWith(QStringLiteral("domain:"), Qt::CaseInsensitive)) return QObject::tr("Точное доменное правило");
    if (value.contains('*')) return QObject::tr("Маска домена");
    return QObject::tr("Доменное правило");
}

void notifyDataStoreChanged(const QString &info) {
    if (MW_dialog_message) {
        MW_dialog_message(QString(), info);
    }
}

QString normalizedPlainRuleValue(QString value) {
    value = value.trimmed();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith('\'') && value.endsWith('\''))) {
        value = value.mid(1, value.size() - 2).trimmed();
    }
    return value;
}

void appendRulesFromValue(QList<RoutingRuleEntry> &rules, const QJsonValue &value, const QString &policy) {
    if (value.isArray()) {
        const auto array = value.toArray();
        for (const auto &item : array) {
            const QString text = normalizedPlainRuleValue(item.toString());
            if (!text.isEmpty()) rules.append({text, normalizedPolicy(policy)});
        }
        return;
    }

    const QString text = value.toString();
    for (const QString &line : lines(text)) {
        const QString normalized = normalizedPlainRuleValue(line);
        if (!normalized.isEmpty()) rules.append({normalized, normalizedPolicy(policy)});
    }
}

QJsonObject buildRoutingExportObject() {
    QJsonObject root;
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return root;

    auto toArray = [](const QString &raw) {
        QJsonArray out;
        for (const QString &line : lines(raw)) out.append(line);
        return out;
    };

    root.insert(QStringLiteral("active_routing"), NekoGui::dataStore->active_routing);
    root.insert(QStringLiteral("def_outbound"), normalizedPolicy(NekoGui::dataStore->routing->def_outbound));
    root.insert(QStringLiteral("direct_domain"), toArray(NekoGui::dataStore->routing->direct_domain));
    root.insert(QStringLiteral("proxy_domain"), toArray(NekoGui::dataStore->routing->proxy_domain));
    root.insert(QStringLiteral("block_domain"), toArray(NekoGui::dataStore->routing->block_domain));
    root.insert(QStringLiteral("direct_ip"), toArray(NekoGui::dataStore->routing->direct_ip));
    root.insert(QStringLiteral("proxy_ip"), toArray(NekoGui::dataStore->routing->proxy_ip));
    root.insert(QStringLiteral("block_ip"), toArray(NekoGui::dataStore->routing->block_ip));
    root.insert(QStringLiteral("vpn_rule_process"), toArray(NekoGui::dataStore->vpn_rule_process));
    root.insert(QStringLiteral("vpn_rule_white"), NekoGui::dataStore->vpn_rule_white);
    root.insert(QStringLiteral("vpn_rule_cidr"), toArray(NekoGui::dataStore->vpn_rule_cidr));
    return root;
}

QJsonArray toRuleArray(const QString &raw) {
    QJsonArray out;
    for (const QString &line : lines(raw)) out.append(line);
    return out;
}

void syncMdmBoxRoutingSnapshot() {
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;

    QJsonObject snapshot;
    snapshot.insert(QStringLiteral("default_outbound"), normalizedPolicy(NekoGui::dataStore->routing->def_outbound));
    snapshot.insert(QStringLiteral("active_routing"), NekoGui::dataStore->active_routing);

    QJsonObject domains;
    domains.insert(QStringLiteral("bypass"), toRuleArray(NekoGui::dataStore->routing->direct_domain));
    domains.insert(QStringLiteral("proxy"), toRuleArray(NekoGui::dataStore->routing->proxy_domain));
    domains.insert(QStringLiteral("block"), toRuleArray(NekoGui::dataStore->routing->block_domain));
    snapshot.insert(QStringLiteral("domains"), domains);

    QJsonObject ips;
    ips.insert(QStringLiteral("bypass"), toRuleArray(NekoGui::dataStore->routing->direct_ip));
    ips.insert(QStringLiteral("proxy"), toRuleArray(NekoGui::dataStore->routing->proxy_ip));
    ips.insert(QStringLiteral("block"), toRuleArray(NekoGui::dataStore->routing->block_ip));
    snapshot.insert(QStringLiteral("ips"), ips);

    QJsonObject applications;
    applications.insert(QStringLiteral("mode"), NekoGui::dataStore->vpn_rule_white ? QStringLiteral("proxy") : QStringLiteral("bypass"));
    applications.insert(QStringLiteral("items"), toRuleArray(NekoGui::dataStore->vpn_rule_process));
    snapshot.insert(QStringLiteral("applications"), applications);
    snapshot.insert(QStringLiteral("cidr"), toRuleArray(NekoGui::dataStore->vpn_rule_cidr));

    NekoGui::dataStore->routing->mdmbox_rules_json = QString::fromUtf8(QJsonDocument(snapshot).toJson(QJsonDocument::Indented));
}

void saveActiveRoutingState(bool routeChanged) {
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;
    if (NekoGui::dataStore->active_routing.trimmed().isEmpty()) {
        NekoGui::dataStore->active_routing = QStringLiteral("Default");
    }
    syncMdmBoxRoutingSnapshot();
    NekoGui::dataStore->routing->fn = ROUTES_PREFIX + NekoGui::dataStore->active_routing;
    NekoGui::dataStore->routing->Save();
    NekoGui::dataStore->Save();
    notifyDataStoreChanged(routeChanged ? QStringLiteral("UpdateDataStore,RouteChanged") : QStringLiteral("UpdateDataStore"));
}

void saveTunRuleState() {
    if (!NekoGui::dataStore) return;
    if (NekoGui::dataStore->routing) {
        syncMdmBoxRoutingSnapshot();
        NekoGui::dataStore->routing->fn = ROUTES_PREFIX + NekoGui::dataStore->active_routing;
        NekoGui::dataStore->routing->Save();
    }
    NekoGui::dataStore->Save();
    notifyDataStoreChanged(QStringLiteral("UpdateDataStore,RouteChanged,VPNChanged"));
}

QList<RoutingRuleEntry> collectRoutingRules(int tabIndex) {
    QList<RoutingRuleEntry> rules;
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return rules;

    auto appendList = [&](const QString &raw, const QString &policy) {
        for (const QString &value : lines(raw)) rules.append({value, normalizedPolicy(policy)});
    };

    if (tabIndex == 0) {
        appendList(NekoGui::dataStore->routing->direct_domain, QStringLiteral("bypass"));
        appendList(NekoGui::dataStore->routing->proxy_domain, QStringLiteral("proxy"));
        appendList(NekoGui::dataStore->routing->block_domain, QStringLiteral("block"));
    } else if (tabIndex == 1) {
        appendList(NekoGui::dataStore->vpn_rule_process, NekoGui::dataStore->vpn_rule_white ? QStringLiteral("proxy") : QStringLiteral("bypass"));
    } else {
        appendList(NekoGui::dataStore->routing->direct_ip, QStringLiteral("bypass"));
        appendList(NekoGui::dataStore->routing->proxy_ip, QStringLiteral("proxy"));
        appendList(NekoGui::dataStore->routing->block_ip, QStringLiteral("block"));
    }

    return rules;
}

void storeRoutingRules(int tabIndex, const QList<RoutingRuleEntry> &inputRules) {
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;

    QList<RoutingRuleEntry> rules;
    QStringList seen;
    for (const auto &rule : inputRules) {
        const QString value = rule.value.trimmed();
        const QString policy = normalizedPolicy(rule.policy);
        const QString key = policy + QLatin1Char('|') + value.toLower();
        if (value.isEmpty() || seen.contains(key)) continue;
        seen.append(key);
        rules.append({value, policy});
    }

    auto joinByPolicy = [&](const QString &policy) {
        QStringList values;
        for (const auto &rule : rules) if (rule.policy == policy) values.append(rule.value);
        return values.join("\n");
    };

    if (tabIndex == 0) {
        NekoGui::dataStore->routing->direct_domain = joinByPolicy(QStringLiteral("bypass"));
        NekoGui::dataStore->routing->proxy_domain = joinByPolicy(QStringLiteral("proxy"));
        NekoGui::dataStore->routing->block_domain = joinByPolicy(QStringLiteral("block"));
        saveActiveRoutingState(true);
        return;
    }

    if (tabIndex == 1) {
        QStringList processValues;
        for (const auto &rule : rules) processValues.append(rule.value);
        NekoGui::dataStore->vpn_rule_process = processValues.join("\n");
        if (!rules.isEmpty()) NekoGui::dataStore->vpn_rule_white = rules.first().policy == QStringLiteral("proxy");
        saveTunRuleState();
        return;
    }

    NekoGui::dataStore->routing->direct_ip = joinByPolicy(QStringLiteral("bypass"));
    NekoGui::dataStore->routing->proxy_ip = joinByPolicy(QStringLiteral("proxy"));
    NekoGui::dataStore->routing->block_ip = joinByPolicy(QStringLiteral("block"));
    saveActiveRoutingState(true);
}

} // namespace

MdmBoxWindow *g_mdmBoxWindow = nullptr;

MdmBoxWindow *GetMdmBoxWindow() {
    if (!g_mdmBoxWindow) g_mdmBoxWindow = new MdmBoxWindow();
    return g_mdmBoxWindow;
}

MdmBoxWindow::MdmBoxWindow(QWidget *parent) : QMainWindow(parent) {
    g_mdmBoxWindow = this;
    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowSystemMenuHint | Qt::WindowMinimizeButtonHint);
    setAttribute(Qt::WA_TranslucentBackground);
    resize(1040, 760);
    sessionTimer.start();
    setupUi();
    if (NekoGui::dataStore && NekoGui::dataStore->routing &&
        normalizedPolicy(NekoGui::dataStore->routing->def_outbound) == QStringLiteral("proxy")) {
        NekoGui::dataStore->routing->def_outbound = QStringLiteral("bypass");
        NekoGui::dataStore->routing->Save();
    }
    applyTheme();
    refreshServerGroups();
    refreshServers();
    refreshRoutingPage();
    refreshSettingsPage();
    refreshLogsPage();
    updateStatus();
    auto *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [this] { updateStatus(); syncCurrentPage(); });
    timer->start(1000);
}

MdmBoxWindow::~MdmBoxWindow() {
    if (g_mdmBoxWindow == this) g_mdmBoxWindow = nullptr;
}

void MdmBoxWindow::closeEvent(QCloseEvent *event) {
    hide();
    if (auto *mw = GetMainWindow()) mw->hide();
    event->ignore();
}

void MdmBoxWindow::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton && titleBar && titleBar->geometry().contains(event->pos())) {
        dragPosition = event->globalPosition().toPoint() - frameGeometry().topLeft();
        event->accept();
        return;
    }
    QMainWindow::mousePressEvent(event);
}

void MdmBoxWindow::mouseMoveEvent(QMouseEvent *event) {
    if ((event->buttons() & Qt::LeftButton) && !dragPosition.isNull()) {
        move(event->globalPosition().toPoint() - dragPosition);
        event->accept();
        return;
    }
    QMainWindow::mouseMoveEvent(event);
}

void MdmBoxWindow::setupUi() {
    auto *root = new QWidget(this);
    auto *rootLayout = new QVBoxLayout(root);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    auto *surface = new QWidget(root);
    surface->setObjectName("surface");
    auto *shadow = new QGraphicsDropShadowEffect(surface);
    shadow->setBlurRadius(24);
    shadow->setOffset(0, 8);
    shadow->setColor(QColor(10, 22, 44, 36));
    surface->setGraphicsEffect(shadow);
    rootLayout->addWidget(surface);
    setCentralWidget(root);

    auto *surfaceLayout = new QVBoxLayout(surface);
    surfaceLayout->setContentsMargins(0, 0, 0, 0);
    surfaceLayout->setSpacing(0);

    titleBar = new QWidget(surface);
    titleBar->setObjectName("titleBar");
    titleBar->setFixedHeight(34);
    auto *titleLayout = new QHBoxLayout(titleBar);
    titleLayout->setContentsMargins(14, 0, 12, 0);
    titleLayout->addWidget(new QLabel(QStringLiteral("MDMBOX"), titleBar));
    titleLayout->addStretch();
    auto makeWindowButton = [&](const QString &icon, auto fn) {
        auto *b = new QPushButton(titleBar);
        b->setObjectName("windowButton");
        b->setFixedSize(28, 28);
        b->setIcon(svgIcon(icon, QColor("#6a7280"), 14));
        b->setIconSize(QSize(14, 14));
        connect(b, &QPushButton::clicked, this, fn);
        titleLayout->addWidget(b);
    };
    makeWindowButton(QStringLiteral("remove"), &QWidget::showMinimized);
    makeWindowButton(QStringLiteral("check_box_outline_blank"), [this] { isMaximized() ? showNormal() : showMaximized(); });
    makeWindowButton(QStringLiteral("close"), [this] { close(); });
    surfaceLayout->addWidget(titleBar);

    auto *body = new QHBoxLayout;
    body->setSpacing(0);
    surfaceLayout->addLayout(body, 1);

    auto *sidebar = new QFrame(surface);
    sidebar->setObjectName("sidebar");
    sidebar->setFixedWidth(190);
    auto *side = new QVBoxLayout(sidebar);
    side->setContentsMargins(18, 18, 18, 16);
    auto *brandBox = new QWidget(sidebar);
    auto *brandLayout = new QVBoxLayout(brandBox);
    brandLayout->setContentsMargins(0, 0, 0, 0);
    brandLayout->setSpacing(2);
    auto *brandTitle = new QLabel(QStringLiteral("MDMBOX"), brandBox);
    brandTitle->setObjectName("brandTitle");
    auto *brandSubtitle = new QLabel(QStringLiteral("Как Nekobox но хуже"), brandBox);
    brandSubtitle->setObjectName("brandSubtitle");
    brandLayout->addWidget(brandTitle);
    brandLayout->addWidget(brandSubtitle);
    side->addWidget(brandBox);
    side->addSpacing(14);
    for (int i = 0; i < kNavLabels.size(); ++i) {
        if (i == 4) {
            side->addStretch();
            auto *sep = new QFrame(sidebar);
            sep->setObjectName("sep");
            sep->setFixedHeight(1);
            side->addWidget(sep);
        }
        auto *b = new QPushButton(kNavLabels[i], sidebar);
        b->setObjectName("navButton");
        b->setCheckable(true);
        b->setChecked(i == 0);
        b->setIcon(svgIcon(kNavIcons[i], i == 0 ? QColor("#0a72cf") : QColor("#5f6b7a")));
        b->setIconSize(QSize(18, 18));
        connect(b, &QPushButton::clicked, this, [this, i] { onNavButtonClicked(i); });
        navButtons.append(b);
        side->addWidget(b);
    }
    auto *about = new QPushButton(tr("О программе"), sidebar);
    about->setObjectName("navButton");
    about->setIcon(svgIcon(QStringLiteral("info")));
    connect(about, &QPushButton::clicked, this, &MdmBoxWindow::onAboutClicked);
    side->addWidget(about);
    auto *legacyButton = new QPushButton(tr("Legacy режим"), sidebar);
    legacyButton->setObjectName("secondaryButton");
    const QIcon legacyIcon = svgIcon(QStringLiteral("history_edu"));
    if (!legacyIcon.isNull()) legacyButton->setIcon(legacyIcon);
    connect(legacyButton, &QPushButton::clicked, this, &MdmBoxWindow::onLegacyModeClicked);
    side->addWidget(legacyButton);
    btnSidebarConnect = new QPushButton(tr("Подключиться"), sidebar);
    btnSidebarConnect->setObjectName("primaryButton");
    btnSidebarConnect->setFixedHeight(40);
    connect(btnSidebarConnect, &QPushButton::clicked, this, &MdmBoxWindow::onConnectClicked);
    side->addWidget(btnSidebarConnect);
    body->addWidget(sidebar);

    stackedWidget = new QStackedWidget(surface);
    body->addWidget(stackedWidget, 1);

    auto makePage = [&](const QString &title, const QString &subtitle, QWidget **pageOut = nullptr) {
        auto *page = new QWidget(stackedWidget);
        auto *layout = new QVBoxLayout(page);
        layout->setContentsMargins(26, 20, 26, 20);
        layout->setSpacing(12);
        if (!title.isEmpty()) {
            auto *ttl = new QLabel(title, page);
            ttl->setObjectName("pageTitle");
            layout->addWidget(ttl);
        }
        if (!subtitle.isEmpty()) {
            auto *sub = new QLabel(subtitle, page);
            sub->setObjectName("pageSubtitle");
            layout->addWidget(sub);
        }
        if (pageOut) *pageOut = page;
        return layout;
    };

    QWidget *page = nullptr;
    auto *dash = makePage(QString(), QString(), &page);
    dash->setContentsMargins(24, 20, 24, 20);
    dash->setSpacing(0);

    auto *dashboardCanvas = new QFrame(page);
    dashboardCanvas->setObjectName("dashboardCanvas");
    auto *canvasShadow = new QGraphicsDropShadowEffect(dashboardCanvas);
    canvasShadow->setBlurRadius(28);
    canvasShadow->setOffset(0, 10);
    canvasShadow->setColor(QColor(48, 72, 104, 24));
    dashboardCanvas->setGraphicsEffect(canvasShadow);

    auto *canvas = new QVBoxLayout(dashboardCanvas);
    canvas->setContentsMargins(24, 18, 24, 12);
    canvas->setSpacing(0);

    auto *dashTop = new QHBoxLayout;
    dashTop->setContentsMargins(0, 0, 0, 0);
    dashTop->addStretch();

    auto *menuShell = new QFrame(dashboardCanvas);
    menuShell->setObjectName("menuDotsShell");
    menuShell->setFixedSize(56, 56);
    auto *menuShellLayout = new QVBoxLayout(menuShell);
    menuShellLayout->setContentsMargins(0, 0, 0, 0);

    auto *menuButton = new QPushButton(menuShell);
    menuButton->setObjectName("menuDotsButton");
    menuButton->setFlat(true);
    menuButton->setCursor(Qt::PointingHandCursor);
    menuButton->setFixedSize(40, 40);
    const QIcon moreIcon = svgIcon(QStringLiteral("more_vert"), QColor("#303948"), 16);
    if (moreIcon.isNull()) {
        menuButton->setText(QStringLiteral("⋮"));
    } else {
        menuButton->setIcon(moreIcon);
        menuButton->setIconSize(QSize(16, 16));
    }
    menuShellLayout->addWidget(menuButton, 0, Qt::AlignCenter);

    auto *menu = new QMenu(menuButton);
    auto *addRuleAction = menu->addAction(svgIcon(QStringLiteral("add"), QColor("#0a72cf"), 16), tr("Добавить правило маршрутизации"));
    auto *legacyAction = menu->addAction(legacyIcon.isNull() ? QIcon() : legacyIcon, tr("Legacy режим Nekobox"));
    menu->addSeparator();
    auto *quitAction = menu->addAction(svgIcon(QStringLiteral("power_settings_new"), QColor("#d93025"), 16), tr("Выключить"));
    connect(addRuleAction, &QAction::triggered, this, [this] {
        onNavButtonClicked(2);
        onOpenRoutingEditor();
    });
    connect(legacyAction, &QAction::triggered, this, &MdmBoxWindow::onLegacyModeClicked);
    connect(quitAction, &QAction::triggered, this, [] {
        if (auto *mw = GetMainWindow()) {
            mw->on_menu_exit_triggered();
        } else {
            QCoreApplication::quit();
        }
    });
    connect(menuButton, &QPushButton::clicked, this, [menuButton, menu] {
        const QSize menuSize = menu->sizeHint();
        const QPoint popupPos = menuButton->mapToGlobal(QPoint(menuButton->width() - menuSize.width(), menuButton->height() + 8));
        menu->popup(popupPos);
    });
    dashTop->addWidget(menuShell);
    canvas->addLayout(dashTop);

    canvas->addSpacing(72);
    auto *statusStack = new QWidget(dashboardCanvas);
    auto *statusLayout = new QVBoxLayout(statusStack);
    statusLayout->setContentsMargins(0, 0, 0, 0);
    statusLayout->setSpacing(12);
    lblConnectionBadge = new QLabel(tr("ОТКЛЮЧЕНО"), statusStack);
    lblConnectionBadge->setObjectName("statusBadge");
    lblConnectionBadge->setAlignment(Qt::AlignCenter);
    lblIp = new QLabel(QStringLiteral("-.-.-.-"), statusStack);
    lblIp->setObjectName("heroIp");
    lblIp->setAlignment(Qt::AlignCenter);
    lblStatus = new QLabel(tr("Подключение не установлено"), statusStack);
    lblStatus->setObjectName("heroSubtitle");
    lblStatus->setAlignment(Qt::AlignCenter);
    statusLayout->addWidget(lblConnectionBadge, 0, Qt::AlignHCenter);
    statusLayout->addWidget(lblIp);
    statusLayout->addWidget(lblStatus);
    canvas->addWidget(statusStack, 0, Qt::AlignHCenter);

    canvas->addSpacing(34);
    btnConnect = new QPushButton(QStringLiteral("⏻\n") + tr("Подключить"), dashboardCanvas);
    btnConnect->setObjectName("heroButton");
    btnConnect->setFixedSize(224, 224);
    auto *buttonShadow = new QGraphicsDropShadowEffect(btnConnect);
    buttonShadow->setBlurRadius(44);
    buttonShadow->setOffset(0, 16);
    buttonShadow->setColor(QColor(10, 114, 207, 48));
    btnConnect->setGraphicsEffect(buttonShadow);
    connect(btnConnect, &QPushButton::clicked, this, &MdmBoxWindow::onConnectClicked);
    canvas->addWidget(btnConnect, 0, Qt::AlignHCenter);

    canvas->addSpacing(48);
    auto makeToggleCard = [&](const QString &title, const QString &subtitle, const QString &iconName, const QString &bubbleName, QCheckBox **out) {
        auto *card = new QFrame(dashboardCanvas);
        card->setObjectName("toggleCard");
        card->setFixedSize(328, 106);
        auto *cardShadow = new QGraphicsDropShadowEffect(card);
        cardShadow->setBlurRadius(20);
        cardShadow->setOffset(0, 6);
        cardShadow->setColor(QColor(72, 96, 124, 16));
        card->setGraphicsEffect(cardShadow);
        auto *layout = new QHBoxLayout(card);
        layout->setContentsMargins(24, 24, 24, 24);
        layout->setSpacing(16);

        auto *bubble = new QFrame(card);
        bubble->setObjectName(bubbleName);
        bubble->setFixedSize(48, 48);
        auto *bubbleLayout = new QVBoxLayout(bubble);
        bubbleLayout->setContentsMargins(0, 0, 0, 0);
        auto *icon = new QLabel(bubble);
        icon->setPixmap(svgIcon(iconName, bubbleName == QStringLiteral("toggleBubblePrimary") ? QColor("#bc5b00") : QColor("#456084"), 20).pixmap(20, 20));
        icon->setAlignment(Qt::AlignCenter);
        bubbleLayout->addWidget(icon);

        auto *textLayout = new QVBoxLayout;
        textLayout->setSpacing(2);
        auto *titleLabel = new QLabel(title, card);
        titleLabel->setObjectName("toggleTitle");
        auto *subtitleLabel = new QLabel(subtitle, card);
        subtitleLabel->setObjectName("toggleSubtitle");
        subtitleLabel->setWordWrap(true);
        textLayout->addWidget(titleLabel);
        textLayout->addWidget(subtitleLabel);

        auto *toggle = new SwitchButton(card);
        toggle->setObjectName("switchToggle");
        layout->addWidget(bubble);
        layout->addLayout(textLayout, 1);
        layout->addWidget(toggle, 0, Qt::AlignVCenter);
        *out = toggle;
        return card;
    };

    auto *toggleRow = new QHBoxLayout;
    toggleRow->setSpacing(16);
    chkTunMode = nullptr;
    chkSystemProxy = nullptr;
    auto *tunCard = makeToggleCard(tr("TUN Режим"), tr("Виртуализация L3 интерфейса"), QStringLiteral("route"), QStringLiteral("toggleBubblePrimary"), &chkTunMode);
    auto *proxyCard = makeToggleCard(tr("Системный прокси"), tr("Настройка браузеров"), QStringLiteral("dns"), QStringLiteral("toggleBubbleSecondary"), &chkSystemProxy);
    connect(chkTunMode, &QCheckBox::clicked, this, &MdmBoxWindow::onTunModeToggled);
    connect(chkSystemProxy, &QCheckBox::clicked, this, &MdmBoxWindow::onSystemProxyToggled);
    toggleRow->addStretch();
    toggleRow->addWidget(tunCard);
    toggleRow->addWidget(proxyCard);
    toggleRow->addStretch();
    canvas->addLayout(toggleRow);

    canvas->addStretch();
    auto *footerBar = new QFrame(dashboardCanvas);
    footerBar->setObjectName("footerBar");
    footerBar->setFixedHeight(48);
    auto *footer = new QHBoxLayout(footerBar);
    footer->setContentsMargins(28, 0, 28, 0);
    lblDownload = new QLabel(QStringLiteral("0 KB/s"), footerBar);
    lblUpload = new QLabel(QStringLiteral("0 KB/s"), footerBar);
    lblPing = new QLabel(tr("Пинг: 0 мс"), footerBar);
    auto *downIcon = new QLabel(QStringLiteral("↓"), footerBar);
    downIcon->setObjectName("footerIconPrimary");
    auto *upIcon = new QLabel(QStringLiteral("↑"), footerBar);
    upIcon->setObjectName("footerIconSecondary");
    footer->addWidget(downIcon);
    footer->addWidget(lblDownload);
    footer->addSpacing(22);
    footer->addWidget(upIcon);
    footer->addWidget(lblUpload);
    footer->addStretch();
    footer->addWidget(lblPing);
    canvas->addWidget(footerBar);
    dash->addWidget(dashboardCanvas, 1);
    stackedWidget->addWidget(page);

    auto *servers = makePage(tr("Доступные узлы"), tr("Выберите сервер для подключения."), &page);
    auto *top = new QHBoxLayout;
    top->addStretch();
    auto *pingTest = new QPushButton(tr("Проверить пинг"), page);
    pingTest->setObjectName("secondaryButton");
    connect(pingTest, &QPushButton::clicked, this, [this] {
        if (auto *mw = GetMainWindow()) {
            if (auto *action = mw->findChild<QAction *>(QStringLiteral("menu_tcp_ping"))) action->trigger();
        }
        refreshServers();
    });
    top->addWidget(pingTest);
    auto *deleteServer = new QPushButton(tr("Удалить сервер"), page);
    deleteServer->setObjectName("secondaryButton");
    connect(deleteServer, &QPushButton::clicked, this, [this] {
        if (!serversTable) return;
        const int row = serversTable->currentRow();
        if (row < 0) return;
        auto *item = serversTable->item(row, 0);
        if (!item) return;
        const int id = item->data(Qt::UserRole).toInt();
        auto ent = NekoGui::profileManager->GetProfile(id);
        if (!ent) return;
        const QString name = ent->bean ? ent->bean->name : tr("Без имени");
        if (QMessageBox::question(this, tr("Удалить сервер"), tr("Удалить сервер \"%1\"?").arg(name)) != QMessageBox::Yes) return;
        if (NekoGui::dataStore->started_id == id) {
            if (auto *mw = GetMainWindow()) mw->neko_stop();
        }
        if (selectedProfileId() == id) setSelectedProfileId(-1919);
        if (auto group = NekoGui::profileManager->GetGroup(ent->gid)) {
            group->order.removeAll(id);
            group->Save();
        }
        NekoGui::profileManager->DeleteProfile(id);
        if (auto *mw = GetMainWindow()) {
            mw->refresh_groups();
            mw->show_group(NekoGui::dataStore->current_group);
        }
        refreshServerGroups();
        refreshServers();
        updateStatus();
    });
    top->addWidget(deleteServer);
    auto *deleteGroup = new QPushButton(tr("Удалить список"), page);
    deleteGroup->setObjectName("secondaryButton");
    connect(deleteGroup, &QPushButton::clicked, this, [this] {
        const int gid = NekoGui::dataStore->current_group;
        auto group = NekoGui::profileManager->GetGroup(gid);
        if (!group) return;
        if (NekoGui::profileManager->groups.size() <= 1) {
            QMessageBox::information(this, tr("Удалить список"), tr("Нельзя удалить последний список."));
            return;
        }
        if (QMessageBox::question(this, tr("Удалить список"), tr("Удалить список \"%1\" со всеми серверами?").arg(group->name)) != QMessageBox::Yes) return;
        auto started = NekoGui::profileManager->GetProfile(NekoGui::dataStore->started_id);
        if (started && started->gid == gid) {
            if (auto *mw = GetMainWindow()) mw->neko_stop();
        }
        if (auto selected = NekoGui::profileManager->GetProfile(selectedProfileId()); selected && selected->gid == gid) {
            setSelectedProfileId(-1919);
        }
        NekoGui::profileManager->DeleteGroup(gid);
        int nextGid = -1;
        for (const auto &pair : NekoGui::profileManager->groups) {
            nextGid = pair.first;
            break;
        }
        if (nextGid >= 0) NekoGui::dataStore->current_group = nextGid;
        if (auto *mw = GetMainWindow()) {
            mw->refresh_groups();
            if (nextGid >= 0) mw->show_group(nextGid);
        }
        refreshServerGroups();
        refreshServers();
        updateStatus();
    });
    top->addWidget(deleteGroup);
    auto *addSub = new QPushButton(tr("Добавить ссылку"), page);
    addSub->setObjectName("primaryButton");
    connect(addSub, &QPushButton::clicked, this, &MdmBoxWindow::onOpenAddSubscription);
    top->addWidget(addSub);
    servers->addLayout(top);
    serverFilterLayout = new QHBoxLayout;
    servers->addLayout(serverFilterLayout);
    serversTable = new QTableWidget(page);
    serversTable->setColumnCount(4);
    serversTable->setHorizontalHeaderLabels({tr("СТАТУС"), tr("РЕГИОН И НАЗВАНИЕ"), tr("ЗАДЕРЖКА"), tr("ТРАФИК")});
    serversTable->verticalHeader()->setVisible(false);
    serversTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    serversTable->setFocusPolicy(Qt::NoFocus);
    serversTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    serversTable->setColumnWidth(0, 80);
    serversTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    serversTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Fixed);
    serversTable->setColumnWidth(2, 120);
    serversTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Fixed);
    serversTable->setColumnWidth(3, 120);
    connect(serversTable, &QTableWidget::cellClicked, this, &MdmBoxWindow::onServerClicked);
    servers->addWidget(serversTable);
    auto *health = new QFrame(page);
    health->setObjectName("card");
    auto *healthLayout = new QVBoxLayout(health);
    lblServerHealthTitle = new QLabel(tr("Нет данных"), health);
    lblServerHealthTitle->setObjectName("cardTitle");
    lblServerHealthSubtitle = new QLabel(tr("Пока нет метрик стабильности"), health);
    lblServerHealthSubtitle->setObjectName("cardSubtitle");
    healthLayout->addWidget(lblServerHealthTitle);
    healthLayout->addWidget(lblServerHealthSubtitle);
    servers->addWidget(health, 0, Qt::AlignLeft);
    servers->addStretch();
    stackedWidget->addWidget(page);

    auto *routing = makePage(tr("Правила маршрутизации"), tr("Определите способ обработки трафика по домену, приложению или адресу."), &page);
    auto *routeTop = new QHBoxLayout;
    lblRoutingProfile = new QLabel(page);
    lblRoutingProfile->setObjectName("cardSubtitle");
    cmbDefaultOutbound = new QComboBox(page);
    cmbDefaultOutbound->addItems({QStringLiteral("Bypass"), QStringLiteral("Proxy"), QStringLiteral("Block")});
    connect(cmbDefaultOutbound, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MdmBoxWindow::onRoutingDefaultOutboundChanged);
    routeTop->addWidget(lblRoutingProfile);
    routeTop->addStretch();
    routeTop->addWidget(cmbDefaultOutbound);
    routing->addLayout(routeTop);
    auto *tabs = new QHBoxLayout;
    for (int i = 0; i < 3; ++i) {
        auto *b = new QPushButton(i == 0 ? tr("По домену") : (i == 1 ? tr("По приложению") : tr("По сайту")), page);
        b->setObjectName("tabButton");
        b->setCheckable(true);
        b->setChecked(i == 0);
        connect(b, &QPushButton::clicked, this, [this, i] { routingTabIndex = i; for (int j = 0; j < routingTabButtons.size(); ++j) routingTabButtons[j]->setChecked(j == i); refreshRoutingPage(); });
        routingTabButtons.append(b);
        tabs->addWidget(b);
    }
    tabs->addStretch();
    auto *routeEdit = new QPushButton(tr("Добавить правило"), page);
    routeEdit->setObjectName("linkButton");
    connect(routeEdit, &QPushButton::clicked, this, &MdmBoxWindow::onOpenRoutingEditor);
    tabs->addWidget(routeEdit);
    auto *routeImport = new QPushButton(tr("Импорт из буфера"), page);
    routeImport->setObjectName("linkButton");
    connect(routeImport, &QPushButton::clicked, this, &MdmBoxWindow::onImportRoutingFromClipboard);
    tabs->addWidget(routeImport);
    auto *routeExport = new QPushButton(tr("Экспорт JSON"), page);
    routeExport->setObjectName("linkButton");
    connect(routeExport, &QPushButton::clicked, this, &MdmBoxWindow::onExportRoutingConfig);
    tabs->addWidget(routeExport);
    auto *routeReset = new QPushButton(tr("Сбросить правила"), page);
    routeReset->setObjectName("linkButton");
    connect(routeReset, &QPushButton::clicked, this, &MdmBoxWindow::onResetRoutingRules);
    tabs->addWidget(routeReset);
    routing->addLayout(tabs);
    auto *rulesCard = new QFrame(page);
    rulesCard->setObjectName("card");
    auto *rulesCardLayout = new QVBoxLayout(rulesCard);
    lblRoutingCount = new QLabel(rulesCard);
    lblRoutingCount->setObjectName("metric");
    rulesCardLayout->addWidget(lblRoutingCount);
    routingRulesLayout = new QVBoxLayout;
    rulesCardLayout->addLayout(routingRulesLayout);
    routing->addWidget(rulesCard, 1);
    stackedWidget->addWidget(page);

    auto *settings = makePage(tr("Настройки"), tr("Управление параметрами подключения и поведения приложения."), &page);
    txtRemoteDns = new QLineEdit(page);
    txtDirectDns = new QLineEdit(page);
    cmbTunImplementation = new QComboBox(page);
    cmbTunImplementation->addItems({QStringLiteral("Mixed"), QStringLiteral("System")});
    txtMtu = new QLineEdit(page);
    chkVpnIpv6 = new QCheckBox(tr("Вкл. IPv6 Tun"), page);
    chkStrictRoute = new QCheckBox(QStringLiteral("Strict Route"), page);
    chkFakeDns = new QCheckBox(QStringLiteral("FakeDNS"), page);
    chkSingleCore = new QCheckBox(tr("Встроен. Tun"), page);
    chkHideConsole = new QCheckBox(tr("Скрывать окно"), page);
    chkWhitelistMode = new QCheckBox(tr("Whitelist mode"), page);
    chkZapretFix = new QCheckBox(tr("Фикс Zapret-Discord"), page);
    txtBypassCidr = new QTextEdit(page);
    txtBypassProcesses = new QTextEdit(page);
    txtRemoteDns->setObjectName("field");
    txtDirectDns->setObjectName("field");
    cmbTunImplementation->setObjectName("field");
    txtMtu->setObjectName("field");
    txtBypassCidr->setObjectName("field");
    txtBypassProcesses->setObjectName("field");
    settings->addWidget(new QLabel(tr("Основной DNS"), page));
    settings->addWidget(txtRemoteDns);
    settings->addWidget(new QLabel(tr("DNS для прямых запросов"), page));
    settings->addWidget(txtDirectDns);
    settings->addWidget(new QLabel(tr("Stack"), page));
    settings->addWidget(cmbTunImplementation);
    settings->addWidget(new QLabel(tr("MTU"), page));
    settings->addWidget(txtMtu);
    auto *checks = new QHBoxLayout;
    for (QCheckBox *c : {chkVpnIpv6, chkStrictRoute, chkFakeDns, chkSingleCore, chkHideConsole}) checks->addWidget(c);
    settings->addLayout(checks);
    settings->addWidget(new QLabel(tr("Пропускать CIDR"), page));
    settings->addWidget(txtBypassCidr);
    settings->addWidget(new QLabel(tr("Bypass Process / Path"), page));
    settings->addWidget(txtBypassProcesses);
    settings->addWidget(chkWhitelistMode);
    settings->addWidget(chkZapretFix);
    auto *setButtons = new QHBoxLayout;
    auto *preset = new QPushButton(tr("Add Zapret / Discord preset"), page);
    preset->setObjectName("secondaryButton");
    connect(preset, &QPushButton::clicked, this, &MdmBoxWindow::onAddZapretPreset);
    auto *copy = new QPushButton(tr("Копировать настройки"), page);
    copy->setObjectName("secondaryButton");
    connect(copy, &QPushButton::clicked, this, &MdmBoxWindow::onCopySettings);
    auto *apply = new QPushButton(tr("OK"), page);
    apply->setObjectName("primaryButton");
    connect(apply, &QPushButton::clicked, this, &MdmBoxWindow::onApplySettings);
    auto *reset = new QPushButton(tr("Cancel"), page);
    reset->setObjectName("secondaryButton");
    connect(reset, &QPushButton::clicked, this, &MdmBoxWindow::onResetSettings);
    setButtons->addWidget(preset);
    setButtons->addStretch();
    setButtons->addWidget(copy);
    setButtons->addWidget(apply);
    setButtons->addWidget(reset);
    settings->addLayout(setButtons);
    stackedWidget->addWidget(page);

    auto *logs = makePage(tr("Системный журнал"), QString(), &page);
    auto *logButtons = new QHBoxLayout;
    logButtons->addStretch();
    auto *clear = new QPushButton(tr("Очистить"), page);
    clear->setObjectName("secondaryButton");
    connect(clear, &QPushButton::clicked, this, &MdmBoxWindow::onClearLogs);
    auto *exportBtn = new QPushButton(tr("Экспорт"), page);
    exportBtn->setObjectName("secondaryButton");
    connect(exportBtn, &QPushButton::clicked, this, &MdmBoxWindow::onExportLogs);
    logButtons->addWidget(clear);
    logButtons->addWidget(exportBtn);
    logs->addLayout(logButtons);
    chkLogAutoscroll = new QCheckBox(tr("Auto-scroll"), page);
    chkLogAutoscroll->setChecked(true);
    logs->addWidget(chkLogAutoscroll, 0, Qt::AlignRight);
    txtLogs = new QPlainTextEdit(page);
    txtLogs->setObjectName("console");
    txtLogs->setReadOnly(true);
    logs->addWidget(txtLogs, 1);
    txtLogFilter = new QLineEdit(page);
    txtLogFilter->setPlaceholderText(tr("Введите команду или фильтр..."));
    connect(txtLogFilter, &QLineEdit::textChanged, this, [this] { refreshLogsPage(); });
    logs->addWidget(txtLogFilter);
    auto *metrics = new QHBoxLayout;
    auto mk = [&](QLabel **out, const QString &t) { auto *box = new QFrame(page); box->setObjectName("card"); auto *l = new QVBoxLayout(box); l->addWidget(new QLabel(t, box)); *out = new QLabel(QStringLiteral("0"), box); (*out)->setObjectName("metric"); l->addWidget(*out); metrics->addWidget(box); };
    mk(&lblLogCount, tr("ВСЕГО ЛОГОВ"));
    mk(&lblLogErrors, tr("ОШИБОК"));
    mk(&lblLogSize, tr("РАЗМЕР"));
    mk(&lblLogUptime, tr("АПТАЙМ"));
    logs->addLayout(metrics);
    stackedWidget->addWidget(page);
}

void MdmBoxWindow::applyTheme() {
    setStyleSheet(R"(
        QMainWindow { background: transparent; }
        QWidget#surface { background: #f7f9fc; border: 1px solid rgba(187,197,212,0.55); border-radius: 16px; }
        QWidget#titleBar { background: rgba(255,255,255,0.70); border-top-left-radius: 16px; border-top-right-radius: 16px; border-bottom: 1px solid rgba(187,197,212,0.75); color: #1f2733; font-size: 12px; font-weight: 600; }
        QPushButton#windowButton { background: transparent; border: none; border-radius: 6px; }
        QPushButton#windowButton:hover { background: rgba(95,107,122,0.10); }
        QFrame#sidebar { background: #f4f7fb; border-right: 1px solid rgba(187,197,212,0.75); border-bottom-left-radius: 16px; }
        QLabel#brandTitle { color: #0a72cf; font-size: 16px; font-weight: 800; }
        QLabel#brandSubtitle { color: #6f7a8a; font-size: 10px; font-weight: 600; }
        QFrame#card, QFrame#hero { background: rgba(255,255,255,0.96); border: 1px solid rgba(187,197,212,0.75); border-radius: 14px; }
        QFrame#hero { background: qradialgradient(cx:0.5, cy:0.35, radius:0.7, stop:0 rgba(10,114,207,0.15), stop:1 rgba(255,255,255,0.98)); }
        QFrame#dashboardCanvas {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(214,232,251,0.94), stop:0.52 rgba(243,247,252,0.97), stop:1 rgba(255,255,255,0.99));
            border: 1px solid rgba(187,197,212,0.88);
            border-radius: 22px;
        }
        QFrame#toggleCard { background: rgba(255,255,255,0.72); border: none; border-radius: 18px; }
        QFrame#footerBar {
            background: rgba(255,255,255,0.38);
            border: none;
            border-top: 1px solid rgba(225,230,238,0.98);
            border-bottom-left-radius: 18px;
            border-bottom-right-radius: 18px;
        }
        QFrame#toggleBubblePrimary { background: rgba(188,91,0,0.10); border-radius: 12px; }
        QFrame#toggleBubbleSecondary { background: rgba(69,96,132,0.10); border-radius: 12px; }
        QFrame#menuDotsShell { background: rgba(255,255,255,0.62); border: none; border-radius: 14px; }
        QPushButton#navButton { min-height: 38px; border: none; border-radius: 10px; background: transparent; color: #4c5868; font-size: 13px; font-weight: 600; text-align: left; padding: 0 12px; }
        QPushButton#navButton:checked { background: rgba(10,114,207,0.10); color: #0a72cf; }
        QPushButton#navButton:hover:!checked { background: rgba(95,107,122,0.08); }
        QFrame#sep { background: rgba(187,197,212,0.95); border: none; }
        QPushButton#primaryButton { background: #0a72cf; color: white; border: none; border-radius: 10px; padding: 0 16px; min-height: 38px; font-size: 12px; font-weight: 700; }
        QPushButton#primaryButton[state="connected"] { background: #9aa6b6; }
        QPushButton#primaryButton[state="disconnected"] { background: #0a72cf; }
        QPushButton#primaryButton[state="connecting"] { background: #e7b400; color: #243040; }
        QPushButton#primaryButton:hover { background: #075fad; }
        QPushButton#secondaryButton { background: white; color: #243040; border: 1px solid rgba(187,197,212,0.85); border-radius: 10px; padding: 0 14px; min-height: 36px; font-size: 12px; font-weight: 600; }
        QPushButton#menuDotsButton { background: transparent; border: none; color: #303948; font-size: 19px; font-weight: 700; text-align: center; padding: 0; }
        QPushButton#menuDotsButton:hover { color: #0a72cf; background: rgba(10,114,207,0.06); border-radius: 12px; }
        QPushButton#linkButton { background: transparent; border: none; color: #0a72cf; font-size: 12px; font-weight: 700; }
        QPushButton#tabButton { background: transparent; border: none; border-bottom: 2px solid transparent; color: #6f7a8a; font-size: 12px; font-weight: 700; padding: 6px 0; }
        QPushButton#tabButton:checked { color: #0a72cf; border-bottom-color: #0a72cf; }
        QLabel#pageTitle { color: #202733; font-size: 18px; font-weight: 800; }
        QLabel#pageSubtitle, QLabel#cardSubtitle { color: #6f7a8a; font-size: 12px; }
        QLabel#cardTitle { color: #202733; font-size: 14px; font-weight: 700; }
        QLabel#toggleTitle { color: #1f2733; font-size: 14px; font-weight: 700; }
        QLabel#toggleSubtitle { color: #6f7a8a; font-size: 11px; }
        QLabel#metric { color: #202733; font-size: 22px; font-weight: 800; }
        QLabel#statusBadge { border-radius: 14px; padding: 6px 18px; font-size: 11px; font-weight: 800; min-width: 128px; max-width: 128px; }
        QLabel#statusBadge[state="connected"] { background: rgba(10,114,207,0.10); color: #0a72cf; }
        QLabel#statusBadge[state="disconnected"] { background: rgba(217,48,37,0.12); color: #d93025; }
        QLabel#statusBadge[state="connecting"] { background: rgba(231,180,0,0.18); color: #8a6a00; }
        QLabel#heroIp { color: #202733; font-size: 42px; font-weight: 800; letter-spacing: 2px; }
        QLabel#heroSubtitle { color: #6f7a8a; font-size: 13px; }
        QPushButton#heroButton {
            background: qradialgradient(cx:0.38, cy:0.32, radius:0.85, stop:0 #2c8ae3, stop:1 #0a72cf);
            color: white;
            border: none;
            border-radius: 112px;
            font-size: 24px;
            font-weight: 800;
        }
        QPushButton#heroButton[state="disconnected"] { background: qradialgradient(cx:0.38, cy:0.32, radius:0.85, stop:0 #cfd6e1, stop:1 #9ca8b9); }
        QPushButton#heroButton[state="connecting"] { background: qradialgradient(cx:0.38, cy:0.32, radius:0.85, stop:0 #f7cd42, stop:1 #dfab00); color: #243040; }
        QPushButton#heroButton:hover { background: qradialgradient(cx:0.38, cy:0.32, radius:0.85, stop:0 #3b96ea, stop:1 #0c6cc2); }
        QLabel#footerIconPrimary { color: #0a72cf; font-size: 11px; font-weight: 800; }
        QLabel#footerIconSecondary { color: #bc5b00; font-size: 11px; font-weight: 800; }
        QMenu {
            background: rgba(255,255,255,0.98);
            border: 1px solid rgba(187,197,212,0.92);
            border-radius: 12px;
            padding: 8px;
        }
        QMenu::item {
            padding: 9px 14px 9px 34px;
            border-radius: 8px;
            color: #243040;
            font-size: 12px;
            font-weight: 600;
        }
        QMenu::item:selected { background: rgba(10,114,207,0.08); color: #0a72cf; }
        QMenu::separator { height: 1px; background: rgba(225,230,238,1); margin: 6px 8px; }
        QMenu::icon { left: 12px; }
        QTableWidget { background: white; border: 1px solid rgba(187,197,212,0.85); border-radius: 14px; }
        QHeaderView::section { background: #f4f7fb; color: #738097; font-size: 10px; font-weight: 800; border: none; border-bottom: 1px solid rgba(187,197,212,0.85); padding: 12px 16px; }
        QTableWidget::item { border-bottom: 1px solid rgba(235,240,246,1); }
        QLineEdit#field, QTextEdit#field, QComboBox#field, QLineEdit { background: #f4f7fb; border: 1px solid rgba(187,197,212,0.85); border-radius: 10px; padding: 8px 10px; color: #263241; }
        QPlainTextEdit#console { background: #060b1c; color: #c5d0e3; border: 1px solid #1c2741; border-radius: 12px; font-family: Consolas; }
    )");
}

void MdmBoxWindow::onConnectClicked() {
    if (auto *mw = GetMainWindow()) {
        if (NekoGui::dataStore->started_id >= 0) {
            pendingConnection = false;
            mw->neko_stop();
        } else {
            int targetId = selectedProfileId();
            if (targetId < 0 && serversTable && serversTable->currentRow() >= 0) {
                if (auto *item = serversTable->item(serversTable->currentRow(), 0)) {
                    targetId = item->data(Qt::UserRole).toInt();
                }
            }
            if (targetId < 0) {
                if (auto group = NekoGui::profileManager->GetGroup(NekoGui::dataStore->current_group); group && !group->order.isEmpty()) {
                    targetId = group->order.first();
                }
            }

            pendingConnection = targetId >= 0;
            if (targetId >= 0) {
                setSelectedProfileId(targetId);
                if (auto profile = NekoGui::profileManager->GetProfile(targetId)) {
                    NekoGui::dataStore->current_group = profile->gid;
                    NekoGui::dataStore->Save();
                    mw->show_group(profile->gid);
                }
                mw->neko_start(targetId);
                QTimer::singleShot(8000, this, [this] {
                    if (NekoGui::dataStore->started_id < 0) {
                        pendingConnection = false;
                        updateStatus();
                    }
                });
            } else {
                mw->neko_start();
            }
        }
    }
    updateStatus();
    syncCurrentPage();
}

void MdmBoxWindow::onLegacyModeClicked() {
    hide();
    if (auto *mw = GetMainWindow()) {
        mw->show_group(NekoGui::dataStore->current_group);
        mw->show();
        mw->raise();
        mw->activateWindow();
    }
}

void MdmBoxWindow::onNavButtonClicked(int index) {
    for (int i = 0; i < navButtons.size(); ++i) {
        navButtons[i]->setChecked(i == index);
        navButtons[i]->setIcon(svgIcon(kNavIcons[i], i == index ? QColor("#0a72cf") : QColor("#5f6b7a")));
    }
    if (index < stackedWidget->count()) stackedWidget->setCurrentIndex(index);
    syncCurrentPage();
}

void MdmBoxWindow::onAboutClicked() {
    QStringList content;
    QFile file(QStringLiteral(":/neko/mdmbox_about.txt"));
    if (file.open(QFile::ReadOnly | QFile::Text)) {
        content = lines(QString::fromUtf8(file.readAll()));
    }
    if (content.isEmpty()) {
        content << tr("MDMBOX UI shell поверх существующей логики NekoBox.");
    }
    while (content.size() > 10) content.removeLast();

    QMessageBox box(this);
    box.setWindowTitle(QStringLiteral("MDMBOX"));
    box.setText(content.join("\n"));
    auto *legacy = box.addButton(tr("Legacy режим"), QMessageBox::ActionRole);
    box.addButton(QMessageBox::Ok);
    box.exec();
    if (box.clickedButton() == legacy) onLegacyModeClicked();
}

void MdmBoxWindow::onSystemProxyToggled(bool checked) {
    if (auto *mw = GetMainWindow()) mw->neko_set_spmode_system_proxy(checked);
    if (NekoGui::dataStore) {
        NekoGui::dataStore->remember_spmode.removeAll(QStringLiteral("system_proxy"));
        if (checked) NekoGui::dataStore->remember_spmode.append(QStringLiteral("system_proxy"));
        NekoGui::dataStore->Save();
    }
    updateStatus();
}

void MdmBoxWindow::onTunModeToggled(bool checked) {
#ifdef Q_OS_WIN
    if (checked && NekoGui::dataStore && NekoGui::dataStore->vpn_internal_tun && !NekoGui::IsAdmin()) {
        auto n = QMessageBox::warning(this, software_name, tr("Please run NekoBox as admin"), QMessageBox::Yes | QMessageBox::No);
        if (n == QMessageBox::Yes) {
            QDir::setCurrent(QApplication::applicationDirPath());
            auto arguments = NekoGui::dataStore->argv;
            if (arguments.length() > 0) {
                arguments.removeFirst();
                arguments.removeAll("-tray");
                arguments.removeAll("-flag_restart_tun_on");
                arguments.removeAll("-flag_reorder");
            }
            const bool isLauncher = qEnvironmentVariable("NKR_FROM_LAUNCHER") == "1";
            if (isLauncher) arguments.prepend("--");
            const auto program = isLauncher ? QStringLiteral("./launcher") : QApplication::applicationFilePath();
            arguments << "-flag_restart_tun_on";
            NekoGui::dataStore->remember_spmode.removeAll(QStringLiteral("vpn"));
            NekoGui::dataStore->remember_spmode.append(QStringLiteral("vpn"));
            NekoGui::dataStore->Save();
            WinCommander::runProcessElevated(program, arguments, "", WinCommander::SW_NORMAL, false);
            qApp->quit();
            return;
        }
        updateStatus();
        return;
    }
#endif
    if (auto *mw = GetMainWindow()) mw->neko_set_spmode_vpn(checked);
    if (NekoGui::dataStore) {
        NekoGui::dataStore->remember_spmode.removeAll(QStringLiteral("vpn"));
        if (checked) NekoGui::dataStore->remember_spmode.append(QStringLiteral("vpn"));
        NekoGui::dataStore->Save();
    }
    updateStatus();
}

void MdmBoxWindow::onServerClicked(int row, int) {
    auto *item = serversTable ? serversTable->item(row, 0) : nullptr;
    if (!item) return;
    int id = item->data(Qt::UserRole).toInt();
    if (id <= 0) return;
    setSelectedProfileId(id);
    if (auto *mw = GetMainWindow()) {
        if (NekoGui::dataStore->started_id >= 0 && NekoGui::dataStore->started_id != id) {
            pendingConnection = true;
            mw->neko_start(id);
        }
    }
    refreshServers();
    updateStatus();
}

void MdmBoxWindow::onOpenAddSubscription() {
    const QString clipboard = QApplication::clipboard()->text().trimmed();
    if (clipboard.isEmpty()) {
        QMessageBox::information(this, tr("Буфер обмена"), tr("Буфер обмена пуст. Скопируйте ссылку или набор серверов и повторите."));
        return;
    }

    const bool isSingleLine = !clipboard.contains('\n') && !clipboard.contains('\r');
    const bool isSubscriptionUrl = isSingleLine &&
                                   (clipboard.startsWith(QStringLiteral("http://"), Qt::CaseInsensitive) ||
                                    clipboard.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive));

    auto refreshImportedState = [this](int targetGid) {
        NekoGui::dataStore->current_group = targetGid;
        if (auto *mw = GetMainWindow()) {
            mw->refresh_groups();
            mw->show_group(targetGid);
        }
        refreshServerGroups();
        refreshServers();
        updateStatus();
    };

    auto createGroup = [&](const QString &title) {
        auto group = NekoGui::ProfileManager::NewGroup();
        group->name = title.trimmed().isEmpty() ? tr("Новый список") : title.trimmed();
        NekoGui::profileManager->AddGroup(group);
        return group;
    };

    auto importAsLinks = [&](int targetGid) {
        NekoGui_sub::RawUpdater rawUpdater;
        rawUpdater.gid_add_to = targetGid;
        rawUpdater.update(clipboard);

        if (rawUpdater.updated_order.isEmpty()) {
            QMessageBox::information(this, tr("Импорт"), tr("В буфере обмена не найдено поддерживаемых серверных ссылок."));
            return;
        }

        if (auto group = NekoGui::profileManager->GetGroup(targetGid)) {
            for (const auto &profile : rawUpdater.updated_order) {
                if (profile && profile->gid != targetGid) {
                    NekoGui::profileManager->MoveProfile(profile, targetGid);
                }
                if (!group->order.contains(profile->id)) group->order.append(profile->id);
            }
            group->Save();
        }
        NekoGui::dataStore->imported_count = rawUpdater.updated_order.count();
        refreshImportedState(targetGid);
    };

    auto importAsSubscription = [&](int targetGid) {
        if (auto group = NekoGui::profileManager->GetGroup(targetGid)) {
            group->url = clipboard;
            group->Save();
        }
        NekoGui_sub::groupUpdater->AsyncUpdate(clipboard, targetGid, [this, refreshImportedState, targetGid] {
            QMetaObject::invokeMethod(this, [refreshImportedState, targetGid] {
                refreshImportedState(targetGid);
            }, Qt::QueuedConnection);
        });
    };

    if (isSubscriptionUrl) {
        QMessageBox box(this);
        box.setWindowTitle(tr("Добавить ссылку"));
        box.setText(tr("Если это подписка, куда ее добавить?"));
        auto *asCurrentSubscription = box.addButton(tr("В список по умолчанию"), QMessageBox::ActionRole);
        auto *asNewSubscription = box.addButton(tr("В новую папку"), QMessageBox::ActionRole);
        auto *asLinks = box.addButton(tr("Как обычные ссылки"), QMessageBox::ActionRole);
        box.addButton(QMessageBox::Cancel);
        box.exec();

        const int currentGid = defaultGroupId();
        if (box.clickedButton() == asCurrentSubscription) {
            importAsSubscription(currentGid);
            return;
        }
        if (box.clickedButton() == asNewSubscription) {
            const QString host = QUrl(clipboard).host();
            auto group = createGroup(host.isEmpty() ? tr("Новый список") : host);
            importAsSubscription(group->id);
            return;
        }
        if (box.clickedButton() == asLinks) {
            importAsLinks(currentGid);
        }
        return;
    }

    QMessageBox box(this);
    box.setWindowTitle(tr("Добавить серверы"));
    box.setText(tr("Куда добавить серверы из буфера обмена?"));
    auto *toCurrent = box.addButton(tr("В список по умолчанию"), QMessageBox::ActionRole);
    auto *toNew = box.addButton(tr("В новую папку"), QMessageBox::ActionRole);
    box.addButton(QMessageBox::Cancel);
    box.exec();

    if (box.clickedButton() == toCurrent) {
        importAsLinks(defaultGroupId());
        return;
    }
    if (box.clickedButton() == toNew) {
        auto group = createGroup(tr("Импортированные серверы"));
        importAsLinks(group->id);
    }
}

void MdmBoxWindow::onOpenRoutingEditor() {
    openRoutingRuleDialog();
}

void MdmBoxWindow::onImportRoutingFromClipboard() {
    const QString raw = QApplication::clipboard()->text().trimmed();
    if (raw.isEmpty()) {
        QMessageBox::information(this, tr("Импорт маршрутизации"), tr("Буфер обмена пуст."));
        return;
    }

    QList<RoutingRuleEntry> imported = collectRoutingRules(routingTabIndex);
    QString processPolicy = NekoGui::dataStore->vpn_rule_white ? QStringLiteral("proxy") : QStringLiteral("bypass");

    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(raw.toUtf8(), &error);
    if (error.error == QJsonParseError::NoError && document.isObject()) {
        const QJsonObject object = document.object();
        if (routingTabIndex == 0) {
            appendRulesFromValue(imported, object.value(QStringLiteral("direct_domain")), QStringLiteral("bypass"));
            appendRulesFromValue(imported, object.value(QStringLiteral("proxy_domain")), QStringLiteral("proxy"));
            appendRulesFromValue(imported, object.value(QStringLiteral("block_domain")), QStringLiteral("block"));
        } else if (routingTabIndex == 1) {
            if (object.contains(QStringLiteral("vpn_rule_white"))) {
                processPolicy = object.value(QStringLiteral("vpn_rule_white")).toBool() ? QStringLiteral("proxy") : QStringLiteral("bypass");
            }
            appendRulesFromValue(imported, object.value(QStringLiteral("vpn_rule_process")), processPolicy);
        } else {
            appendRulesFromValue(imported, object.value(QStringLiteral("direct_ip")), QStringLiteral("bypass"));
            appendRulesFromValue(imported, object.value(QStringLiteral("proxy_ip")), QStringLiteral("proxy"));
            appendRulesFromValue(imported, object.value(QStringLiteral("block_ip")), QStringLiteral("block"));
        }
    } else {
        const QString fallbackPolicy = routingTabIndex == 1
            ? (NekoGui::dataStore->vpn_rule_white ? QStringLiteral("proxy") : QStringLiteral("bypass"))
            : normalizedPolicy(cmbDefaultOutbound->currentText());
        for (QString line : lines(raw)) {
            line = line.trimmed();
            if (line.isEmpty() || line.startsWith('#')) continue;

            QString policy = fallbackPolicy;
            QString value = line;
            const QString lower = line.toLower();
            if (lower.startsWith(QStringLiteral("[proxy]"))) {
                policy = QStringLiteral("proxy");
                value = line.mid(7).trimmed();
            } else if (lower.startsWith(QStringLiteral("[bypass]")) || lower.startsWith(QStringLiteral("[direct]"))) {
                policy = QStringLiteral("bypass");
                value = line.mid(line.indexOf(']') + 1).trimmed();
            } else if (lower.startsWith(QStringLiteral("[block]"))) {
                policy = QStringLiteral("block");
                value = line.mid(7).trimmed();
            } else if (lower.startsWith(QStringLiteral("proxy:"))) {
                policy = QStringLiteral("proxy");
                value = line.mid(6).trimmed();
            } else if (lower.startsWith(QStringLiteral("bypass:")) || lower.startsWith(QStringLiteral("direct:"))) {
                policy = QStringLiteral("bypass");
                value = line.mid(line.indexOf(':') + 1).trimmed();
            } else if (lower.startsWith(QStringLiteral("block:"))) {
                policy = QStringLiteral("block");
                value = line.mid(6).trimmed();
            }

            value = normalizedPlainRuleValue(value);
            if (!value.isEmpty()) imported.append({value, policy});
        }
    }

    if (imported.isEmpty()) {
        QMessageBox::information(this, tr("Импорт маршрутизации"), tr("Не удалось распознать правила в буфере обмена."));
        return;
    }

    storeRoutingRules(routingTabIndex, imported);
    refreshSettingsPage();
    refreshRoutingPage();
}

void MdmBoxWindow::onExportRoutingConfig() {
    const QString path = QFileDialog::getSaveFileName(this, tr("Экспорт маршрутизации"), QStringLiteral("mdmbox-routing.txt"), tr("Text files (*.txt)"));
    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QFile::WriteOnly | QFile::Text)) return;
    file.write(QJsonDocument(buildRoutingExportObject()).toJson(QJsonDocument::Indented));
}

void MdmBoxWindow::onResetRoutingRules() {
    if (QMessageBox::question(this, tr("Сбросить правила"), tr("Очистить правила текущей вкладки?")) != QMessageBox::Yes) return;

    if (routingTabIndex == 0) {
        NekoGui::dataStore->routing->direct_domain.clear();
        NekoGui::dataStore->routing->proxy_domain.clear();
        NekoGui::dataStore->routing->block_domain.clear();
        saveActiveRoutingState(true);
    } else if (routingTabIndex == 1) {
        NekoGui::dataStore->vpn_rule_process.clear();
        saveTunRuleState();
    } else {
        NekoGui::dataStore->routing->direct_ip.clear();
        NekoGui::dataStore->routing->proxy_ip.clear();
        NekoGui::dataStore->routing->block_ip.clear();
        saveActiveRoutingState(true);
    }

    refreshSettingsPage();
    refreshRoutingPage();
}

void MdmBoxWindow::openRoutingRuleDialog(const QString &initialValue, const QString &initialPolicy) {
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;

    QDialog dialog(this);
    dialog.setWindowTitle(initialValue.isEmpty() ? tr("Добавить правило") : tr("Изменить правило"));
    dialog.setModal(true);

    auto *layout = new QVBoxLayout(&dialog);
    auto *form = new QFormLayout;
    auto *valueEdit = new QLineEdit(&dialog);
    valueEdit->setPlaceholderText(
        routingTabIndex == 0 ? tr("Например: *.google.com") :
        routingTabIndex == 1 ? tr("Например: Discord.exe") :
                               tr("Например: 8.8.8.8/32"));
    valueEdit->setText(initialValue);
    form->addRow(tr("Правило"), valueEdit);

    auto *policyCombo = new QComboBox(&dialog);
    if (routingTabIndex == 1) {
        policyCombo->addItems({QStringLiteral("Bypass"), QStringLiteral("Proxy")});
        policyCombo->setCurrentText(initialPolicy.isEmpty()
                                        ? (NekoGui::dataStore->vpn_rule_white ? QStringLiteral("Proxy") : QStringLiteral("Bypass"))
                                        : displayPolicy(initialPolicy));
    } else {
        policyCombo->addItems({QStringLiteral("Bypass"), QStringLiteral("Proxy"), QStringLiteral("Block")});
        policyCombo->setCurrentText(initialPolicy.isEmpty() ? cmbDefaultOutbound->currentText() : displayPolicy(initialPolicy));
    }
    form->addRow(tr("Политика"), policyCombo);
    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted) return;

    const QString newValue = valueEdit->text().trimmed();
    if (newValue.isEmpty()) return;

    const QString selectedPolicy = normalizedPolicy(policyCombo->currentText());
    QList<RoutingRuleEntry> rules = collectRoutingRules(routingTabIndex);

    for (int i = rules.size() - 1; i >= 0; --i) {
        if (rules[i].value.compare(initialValue, Qt::CaseInsensitive) == 0 &&
            rules[i].policy == normalizedPolicy(initialPolicy)) {
            rules.removeAt(i);
        }
    }

    if (routingTabIndex == 1) {
        const bool newWhitelist = selectedPolicy == QStringLiteral("proxy");
        if (NekoGui::dataStore->vpn_rule_white != newWhitelist && !NekoGui::dataStore->vpn_rule_process.trimmed().isEmpty()) {
            const auto answer = QMessageBox::question(
                this,
                tr("Изменить режим процессов"),
                newWhitelist
                    ? tr("Переключить список процессов в Proxy mode? Это изменит поведение всех правил на вкладке приложений.")
                    : tr("Переключить список процессов в Bypass mode? Это изменит поведение всех правил на вкладке приложений."));
            if (answer != QMessageBox::Yes) return;
        }
        for (auto &rule : rules) rule.policy = selectedPolicy;
    }

    for (int i = rules.size() - 1; i >= 0; --i) {
        if (rules[i].value.compare(newValue, Qt::CaseInsensitive) == 0 &&
            rules[i].policy == selectedPolicy) {
            rules.removeAt(i);
        }
    }
    rules.append({newValue, selectedPolicy});
    storeRoutingRules(routingTabIndex, rules);
    refreshSettingsPage();
    refreshRoutingPage();
}

void MdmBoxWindow::removeRoutingRule(const QString &value, const QString &policy) {
    QList<RoutingRuleEntry> rules = collectRoutingRules(routingTabIndex);
    for (int i = rules.size() - 1; i >= 0; --i) {
        if (rules[i].value.compare(value, Qt::CaseInsensitive) == 0 && rules[i].policy == normalizedPolicy(policy)) {
            rules.removeAt(i);
            break;
        }
    }
    storeRoutingRules(routingTabIndex, rules);
    refreshSettingsPage();
    refreshRoutingPage();
}

void MdmBoxWindow::onRoutingDefaultOutboundChanged(int) {
    if (suppressRoutingSignals || !NekoGui::dataStore || !NekoGui::dataStore->routing) return;
    NekoGui::dataStore->routing->def_outbound = cmbDefaultOutbound->currentText().toLower();
    saveActiveRoutingState(true);
    if (auto *mw = GetMainWindow(); mw && NekoGui::dataStore->started_id >= 0) mw->neko_start(NekoGui::dataStore->started_id);
}

void MdmBoxWindow::onApplySettings() { applySettingsFromUi(); }
void MdmBoxWindow::onResetSettings() { refreshSettingsPage(); }

void MdmBoxWindow::onCopySettings() {
    QString dump = QStringLiteral("remote_dns=%1\ndirect_dns=%2\nvpn_mtu=%3\nvpn_rule_cidr=\n%4\nvpn_rule_process=\n%5")
        .arg(txtRemoteDns->text(), txtDirectDns->text(), txtMtu->text(), txtBypassCidr->toPlainText(), txtBypassProcesses->toPlainText());
    QGuiApplication::clipboard()->setText(dump);
}

void MdmBoxWindow::onAddZapretPreset() {
    QStringList current = lines(txtBypassProcesses->toPlainText());
    for (const QString &v : kPreset) if (!current.contains(v, Qt::CaseInsensitive)) current << v;
    txtBypassProcesses->setPlainText(current.join("\n"));
    chkZapretFix->setChecked(true);
}

void MdmBoxWindow::onClearLogs() {
    if (auto *mw = GetMainWindow()) if (auto *browser = mw->findChild<QTextBrowser *>("masterLogBrowser")) browser->clear();
    refreshLogsPage();
}

void MdmBoxWindow::onExportLogs() {
    QString path = QFileDialog::getSaveFileName(this, tr("Экспорт журнала"), QStringLiteral("mdmbox-log.txt"), tr("Text files (*.txt)"));
    if (path.isEmpty()) return;
    QFile file(path);
    if (file.open(QFile::WriteOnly | QFile::Text)) file.write(txtLogs->toPlainText().toUtf8());
}

void MdmBoxWindow::updateStatus() {
    bool connected = NekoGui::dataStore->started_id >= 0;
    if (connected) {
        pendingConnection = false;
        if (selectedProfileId() != NekoGui::dataStore->started_id) setSelectedProfileId(NekoGui::dataStore->started_id);
    }
    const bool connecting = !connected && pendingConnection;
    const QString state = connecting ? QStringLiteral("connecting") : (connected ? QStringLiteral("connected") : QStringLiteral("disconnected"));
    lblConnectionBadge->setProperty("state", state);
    btnConnect->setProperty("state", state);
    btnSidebarConnect->setProperty("state", state);
    lblConnectionBadge->style()->unpolish(lblConnectionBadge);
    lblConnectionBadge->style()->polish(lblConnectionBadge);
    btnConnect->style()->unpolish(btnConnect);
    btnConnect->style()->polish(btnConnect);
    btnSidebarConnect->style()->unpolish(btnSidebarConnect);
    btnSidebarConnect->style()->polish(btnSidebarConnect);

    lblConnectionBadge->setText(connecting ? tr("ПОДКЛЮЧЕНИЕ") : (connected ? tr("ПОДКЛЮЧЕНО") : tr("ОТКЛЮЧЕНО")));
    lblIp->setText(connected ? QStringLiteral("192.168.1.104") : QStringLiteral("-.-.-.-"));
    QString name = activeProfileName();
    lblStatus->setText(connecting
                           ? tr("Подождите, профиль запускается...")
                           : (connected ? tr("Виртуальный IP через %1").arg(name.isEmpty() ? tr("активный профиль") : name)
                                        : tr("Подключение не установлено")));
    btnConnect->setText(QStringLiteral("⏻\n") + (connecting ? tr("Подключение") : (connected ? tr("Выключить") : tr("Включить"))));
    btnSidebarConnect->setText(connecting ? tr("Подключение") : (connected ? tr("Отключить") : tr("Подключиться")));
    { QSignalBlocker a(chkTunMode), b(chkSystemProxy); chkTunMode->setChecked(NekoGui::dataStore->spmode_vpn); chkSystemProxy->setChecked(NekoGui::dataStore->spmode_system_proxy); }
    if (auto *mw = GetMainWindow()) if (auto *speed = mw->findChild<QLabel *>("label_speed")) {
        QStringList p = lines(speed->text());
        if (p.size() >= 2) { lblDownload->setText(p[0].section(':', 1).trimmed()); lblUpload->setText(p[1].section(':', 1).trimmed()); }
    }
    auto profile = NekoGui::profileManager->GetProfile(NekoGui::dataStore->started_id);
    lblPing->setText(profile && profile->latency > 0 ? tr("Пинг: %1 мс").arg(profile->latency) : tr("Пинг: 0 мс"));
}

void MdmBoxWindow::refreshServers() {
    if (!serversTable) return;
    serversTable->setRowCount(0);
    auto group = NekoGui::profileManager->GetGroup(NekoGui::dataStore->current_group);
    if (!group) return;
    int total = 0, count = 0;
    const int selectedId = selectedProfileId();
    int selectedRow = -1;
    for (int id : group->order) {
        auto profile = NekoGui::profileManager->GetProfile(id);
        if (!profile) continue;
        int row = serversTable->rowCount();
        serversTable->insertRow(row);
        const bool isStarted = id == NekoGui::dataStore->started_id;
        const bool isSelected = id == selectedId;
        auto *status = new QTableWidgetItem(isStarted ? QStringLiteral("●") : (isSelected ? QStringLiteral("◉") : QStringLiteral("○")));
        status->setData(Qt::UserRole, id);
        status->setForeground(isStarted || isSelected ? QColor("#0a72cf") : QColor("#c0cad8"));
        status->setTextAlignment(Qt::AlignCenter);
        serversTable->setItem(row, 0, status);
        QString name = profile->bean ? profile->bean->name : tr("Без имени");
        QString addr = profile->bean ? profile->bean->DisplayAddress() : QString();
        serversTable->setItem(row, 1, new QTableWidgetItem(QStringLiteral("[%1] %2\n%3").arg(badge(name), name, isStarted ? tr("АКТИВЕН") : (isSelected ? tr("ВЫБРАН") : addr))));
        serversTable->setItem(row, 2, new QTableWidgetItem(profile->latency > 0 ? tr("%1 мс").arg(profile->latency) : QStringLiteral("-")));
        serversTable->setItem(row, 3, new QTableWidgetItem(QStringLiteral("-")));
        if (isStarted || isSelected) selectedRow = row;
        if (profile->latency > 0) { total += profile->latency; ++count; }
    }
    if (selectedRow >= 0) {
        serversTable->selectRow(selectedRow);
        serversTable->setCurrentCell(selectedRow, 0);
    } else {
        serversTable->clearSelection();
    }
    lblServerHealthTitle->setText(count == 0 ? tr("Нет данных") : (total / count < 80 ? tr("Отлично") : (total / count < 160 ? tr("Хорошо") : tr("Средне"))));
    lblServerHealthSubtitle->setText(count == 0 ? tr("Проверьте задержку для оценки стабильности") : tr("Средняя задержка %1 мс").arg(total / count));
}

void MdmBoxWindow::refreshServerGroups() {
    while (serverFilterLayout->count() > 0) { delete serverFilterLayout->takeAt(0); }
    for (int gid : NekoGui::profileManager->groupsTabOrder) {
        auto group = NekoGui::profileManager->GetGroup(gid);
        if (!group) continue;
        auto *b = new QPushButton(group->name, this);
        b->setObjectName("tabButton");
        b->setCheckable(true);
        b->setChecked(gid == NekoGui::dataStore->current_group);
        connect(b, &QPushButton::clicked, this, [this, gid] {
            NekoGui::dataStore->current_group = gid;
            NekoGui::dataStore->Save();
            if (auto *mw = GetMainWindow()) mw->show_group(gid);
            refreshServerGroups();
            refreshServers();
        });
        serverFilterLayout->addWidget(b);
    }
    serverFilterLayout->addStretch();
}

void MdmBoxWindow::refreshRoutingPage() {
    if (!lblRoutingProfile || !cmbDefaultOutbound || !routingRulesLayout) return;
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;
    lblRoutingProfile->setText(tr("Активный профиль: %1").arg(NekoGui::dataStore->active_routing));
    { QSignalBlocker b(cmbDefaultOutbound); suppressRoutingSignals = true; cmbDefaultOutbound->setCurrentText(prettifyOutbound(NekoGui::dataStore->routing->def_outbound)); suppressRoutingSignals = false; }
    while (routingRulesLayout->count() > 0) {
        auto *item = routingRulesLayout->takeAt(0);
        if (item->widget()) item->widget()->deleteLater();
        delete item;
    }
    const QList<RoutingRuleEntry> rules = collectRoutingRules(routingTabIndex);
    lblRoutingCount->setText(tr("АКТИВНЫЕ ПРАВИЛА (%1)").arg(rules.size()));
    if (rules.isEmpty()) {
        auto *empty = new QLabel(tr("Для этого режима пока нет правил."), this);
        empty->setObjectName("cardSubtitle");
        routingRulesLayout->addWidget(empty);
    }
    for (const auto &rule : rules) {
        auto *row = new QFrame(this);
        row->setObjectName("card");
        auto *l = new QHBoxLayout(row);
        l->setContentsMargins(16, 14, 16, 14);
        auto *meta = new QVBoxLayout;
        auto *t = new QLabel(rule.value, row);
        t->setObjectName("cardTitle");
        auto *subtitle = new QLabel(tr("%1 • %2").arg(displayRuleKind(routingTabIndex, rule.value), displayPolicy(rule.policy)), row);
        subtitle->setObjectName("cardSubtitle");
        meta->addWidget(t);
        meta->addWidget(subtitle);
        l->addLayout(meta);
        l->addStretch();
        auto *edit = new QPushButton(tr("Изменить"), row);
        edit->setObjectName("linkButton");
        connect(edit, &QPushButton::clicked, this, [this, rule] { openRoutingRuleDialog(rule.value, rule.policy); });
        l->addWidget(edit);
        auto *remove = new QPushButton(tr("Удалить"), row);
        remove->setObjectName("linkButton");
        connect(remove, &QPushButton::clicked, this, [this, rule] { removeRoutingRule(rule.value, rule.policy); });
        l->addWidget(remove);
        routingRulesLayout->addWidget(row);
    }
    routingRulesLayout->addStretch();
}

void MdmBoxWindow::refreshSettingsPage() {
    if (!txtRemoteDns) return;
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;
    txtRemoteDns->setText(NekoGui::dataStore->routing->remote_dns);
    txtDirectDns->setText(NekoGui::dataStore->routing->direct_dns);
    cmbTunImplementation->setCurrentIndex(qBound(0, NekoGui::dataStore->vpn_implementation, 1));
    txtMtu->setText(QString::number(NekoGui::dataStore->vpn_mtu));
    chkVpnIpv6->setChecked(NekoGui::dataStore->vpn_ipv6);
    chkStrictRoute->setChecked(NekoGui::dataStore->vpn_strict_route);
    chkFakeDns->setChecked(NekoGui::dataStore->fake_dns);
    chkSingleCore->setChecked(NekoGui::dataStore->vpn_internal_tun);
    chkHideConsole->setChecked(NekoGui::dataStore->vpn_hide_console);
    chkWhitelistMode->setChecked(NekoGui::dataStore->vpn_rule_white);
    txtBypassCidr->setPlainText(NekoGui::dataStore->vpn_rule_cidr);
    txtBypassProcesses->setPlainText(NekoGui::dataStore->vpn_rule_process);
    bool installed = true;
    QStringList proc = lines(NekoGui::dataStore->vpn_rule_process);
    for (const QString &v : kPreset) if (!proc.contains(v, Qt::CaseInsensitive)) { installed = false; break; }
    chkZapretFix->setChecked(installed);
}

void MdmBoxWindow::refreshLogsPage() {
    if (!txtLogs || !txtLogFilter) return;
    QString raw;
    if (auto *mw = GetMainWindow()) if (auto *browser = mw->findChild<QTextBrowser *>("masterLogBrowser")) raw = browser->toPlainText();
    QStringList filtered = lines(raw), all = filtered;
    QString f = txtLogFilter->text().trimmed();
    if (!f.isEmpty()) {
        filtered.clear();
        for (const QString &line : all) if (line.contains(f, Qt::CaseInsensitive)) filtered << line;
    }
    txtLogs->setPlainText(filtered.join("\n"));
    if (chkLogAutoscroll->isChecked()) txtLogs->verticalScrollBar()->setValue(txtLogs->verticalScrollBar()->maximum());
    int errors = 0;
    for (const QString &line : all) if (line.contains(QStringLiteral("ERROR"), Qt::CaseInsensitive)) ++errors;
    lblLogCount->setText(QString::number(all.size()));
    lblLogErrors->setText(QString::number(errors));
    lblLogSize->setText(QString::number(raw.toUtf8().size() / (1024.0 * 1024.0), 'f', 1) + QStringLiteral(" MB"));
    lblLogUptime->setText(uptimeText(sessionTimer.elapsed() / 1000));
}

void MdmBoxWindow::syncCurrentPage() {
    if (!stackedWidget) return;
    if (btnSidebarConnect) btnSidebarConnect->setVisible(stackedWidget->currentIndex() != 0);
    if (stackedWidget->currentIndex() == 1) { refreshServerGroups(); refreshServers(); }
    if (stackedWidget->currentIndex() == 2) refreshRoutingPage();
    if (stackedWidget->currentIndex() == 4) refreshLogsPage();
}

void MdmBoxWindow::applySettingsFromUi() {
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;
    NekoGui::dataStore->routing->remote_dns = txtRemoteDns->text().trimmed();
    NekoGui::dataStore->routing->direct_dns = txtDirectDns->text().trimmed();
    NekoGui::dataStore->routing->Save();
    QStringList proc = lines(txtBypassProcesses->toPlainText());
    if (chkZapretFix->isChecked()) for (const QString &v : kPreset) if (!proc.contains(v, Qt::CaseInsensitive)) proc << v;
    NekoGui::dataStore->vpn_implementation = cmbTunImplementation->currentIndex();
    NekoGui::dataStore->vpn_mtu = qBound(1000, txtMtu->text().toInt(), 10000);
    NekoGui::dataStore->vpn_ipv6 = chkVpnIpv6->isChecked();
    NekoGui::dataStore->vpn_strict_route = chkStrictRoute->isChecked();
    NekoGui::dataStore->fake_dns = chkFakeDns->isChecked();
    NekoGui::dataStore->vpn_internal_tun = chkSingleCore->isChecked();
    NekoGui::dataStore->vpn_hide_console = chkHideConsole->isChecked();
    NekoGui::dataStore->vpn_rule_white = chkWhitelistMode->isChecked();
    NekoGui::dataStore->vpn_rule_cidr = txtBypassCidr->toPlainText().trimmed();
    NekoGui::dataStore->vpn_rule_process = proc.join("\n");
    NekoGui::dataStore->Save();
    refreshSettingsPage();
    refreshRoutingPage();
    if (auto *mw = GetMainWindow(); mw && NekoGui::dataStore->started_id >= 0) mw->neko_start(NekoGui::dataStore->started_id);
}

void MdmBoxWindow::saveRoutingQuickSettings() {}

QString MdmBoxWindow::activeProfileName() const {
    auto profile = NekoGui::profileManager->GetProfile(NekoGui::dataStore->started_id);
    return (profile && profile->bean) ? profile->bean->DisplayName() : QString();
}

QString MdmBoxWindow::activeProfileSubtitle() const { return QString(); }
QString MdmBoxWindow::activeGroupName() const { auto g = NekoGui::profileManager->GetGroup(NekoGui::dataStore->current_group); return g ? g->name : QString(); }
QString MdmBoxWindow::prettifyOutbound(const QString &value) const { QString v = value.toLower(); return v == "proxy" ? "Proxy" : (v == "bypass" ? "Bypass" : (v == "block" ? "Block" : value)); }
QStringList MdmBoxWindow::splitRules(const QString &text) const { return lines(text); }
