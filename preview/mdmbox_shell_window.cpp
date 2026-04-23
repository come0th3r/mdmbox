#include "mdmbox_shell_window.h"

#include "mdmbox_shell_bridge.h"
#include "db/Database.hpp"
#include "main/NekoGui.hpp"
#include "ui/mainwindow.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QMetaObject>
#include <QMessageBox>
#include <QRegularExpression>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWebChannel>
#include <QWebEnginePage>
#include <QWebEngineSettings>
#include <QWebEngineView>

namespace {

QString pageName(const QString &pageKey) {
    if (pageKey == QStringLiteral("servers")) return QStringLiteral("mdmbox_2");
    if (pageKey == QStringLiteral("routing")) return QStringLiteral("mdmbox_1");
    if (pageKey == QStringLiteral("settings")) return QStringLiteral("mdmbox_4");
    if (pageKey == QStringLiteral("logs")) return QStringLiteral("mdmbox_5");
    return QStringLiteral("mdmbox_3");
}

QString badgeFromName(const QString &name) {
    QString out;
    for (const QChar ch : name) {
        if (!ch.isLetter()) continue;
        out += ch.toUpper();
        if (out.size() == 3) break;
    }
    return out.isEmpty() ? QStringLiteral("VPN") : out;
}

QStringList lines(const QString &text) {
    return text.split(QRegularExpression(QStringLiteral("[\r\n]+")), Qt::SkipEmptyParts);
}

QString findDesignRootFrom(const QString &startPath) {
    QDir dir(startPath);
    while (dir.exists()) {
        if (dir.exists(QStringLiteral("newdesign"))) {
            return dir.absoluteFilePath(QStringLiteral("newdesign"));
        }
        if (!dir.cdUp()) break;
    }
    return {};
}

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

QString normalizedPlainRuleValue(QString value) {
    value = value.trimmed();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith('\'') && value.endsWith('\''))) {
        value = value.mid(1, value.size() - 2).trimmed();
    }
    return value;
}

void appendRulesFromValue(QList<RoutingRuleEntry> &rules, const QJsonValue &value, const QString &policy) {
    if (value.isArray()) {
        for (const auto &item : value.toArray()) {
            const QString text = normalizedPlainRuleValue(item.toString());
            if (!text.isEmpty()) rules.append({text, normalizedPolicy(policy)});
        }
        return;
    }

    for (const QString &line : lines(value.toString())) {
        const QString text = normalizedPlainRuleValue(line);
        if (!text.isEmpty()) rules.append({text, normalizedPolicy(policy)});
    }
}

int effectiveSelectedId() {
    if (!NekoGui::dataStore) return -1919;
    if (NekoGui::dataStore->started_id >= 0) return NekoGui::dataStore->started_id;
    auto group = NekoGui::profileManager ? NekoGui::profileManager->CurrentGroup() : nullptr;
    if (NekoGui::dataStore->selected_id >= 0) {
        auto selected = NekoGui::profileManager ? NekoGui::profileManager->GetProfile(NekoGui::dataStore->selected_id) : nullptr;
        if (selected && (!group || selected->gid == group->id)) return NekoGui::dataStore->selected_id;
    }
    if (group && !group->order.isEmpty()) return group->order.first();
    if (group) {
        auto profiles = group->ProfilesWithOrder();
        if (!profiles.isEmpty() && profiles.first()) return profiles.first()->id;
    }
    return -1919;
}

QJsonObject parseTrafficState(QString trafficText) {
    QJsonObject result{
        {QStringLiteral("upload"), QStringLiteral("0 B/s")},
        {QStringLiteral("download"), QStringLiteral("0 B/s")},
    };

    if (trafficText.trimmed().isEmpty()) return result;

    trafficText.remove(QRegularExpression(QStringLiteral("[\\x{202A}-\\x{202E}]")));

    const auto proxyMatch =
        QRegularExpression(QStringLiteral("Proxy:\\s*(.+?)(?:\\r?\\n|$)"), QRegularExpression::CaseInsensitiveOption)
            .match(trafficText);
    if (proxyMatch.hasMatch()) trafficText = proxyMatch.captured(1).trimmed();

    const auto arrows = QRegularExpression(QStringLiteral("(.+?)\\s*↑\\s*(.+?)\\s*↓")).match(trafficText);
    if (arrows.hasMatch()) {
        result.insert(QStringLiteral("upload"), arrows.captured(1).trimmed());
        result.insert(QStringLiteral("download"), arrows.captured(2).trimmed());
    }

    return result;
}

QJsonObject buildShellState() {
    QJsonObject state;
    const bool connected = NekoGui::dataStore && NekoGui::dataStore->started_id >= 0;
    const int selectedId = effectiveSelectedId();
    auto selectedProfile = NekoGui::profileManager ? NekoGui::profileManager->GetProfile(selectedId) : nullptr;
    auto *mw = GetMainWindow();

    QString name = QObject::tr("Профиль не выбран");
    QString address;
    int latency = 0;
    if (selectedProfile && selectedProfile->bean) {
        name = selectedProfile->bean->DisplayName();
        address = selectedProfile->bean->DisplayAddress();
        latency = selectedProfile->latency;
    }
    if (mw && mw->shellLatencyMs() > 0) latency = mw->shellLatencyMs();

    const auto traffic = parseTrafficState(mw ? mw->shellTrafficText() : QString());
    const auto signal = mw ? mw->shellSignalStats() : QJsonObject{};

    state.insert(QStringLiteral("connected"), connected);
    state.insert(QStringLiteral("selectedId"), selectedId);
    state.insert(QStringLiteral("selectedName"), name);
    state.insert(QStringLiteral("selectedAddress"), address);
    state.insert(QStringLiteral("tunEnabled"), NekoGui::dataStore ? NekoGui::dataStore->spmode_vpn : false);
    state.insert(QStringLiteral("systemProxyEnabled"), NekoGui::dataStore ? NekoGui::dataStore->spmode_system_proxy : false);
    state.insert(QStringLiteral("statusPill"), connected ? QObject::tr("Подключено") : QObject::tr("Отключено"));
    state.insert(QStringLiteral("statusSubtitle"),
                 connected ? QObject::tr("Виртуальный IP через %1").arg(name) : QObject::tr("Подключение не установлено"));
    state.insert(QStringLiteral("connectButton"), connected ? QObject::tr("Отключить") : QObject::tr("Подключить"));
    state.insert(QStringLiteral("sidebarButton"), connected ? QObject::tr("Отключить") : QObject::tr("Подключиться"));
    state.insert(QStringLiteral("ipAddress"), connected ? name : QStringLiteral("-.-.-.-"));
    state.insert(QStringLiteral("ping"), latency > 0 ? QString::number(latency) + QStringLiteral(" мс") : QStringLiteral("0 мс"));
    state.insert(QStringLiteral("pingMs"), latency);
    state.insert(QStringLiteral("upload"), traffic.value(QStringLiteral("upload")).toString());
    state.insert(QStringLiteral("download"), traffic.value(QStringLiteral("download")).toString());
    state.insert(QStringLiteral("signal"), signal);
    return state;
}

QString formatBytes(qint64 bytes) {
    static const QStringList units = {QStringLiteral("B"), QStringLiteral("KB"), QStringLiteral("MB"), QStringLiteral("GB")};
    double value = static_cast<double>(qMax<qint64>(bytes, 0));
    int unitIndex = 0;
    while (value >= 1024.0 && unitIndex < units.size() - 1) {
        value /= 1024.0;
        ++unitIndex;
    }
    return unitIndex == 0
        ? QString::number(static_cast<qint64>(value)) + QStringLiteral(" ") + units[unitIndex]
        : QString::number(value, 'f', value >= 10.0 ? 1 : 2) + QStringLiteral(" ") + units[unitIndex];
}

QString formatUptime(qint64 seconds) {
    const qint64 hours = seconds / 3600;
    const qint64 minutes = (seconds % 3600) / 60;
    const qint64 secs = seconds % 60;
    return QStringLiteral("%1:%2:%3")
        .arg(hours, 2, 10, QLatin1Char('0'))
        .arg(minutes, 2, 10, QLatin1Char('0'))
        .arg(secs, 2, 10, QLatin1Char('0'));
}

QJsonObject buildLogsState() {
    QJsonObject state;
    auto *mw = GetMainWindow();
    const QString rawLog = mw ? mw->shellLogText() : QString();
    const QStringList rawLines = lines(rawLog);

    QJsonArray lineItems;
    int errorCount = 0;
    for (const QString &line : rawLines) {
        const QString trimmed = line.trimmed();
        if (trimmed.isEmpty()) continue;
        lineItems.append(trimmed);
        const QString lower = trimmed.toLower();
        if (lower.contains(QStringLiteral("error")) || lower.contains(QStringLiteral("[error]")) || lower.contains(QStringLiteral("failed"))) {
            ++errorCount;
        }
    }

    static const QDateTime startedAt = QDateTime::currentDateTime();
    state.insert(QStringLiteral("lines"), lineItems);
    state.insert(QStringLiteral("total"), lineItems.size());
    state.insert(QStringLiteral("errors"), errorCount);
    state.insert(QStringLiteral("size"), formatBytes(rawLog.toUtf8().size()));
    state.insert(QStringLiteral("uptime"), formatUptime(startedAt.secsTo(QDateTime::currentDateTime())));
    return state;
}

QJsonArray buildServerList() {
    QJsonArray servers;
    auto group = NekoGui::profileManager ? NekoGui::profileManager->CurrentGroup() : nullptr;
    if (!group) return servers;

    const int startedId = NekoGui::dataStore ? NekoGui::dataStore->started_id : -1919;
    const int selectedId = effectiveSelectedId();

    for (const auto &profile : group->ProfilesWithOrder()) {
        if (!profile || !profile->bean) continue;

        QJsonObject item;
        item.insert(QStringLiteral("id"), profile->id);
        item.insert(QStringLiteral("name"), profile->bean->DisplayName());
        item.insert(QStringLiteral("address"), profile->bean->DisplayAddress());
        item.insert(QStringLiteral("badge"), badgeFromName(profile->bean->DisplayName()));
        item.insert(QStringLiteral("latency"), profile->latency > 0 ? QString::number(profile->latency) + QStringLiteral(" мс") : QStringLiteral("-"));
        const QString traffic =
            profile->traffic_data ? profile->traffic_data->DisplayTraffic().trimmed() : QString();
        item.insert(QStringLiteral("traffic"), traffic.isEmpty() ? QStringLiteral("-") : traffic);
        item.insert(QStringLiteral("isRunning"), profile->id == startedId);
        item.insert(QStringLiteral("isSelected"), profile->id == selectedId);
        servers.append(item);
    }

    return servers;
}

QJsonObject buildServersState() {
    QJsonObject state;
    QJsonArray groups;
    const int currentGroup = NekoGui::dataStore ? NekoGui::dataStore->current_group : 0;

    if (NekoGui::profileManager) {
        for (const auto gid : NekoGui::profileManager->groupsTabOrder) {
            auto group = NekoGui::profileManager->GetGroup(gid);
            if (!group) continue;

            QString title = group->name.trimmed();
            if (title.isEmpty() || title.compare(QStringLiteral("Default"), Qt::CaseInsensitive) == 0) {
                title = QObject::tr("По умолчанию");
            }

            QJsonObject item;
            item.insert(QStringLiteral("id"), gid);
            item.insert(QStringLiteral("name"), title);
            item.insert(QStringLiteral("isCurrent"), gid == currentGroup);
            groups.append(item);
        }
    }

    if (groups.isEmpty()) {
        groups.append(QJsonObject{
            {QStringLiteral("id"), 0},
            {QStringLiteral("name"), QObject::tr("По умолчанию")},
            {QStringLiteral("isCurrent"), true},
        });
    }

    state.insert(QStringLiteral("currentGroup"), currentGroup);
    state.insert(QStringLiteral("groups"), groups);
    state.insert(QStringLiteral("items"), buildServerList());
    return state;
}

QJsonArray toRuleArray(const QString &raw) {
    QJsonArray out;
    for (const QString &line : lines(raw)) out.append(line);
    return out;
}

void syncRoutingSnapshot() {
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
    syncRoutingSnapshot();
    NekoGui::dataStore->routing->fn = ROUTES_PREFIX + NekoGui::dataStore->active_routing;
    NekoGui::dataStore->routing->Save();
    NekoGui::dataStore->Save();
    if (MW_dialog_message) {
        MW_dialog_message(QString(), routeChanged ? QStringLiteral("UpdateDataStore,RouteChanged") : QStringLiteral("UpdateDataStore"));
    }
}

void saveTunRuleState() {
    if (!NekoGui::dataStore) return;
    if (NekoGui::dataStore->routing) {
        syncRoutingSnapshot();
        NekoGui::dataStore->routing->fn = ROUTES_PREFIX + NekoGui::dataStore->active_routing;
        NekoGui::dataStore->routing->Save();
    }
    NekoGui::dataStore->Save();
    if (MW_dialog_message) MW_dialog_message(QString(), QStringLiteral("UpdateDataStore,RouteChanged,VPNChanged"));
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
        for (const auto &rule : rules) {
            if (rule.policy == policy) values.append(rule.value);
        }
        return values.join('\n');
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
        NekoGui::dataStore->vpn_rule_process = processValues.join('\n');
        if (!rules.isEmpty()) NekoGui::dataStore->vpn_rule_white = rules.first().policy == QStringLiteral("proxy");
        saveTunRuleState();
        return;
    }

    NekoGui::dataStore->routing->direct_ip = joinByPolicy(QStringLiteral("bypass"));
    NekoGui::dataStore->routing->proxy_ip = joinByPolicy(QStringLiteral("proxy"));
    NekoGui::dataStore->routing->block_ip = joinByPolicy(QStringLiteral("block"));
    saveActiveRoutingState(true);
}

QJsonObject buildRoutingExportObject() {
    QJsonObject root;
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return root;

    root.insert(QStringLiteral("active_routing"), NekoGui::dataStore->active_routing);
    root.insert(QStringLiteral("def_outbound"), normalizedPolicy(NekoGui::dataStore->routing->def_outbound));
    root.insert(QStringLiteral("direct_domain"), toRuleArray(NekoGui::dataStore->routing->direct_domain));
    root.insert(QStringLiteral("proxy_domain"), toRuleArray(NekoGui::dataStore->routing->proxy_domain));
    root.insert(QStringLiteral("block_domain"), toRuleArray(NekoGui::dataStore->routing->block_domain));
    root.insert(QStringLiteral("direct_ip"), toRuleArray(NekoGui::dataStore->routing->direct_ip));
    root.insert(QStringLiteral("proxy_ip"), toRuleArray(NekoGui::dataStore->routing->proxy_ip));
    root.insert(QStringLiteral("block_ip"), toRuleArray(NekoGui::dataStore->routing->block_ip));
    root.insert(QStringLiteral("vpn_rule_process"), toRuleArray(NekoGui::dataStore->vpn_rule_process));
    root.insert(QStringLiteral("vpn_rule_white"), NekoGui::dataStore->vpn_rule_white);
    root.insert(QStringLiteral("vpn_rule_cidr"), toRuleArray(NekoGui::dataStore->vpn_rule_cidr));
    return root;
}

QJsonObject buildRoutingState() {
    QJsonObject state;
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return state;

    state.insert(QStringLiteral("activeRouting"), NekoGui::dataStore->active_routing);
    state.insert(QStringLiteral("defaultOutbound"), normalizedPolicy(NekoGui::dataStore->routing->def_outbound));

    QJsonArray tabs;
    for (int tabIndex = 0; tabIndex < 3; ++tabIndex) {
        QJsonObject tab;
        if (tabIndex == 0) tab.insert(QStringLiteral("title"), QObject::tr("По домену"));
        else if (tabIndex == 1) tab.insert(QStringLiteral("title"), QObject::tr("По приложению"));
        else tab.insert(QStringLiteral("title"), QObject::tr("По сайту"));

        QJsonArray rules;
        const auto collected = collectRoutingRules(tabIndex);
        for (const auto &rule : collected) {
            QJsonObject item;
            item.insert(QStringLiteral("value"), rule.value);
            item.insert(QStringLiteral("policy"), normalizedPolicy(rule.policy));
            item.insert(QStringLiteral("policyLabel"), displayPolicy(rule.policy));
            item.insert(QStringLiteral("kind"), displayRuleKind(tabIndex, rule.value));
            rules.append(item);
        }
        tab.insert(QStringLiteral("rules"), rules);
        tabs.append(tab);
    }

    state.insert(QStringLiteral("tabs"), tabs);
    return state;
}

}

MdmBoxShellWindow::MdmBoxShellWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("MDMBOX"));
    resize(1440, 920);

    view = new QWebEngineView(this);
    view->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, true);
    view->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, true);
    view->settings()->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
    setCentralWidget(view);

    channel = new QWebChannel(this);
    bridge = new MdmBoxShellBridge(this, this);
    channel->registerObject(QStringLiteral("mdmboxBridge"), bridge);
    view->page()->setWebChannel(channel);

    connect(view, &QWebEngineView::loadFinished, this, [this](bool ok) {
        if (ok) {
            hookPage();
            refreshPageState();
        }
    });

    refreshTimer = new QTimer(this);
    refreshTimer->setInterval(1200);
    connect(refreshTimer, &QTimer::timeout, this, &MdmBoxShellWindow::refreshPageState);
    refreshTimer->start();

    navigate(currentPage);
}

MdmBoxShellWindow::~MdmBoxShellWindow() = default;

void MdmBoxShellWindow::closeEvent(QCloseEvent *event) {
    if (allowHardClose) {
        QMainWindow::closeEvent(event);
        return;
    }
    hide();
    if (auto *mw = GetMainWindow()) mw->hide();
    event->ignore();
}

QString MdmBoxShellWindow::designRootPath() const {
    const QStringList candidates{
        findDesignRootFrom(QCoreApplication::applicationDirPath()),
        findDesignRootFrom(QDir::currentPath()),
        QStringLiteral("C:/Users/0th3r/nekoray/newdesign"),
    };

    for (const QString &candidate : candidates) {
        if (!candidate.isEmpty() && QDir(candidate).exists()) return QDir(candidate).absolutePath();
    }
    return {};
}

QString MdmBoxShellWindow::htmlPathForPage(const QString &pageKey) const {
    const QString root = designRootPath();
    if (root.isEmpty()) return {};
    return QDir(root).absoluteFilePath(pageName(pageKey) + QStringLiteral("/code.html"));
}

QString MdmBoxShellWindow::htmlContentForPage(const QString &pageKey) const {
    QFile file(htmlPathForPage(pageKey));
    if (!file.open(QFile::ReadOnly | QFile::Text)) return {};
    QString html = QString::fromUtf8(file.readAll());
    const QString bootstrap = QStringLiteral(
        "<style>"
        "body>header{display:none!important;}"
        "a,button,[role='button'],select,label,.material-symbols-outlined{-webkit-user-drag:none;user-select:none;}"
        "button:focus,a:focus,select:focus{outline:none!important;}"
        "</style>"
        "<script>window.__mdmboxFreezeRefreshUntil=0;</script>");
    html.replace(QStringLiteral("</head>"), bootstrap + QStringLiteral("</head>"));
    return html;
}

void MdmBoxShellWindow::navigate(const QString &pageKey) {
    currentPage = pageKey;
    const QString path = htmlPathForPage(pageKey);
    if (!QFile::exists(path)) return;
    const QString html = htmlContentForPage(pageKey);
    if (html.isEmpty()) {
        view->setUrl(QUrl::fromLocalFile(path));
        return;
    }
    view->setHtml(html, QUrl::fromLocalFile(path));
}

void MdmBoxShellWindow::hookPage() {
    const QString script = QStringLiteral(R"JS(
        (function () {
          if (window.__mdmboxQtHooked) return;
          window.__mdmboxQtHooked = true;
          window.__mdmboxRouteTab = typeof window.__mdmboxRouteTab === 'number' ? window.__mdmboxRouteTab : 0;

          function bindBridge() {
            if (!window.mdmboxBridge) return;

            function detectNavTarget(text) {
              const normalized = (text || '').trim();
              if (!normalized) return '';
              if (normalized.includes('Панель')) return 'dashboard';
              if (normalized.includes('Серверы')) return 'servers';
              if (normalized.includes('Маршрут')) return 'routing';
              if (normalized.includes('Настройки')) return 'settings';
              if (normalized.includes('Логи')) return 'logs';
              if (normalized.includes('О программе')) return 'logs';
              return '';
            }

            document.querySelectorAll("button, a, [role='button']").forEach(function (node) {
              if (node.dataset.mdmboxBound === "1") return;
              node.dataset.mdmboxBound = "1";
              node.setAttribute('draggable', 'false');
              node.style.webkitUserDrag = 'none';
              node.style.userSelect = 'none';
              if (node.tagName === 'A') {
                node.setAttribute('href', 'javascript:void(0)');
                node.removeAttribute('target');
              }

              node.addEventListener('mousedown', function () {
                window.__mdmboxFreezeRefreshUntil = Date.now() + 1400;
              });

              node.addEventListener('pointerdown', function () {
                window.__mdmboxFreezeRefreshUntil = Date.now() + 1400;
              });

              node.addEventListener('dragstart', function (ev) {
                ev.preventDefault();
              });

              node.addEventListener("click", function (ev) {
                window.__mdmboxFreezeRefreshUntil = Date.now() + 900;
                const text = (node.innerText || node.textContent || "").trim();
                const navTarget = detectNavTarget(text);
                if (navTarget) {
                  ev.preventDefault();
                  window.mdmboxBridge.navigate(navTarget);
                  return;
                }

                if (text === "−" || text === "remove") {
                  ev.preventDefault();
                  window.mdmboxBridge.minimizeWindow();
                  return;
                }

                if (text === "□" || text === "❐" || text === "check_box_outline_blank") {
                  ev.preventDefault();
                  window.mdmboxBridge.maximizeWindow();
                  return;
                }

                if (text === "×" || text === "✕" || text === "close") {
                  ev.preventDefault();
                  window.mdmboxBridge.closeWindow();
                  return;
                }

                if (text.includes("Выключить")) {
                  ev.preventDefault();
                  window.mdmboxBridge.exitProgram();
                  return;
                }

                if (text.includes("Legacy режим")) {
                  ev.preventDefault();
                  window.mdmboxBridge.openLegacy();
                  return;
                }

                if (text.includes("Сбросить правила")) {
                  ev.preventDefault();
                  window.mdmboxBridge.routingResetRules(window.__mdmboxRouteTab || 0);
                  return;
                }
              });
            });
          }

          function boot() {
            new QWebChannel(qt.webChannelTransport, function (channel) {
              window.mdmboxBridge = channel.objects.mdmboxBridge;
              bindBridge();
            });
          }

          if (typeof QWebChannel === "undefined") {
            const script = document.createElement("script");
            script.src = "qrc:///qtwebchannel/qwebchannel.js";
            script.onload = boot;
            document.head.appendChild(script);
          } else {
            boot();
          }
        })();
    )JS");
    view->page()->runJavaScript(script);
}

QString MdmBoxShellWindow::buildRefreshScript() const {
    const QString state = QString::fromUtf8(QJsonDocument(buildShellState()).toJson(QJsonDocument::Compact));
    const QString servers = QString::fromUtf8(QJsonDocument(buildServersState()).toJson(QJsonDocument::Compact));
    const QString routing = QString::fromUtf8(QJsonDocument(buildRoutingState()).toJson(QJsonDocument::Compact));
    const QString logs = QString::fromUtf8(QJsonDocument(buildLogsState()).toJson(QJsonDocument::Compact));
    const QString page = QString::fromUtf8(QJsonDocument(QJsonArray{currentPage}).toJson(QJsonDocument::Compact));

    return QStringLiteral(
               "(function(){"
               "if(window.__mdmboxFreezeRefreshUntil&&Date.now()<window.__mdmboxFreezeRefreshUntil) return;"
               "const ae=document.activeElement;"
               "if(ae&&['SELECT','INPUT','TEXTAREA'].includes(ae.tagName)) return;"
               "const state=%1;"
               "const servers=%2;"
               "const routing=%3;"
               "const logs=%4;"
               "const page=%5[0];"
               "%6"
               "%7"
               "%8"
               "%9"
               "%10"
               "normalizeShellChrome();"
               "if(page==='dashboard')setDashboardState();"
               "if(page==='servers')setServersState();"
               "if(page==='routing')setRoutingState();"
               "if(page==='logs')setLogsState();"
               "})();")
        .arg(state, servers, routing, logs, page,
             buildChromeNormalizeScript(),
             buildDashboardScript(),
             buildServersScript(),
             buildRoutingScript(),
             buildLogsScript());
}

QString MdmBoxShellWindow::buildChromeNormalizeScript() const {
    return QStringLiteral(R"JS(
        function navTargetFromText(text) {
          const normalized = (text || '').trim();
          if (!normalized) return '';
          if (normalized.includes('Панель')) return 'dashboard';
          if (normalized.includes('Серверы')) return 'servers';
          if (normalized.includes('Маршрут')) return 'routing';
          if (normalized.includes('Настройки')) return 'settings';
          if (normalized.includes('Логи')) return 'logs';
          if (normalized.includes('О программе')) return 'about';
          return '';
        }

        function normalizeShellChrome() {
          const chromeCandidates = Array.from(document.querySelectorAll('body > header, header, .titlebar, .window-controls'));
          chromeCandidates.forEach(function (node) {
            const text = (node.textContent || '').trim();
            const hasWindowIcons = text.includes('remove') || text.includes('check_box_outline_blank') ||
                                   text.includes('close') || text.includes('—') || text.includes('□') || text.includes('×');
            if (hasWindowIcons) node.style.display = 'none';
          });

          document.querySelectorAll('.pt-8, .pt-10').forEach(function (node) {
            node.classList.remove('pt-8', 'pt-10');
            node.style.paddingTop = '0px';
          });

          const aside = document.querySelector('aside');
          if (!aside) return;

          const sidebarTemplate =
            '<div class="px-4 mb-8">' +
            '<h1 class="text-xl font-bold tracking-tighter text-blue-600">MDMBOX</h1>' +
            '<p class="text-[10px] font-medium text-slate-500 tracking-tight opacity-70">Как Nekobox но хуже</p>' +
            '</div>' +
            '<nav class="flex-1 space-y-1">' +
            '<a href="#" data-mdmbox-nav="dashboard" class="flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-150">' +
            '<span class="material-symbols-outlined">speed</span><span class="text-sm font-medium">Панель</span></a>' +
            '<a href="#" data-mdmbox-nav="servers" class="flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-150">' +
            '<span class="material-symbols-outlined">dns</span><span class="text-sm font-medium">Серверы</span></a>' +
            '<a href="#" data-mdmbox-nav="routing" class="flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-150">' +
            '<span class="material-symbols-outlined">route</span><span class="text-sm font-medium">Маршрутизация</span></a>' +
            '<a href="#" data-mdmbox-nav="settings" class="flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-150">' +
            '<span class="material-symbols-outlined">settings</span><span class="text-sm font-medium">Настройки</span></a>' +
            '</nav>' +
            '<div class="mt-auto space-y-1 pt-4 border-t border-outline-variant/10">' +
            '<a href="#" data-mdmbox-nav="logs" class="flex items-center gap-3 px-4 py-2 text-slate-500 transition-colors">' +
            '<span class="material-symbols-outlined text-sm">terminal</span><span class="text-xs font-medium">Логи</span></a>' +
            '<a href="#" data-mdmbox-nav="about" class="flex items-center gap-3 px-4 py-2 text-slate-500 transition-colors">' +
            '<span class="material-symbols-outlined text-sm">info</span><span class="text-xs font-medium">О программе</span></a>' +
            '</div>';

          if (aside.dataset.mdmboxSidebarTemplate !== '1') {
            aside.innerHTML = sidebarTemplate;
            aside.dataset.mdmboxSidebarTemplate = '1';
          }

          aside.style.width = '256px';
          aside.style.minWidth = '256px';
          aside.style.flex = '0 0 256px';
          aside.style.background = '#f7f8fb';
          aside.style.borderRight = '1px solid rgba(192, 199, 212, 0.45)';
          aside.style.padding = '28px 16px 18px';
          aside.style.boxSizing = 'border-box';
          aside.style.display = 'flex';
          aside.style.flexDirection = 'column';
          aside.style.gap = '0';
          aside.style.backdropFilter = 'none';
          aside.style.userSelect = 'none';

          const brandTitle = aside.querySelector('h1, .text-2xl, .text-xl');
          if (brandTitle) {
            brandTitle.textContent = 'MDMBOX';
            brandTitle.style.color = '#0a72cf';
            brandTitle.style.fontSize = '23px';
            brandTitle.style.fontWeight = '800';
            brandTitle.style.letterSpacing = '-0.04em';
            brandTitle.style.lineHeight = '1.1';
            brandTitle.style.margin = '0';
          }

          const brandSubtitle = Array.from(aside.querySelectorAll('div, p, span')).find(function (node) {
            const text = (node.textContent || '').trim();
            return text.includes('Nekobox') || text.includes('NEKOBOX') || text.includes('хуже');
          });
          if (brandSubtitle) {
            brandSubtitle.textContent = 'Как Nekobox но хуже';
            brandSubtitle.style.color = '#7f8794';
            brandSubtitle.style.fontSize = '12px';
            brandSubtitle.style.fontWeight = '500';
            brandSubtitle.style.letterSpacing = '0';
            brandSubtitle.style.textTransform = 'none';
            brandSubtitle.style.marginTop = '6px';
            brandSubtitle.style.opacity = '0.95';
          }

          const navItems = Array.from(aside.querySelectorAll('[data-mdmbox-nav], a, button')).filter(function (node) {
            const explicit = node.getAttribute('data-mdmbox-nav') || '';
            return explicit || navTargetFromText(node.textContent || '');
          });

          navItems.forEach(function (item) {
            const target = item.getAttribute('data-mdmbox-nav') || navTargetFromText(item.textContent || '');
            item.dataset.mdmboxNavTarget = target;
            item.style.display = 'flex';
            item.style.alignItems = 'center';
            item.style.gap = '12px';
            item.style.minHeight = target === 'logs' || target === 'about' ? '36px' : '48px';
            item.style.padding = '0 14px';
            item.style.borderRadius = target === 'logs' || target === 'about' ? '10px' : '14px';
            item.style.marginBottom = target === 'logs' || target === 'about' ? '2px' : '6px';
            item.style.textDecoration = 'none';
            item.style.boxSizing = 'border-box';
            item.style.border = 'none';
            item.style.boxShadow = 'none';
            item.style.transform = 'none';

            const label = Array.from(item.querySelectorAll('span')).filter(function (node) {
              return !(node.classList || []).contains('material-symbols-outlined');
            }).pop();
            if (label) {
              if (target === 'dashboard') label.textContent = 'Панель';
              if (target === 'servers') label.textContent = 'Серверы';
              if (target === 'routing') label.textContent = 'Маршрутизация';
              if (target === 'settings') label.textContent = 'Настройки';
              if (target === 'logs') label.textContent = 'Логи';
              if (target === 'about') label.textContent = 'О программе';
              label.style.fontSize = target === 'logs' || target === 'about' ? '12px' : '14px';
              label.style.fontWeight = target === page ? '700' : '500';
            }

            if (target === page) {
              item.style.background = '#e9f2ff';
              item.style.color = '#0a72cf';
            } else {
              item.style.background = 'transparent';
              item.style.color = '#546173';
            }
          });

          function removeMeaningfulContainer(node, maxDepth) {
            let current = node;
            let depth = 0;
            while (current && depth < (maxDepth || 6)) {
              const text = (current.textContent || '').trim();
              if (current.tagName === 'FOOTER') {
                current.remove();
                return true;
              }
              if (text.length > 0 && text.length < 400) {
                const rect = current.getBoundingClientRect ? current.getBoundingClientRect() : { height: 0, width: 0 };
                if (rect.height >= 20 && rect.width >= 40) {
                  current.remove();
                  return true;
                }
              }
              current = current.parentElement;
              depth += 1;
            }
            return false;
          }

          Array.from(document.querySelectorAll('button, a, div, span, section, footer, p')).forEach(function (node) {
            const text = (node.textContent || '').trim();

            if (text.includes('Добавить правила маршрутизации')) {
              const row = node.closest('button');
              if (row) row.remove();
              return;
            }

            if (text.includes('Исправление проблем')) {
              if (!removeMeaningfulContainer(node, 8)) {
                const row = node.closest('button, div, section');
                if (row) row.remove();
              }
              return;
            }

            if (text === 'OK' || text === 'Cancel') {
              const controls = node.closest('div.flex.gap-3, div.flex.flex-col, div.flex.flex-row, section');
              if (controls && (controls.textContent || '').includes('OK') && (controls.textContent || '').includes('Cancel')) {
                controls.remove();
              } else {
                const button = node.closest('button');
                if (button) button.remove();
              }
              return;
            }

            if (text.includes('Политика конфиденциальности') || text.includes('Условия использования') ||
                text.includes('© 2024 MDMBOX') || text.includes('ВСЕ ПРАВА ЗАЩИЩЕНЫ')) {
              const footer = node.closest('footer, div');
              if (footer) footer.remove();
            }
          });
        }
    )JS");
}

QString MdmBoxShellWindow::buildDashboardScript() const {
    return QStringLiteral(R"JS(
        function setDashboardState() {
          if (!document.getElementById('mdmbox-dashboard-motion')) {
            const style = document.createElement('style');
            style.id = 'mdmbox-dashboard-motion';
            style.textContent =
              '[data-mdmbox-status-pill], [data-mdmbox-connect="1"], [data-mdmbox-toggle-track="1"], [data-mdmbox-toggle-knob="1"], .glass-panel {' +
              'transition: all 220ms cubic-bezier(0.22, 1, 0.36, 1); }' +
              '[data-mdmbox-connect="1"]:hover { transform: translateY(-1px) scale(1.01); }' +
              '.glass-panel:hover { transform: translateY(-1px); }';
            document.head.appendChild(style);
          }

          const headers = Array.from(document.querySelectorAll('h2'));
          const ipNode = headers.find(function (n) {
            return (n.textContent || '').includes('192.168') || (n.textContent || '').includes('-.-.-.-');
          });
          if (ipNode) ipNode.textContent = state.ipAddress;

          const subNode = Array.from(document.querySelectorAll('p')).find(function (n) {
            const text = (n.textContent || '').trim();
            return text.includes('Виртуальный IP через') || text.includes('Подключение не установлено');
          });
          if (subNode) subNode.textContent = state.statusSubtitle;

          const pill = Array.from(document.querySelectorAll('div, span')).find(function (n) {
            const text = (n.textContent || '').trim();
            return text === 'Подключено' || text === 'Отключено' || text === 'Подключение';
          });
          if (pill) {
            pill.dataset.mdmboxStatusPill = '1';
            pill.textContent = state.statusPill;
            pill.style.background = state.connected ? 'rgba(34, 197, 94, 0.16)' : 'rgba(239, 68, 68, 0.16)';
            pill.style.color = state.connected ? '#16a34a' : '#dc2626';
            pill.style.borderRadius = '999px';
            pill.style.padding = '8px 18px';
            pill.style.display = 'inline-flex';
            pill.style.alignItems = 'center';
            pill.style.justifyContent = 'center';
            pill.style.fontWeight = '700';
            pill.style.lineHeight = '1';
            const holder = pill.parentElement;
            if (holder && holder !== pill) {
              holder.style.background = 'transparent';
              holder.style.border = 'none';
              holder.style.boxShadow = 'none';
            }
          }

          const connectButton = Array.from(document.querySelectorAll('button')).find(function (n) {
            const text = (n.textContent || '').trim();
            return text.includes('Подключить') || text.includes('Отключить');
          });
          if (connectButton) {
            connectButton.dataset.mdmboxConnect = '1';
            const label = Array.from(connectButton.querySelectorAll('span')).find(function (n) {
              return !(n.classList || []).contains('material-symbols-outlined');
            });
            if (label) label.textContent = state.connectButton;
            else connectButton.lastChild.textContent = state.connectButton;
            connectButton.classList.remove('from-primary', 'to-primary-container', 'from-slate-400', 'to-slate-500');
            connectButton.style.background = state.connected
              ? 'linear-gradient(180deg, #1678cc 0%, #0e63ad 100%)'
              : 'linear-gradient(180deg, #98a9c3 0%, #7789a5 100%)';
            connectButton.style.boxShadow = state.connected
              ? '0 18px 36px rgba(22, 120, 204, 0.18)'
              : '0 18px 36px rgba(119, 137, 165, 0.18)';
            if (!connectButton.dataset.mdmboxConnectBound) {
              connectButton.dataset.mdmboxConnectBound = '1';
              connectButton.addEventListener('click', function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                window.mdmboxBridge.connectToggle();
              });
            }
          }

          const glow = connectButton ? connectButton.parentElement.querySelector('.blur-3xl') : null;
          if (glow) {
            glow.style.background = state.connected
              ? 'radial-gradient(circle, rgba(33, 150, 243, 0.28) 0%, rgba(33, 150, 243, 0.12) 48%, rgba(33, 150, 243, 0) 78%)'
              : 'radial-gradient(circle, rgba(148, 163, 184, 0.24) 0%, rgba(148, 163, 184, 0.10) 48%, rgba(148, 163, 184, 0) 78%)';
            glow.style.filter = 'blur(48px)';
            glow.style.opacity = '1';
            glow.style.transition = 'all 260ms cubic-bezier(0.22, 1, 0.36, 1)';
          }

          const cards = Array.from(document.querySelectorAll('div.glass-panel'));
          cards.forEach(function (card) {
            const title = card.querySelector('h3');
            if (!title) return;
            const toggle = card.querySelector('.w-12.h-6');
            if (!toggle) return;

            let enabled = false;
            if ((title.textContent || '').includes('TUN')) {
              enabled = !!state.tunEnabled;
              card.dataset.mdmboxToggle = 'tun';
            }
            if ((title.textContent || '').includes('Системный прокси')) {
              enabled = !!state.systemProxyEnabled;
              card.dataset.mdmboxToggle = 'system-proxy';
            }

            toggle.dataset.mdmboxToggleTrack = '1';
            toggle.classList.remove('bg-primary', 'bg-surface-container-highest');
            toggle.classList.add(enabled ? 'bg-primary' : 'bg-surface-container-highest');
            toggle.style.justifyContent = enabled ? 'flex-end' : 'flex-start';
            const knob = toggle.querySelector('div');
            if (knob) {
              knob.dataset.mdmboxToggleKnob = '1';
              knob.style.boxShadow = enabled
                ? '0 3px 10px rgba(15, 23, 42, 0.14)'
                : '0 2px 8px rgba(148, 163, 184, 0.18)';
            }

            if (!card.dataset.mdmboxToggleBound) {
              card.dataset.mdmboxToggleBound = '1';
              card.addEventListener('click', function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                if (card.dataset.mdmboxToggle === 'tun') window.mdmboxBridge.toggleTun();
                if (card.dataset.mdmboxToggle === 'system-proxy') window.mdmboxBridge.toggleSystemProxy();
              });
            }
          });

          const speedNodes = Array.from(document.querySelectorAll('span')).filter(function (n) {
            const text = (n.textContent || '').trim().toLowerCase();
            return text.includes('kb/s') || text.includes('mb/s') || text.includes('gb/s') ||
                   text.includes('кб/с') || text.includes('мб/с') || text.includes('гб/с') ||
                   text.includes('b/s') || text.includes('б/с');
          });
          if (speedNodes.length >= 2) {
            speedNodes[0].textContent = state.download || '0 B/s';
            speedNodes[1].textContent = state.upload || '0 B/s';
          }

          function pingColor(ms) {
            if (ms > 900) return '#dc2626';
            if (ms >= 101) return '#d97706';
            return '#16a34a';
          }

          const pingValue = Array.from(document.querySelectorAll('span')).find(function (n) {
            const text = (n.textContent || '').trim();
            return text.endsWith('мс') || text.endsWith('ms');
          });
          if (pingValue && pingValue.parentElement && (pingValue.parentElement.textContent || '').includes('Пинг')) {
            pingValue.textContent = state.ping;
            pingValue.style.color = pingColor(Number(state.pingMs || 0));
            pingValue.style.fontWeight = '700';
          }

          const sidebarButton = Array.from(document.querySelectorAll('aside button')).find(function (n) {
            const text = (n.textContent || '').trim();
            return text.includes('Подключ') || text.includes('Отключ');
          });
          if (sidebarButton) {
            sidebarButton.textContent = state.sidebarButton;
            if (!sidebarButton.dataset.mdmboxConnectBound) {
              sidebarButton.dataset.mdmboxConnectBound = '1';
              sidebarButton.addEventListener('click', function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                window.mdmboxBridge.connectToggle();
              });
            }
          }

          const metricNode = Array.from(document.querySelectorAll('div, span, p')).find(function (n) {
            const text = (n.textContent || '').trim();
            return text.includes('Пинг:') || text.includes('0 B/s') || text.includes('0 Б/с');
          });
          if (metricNode) {
            let footerLike = metricNode.closest('footer');
            if (!footerLike) {
              let current = metricNode;
              for (let i = 0; i < 8 && current; ++i) {
                const text = (current.textContent || '').trim();
                if (text.includes('Пинг:') &&
                    (text.includes('B/s') || text.includes('Б/с') || text.includes('KB/s') || text.includes('КБ/с') ||
                     text.includes('MB/s') || text.includes('МБ/с'))) {
                  footerLike = current;
                  break;
                }
                current = current.parentElement;
              }
            }
            if (footerLike) {
              footerLike.remove();
            }
          }
        }
    )JS");
}

QString MdmBoxShellWindow::buildServersScript() const {
    return QStringLiteral(R"JS(
        function setServersState() {
          const actionButton = Array.from(document.querySelectorAll('button')).find(function (n) {
            return (n.textContent || '').includes('Добавить подписку') || (n.textContent || '').includes('Вставить ссылку');
          });
          if (actionButton) {
            const textNode = Array.from(actionButton.querySelectorAll('span')).find(function (n) {
              return (n.textContent || '').includes('Добавить подписку') || (n.textContent || '').includes('Вставить ссылку');
            });
            if (textNode) textNode.textContent = 'Вставить ссылку';
            else actionButton.textContent = 'Вставить ссылку';
            if (!actionButton.dataset.mdmboxImportBound) {
              actionButton.dataset.mdmboxImportBound = '1';
              actionButton.addEventListener('click', function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                window.mdmboxBridge.importClipboard();
              });
            }
          }

          const host = document.querySelector('div.flex.gap-2.mb-6.border-b.border-slate-100.pb-2');
          if (host) {
            host.innerHTML = '';
            host.style.display = 'flex';
            host.style.gap = '8px';
            host.style.alignItems = 'center';
            host.style.flexWrap = 'wrap';
            servers.groups.forEach(function (group) {
              const button = document.createElement('button');
              button.type = 'button';
              button.textContent = group.name;
              button.className = group.isCurrent
                ? 'px-4 py-1.5 text-sm font-semibold text-primary border-b-2 border-primary'
                : 'px-4 py-1.5 text-sm font-medium text-slate-500 hover:text-slate-900 transition-colors';
              button.addEventListener('click', function () {
                window.mdmboxBridge.selectGroup(group.id);
              });
              host.appendChild(button);
            });
          }

          const tbody = document.querySelector('tbody');
          if (!tbody) return;
          tbody.innerHTML = '';
          servers.items.forEach(function (server) {
            const row = document.createElement('tr');
            row.className = server.isRunning ? 'bg-primary/5 hover:bg-primary/10 transition-colors cursor-pointer'
                                             : 'hover:bg-slate-50 transition-colors cursor-pointer';
            row.innerHTML =
              '<td class=\"px-6 py-4\"><div class=\"h-2.5 w-2.5 rounded-full ' + (server.isRunning ? 'bg-primary ring-4 ring-primary/10' : (server.isSelected ? 'bg-primary' : 'bg-slate-300')) + '\"></div></td>' +
              '<td class=\"px-6 py-4\"><div class=\"flex items-center gap-3\"><div class=\"w-8 h-5 rounded bg-blue-600 flex items-center justify-center text-[9px] text-white font-bold\">' + server.badge + '</div><div><div class=\"text-sm ' + (server.isRunning ? 'font-semibold' : 'font-medium') + ' text-on-surface\">' + server.name + '</div>' + (server.isRunning ? '<div class=\"text-[10px] text-primary font-bold uppercase\">Активен</div>' : (server.isSelected ? '<div class=\"text-[10px] text-primary font-bold uppercase\">Выбран</div>' : '<div class=\"text-[10px] text-slate-500\">' + server.address + '</div>')) + '</div></div></td>' +
              '<td class=\"px-6 py-4 text-right\"><span class=\"text-sm ' + (server.isRunning ? 'font-medium text-primary' : 'text-slate-600') + '\">' + server.latency + '</span></td>' +
              '<td class=\"px-6 py-4 text-right\"><span class=\"text-sm text-on-surface\">' + server.traffic + '</span></td>';
            row.addEventListener('click', function () { window.mdmboxBridge.selectServer(server.id); });
            tbody.appendChild(row);
          });

          const sidebarButton = Array.from(document.querySelectorAll('aside button')).find(function (n) {
            const text = (n.textContent || '').trim();
            return text.includes('Подключ') || text.includes('Отключ');
          });
          if (sidebarButton) sidebarButton.textContent = state.sidebarButton;

          const signalTitle = Array.from(document.querySelectorAll('div, span')).find(function (n) {
            return (n.textContent || '').trim().toLowerCase().includes('стабильность сигнала');
          });
          const signalCard = signalTitle ? signalTitle.closest('.rounded-xl, .rounded-2xl, .border') : null;
          if (signalCard && state.signal) {
            const signal = state.signal;
            const texts = Array.from(signalCard.querySelectorAll('div, span'));
            const gradeNode = texts.find(function (n) {
              const text = (n.textContent || '').trim();
              return text === 'Отлично' || text === 'Хорошо' || text === 'Средне' || text === 'Плохо' || text === 'Нестабильно' || text === 'Нет данных';
            });
            const subtitleNode = texts.find(function (n) {
              return (n.textContent || '').trim().includes('Стабильность') || (n.textContent || '').trim().includes('Пинг ') || (n.textContent || '').trim().includes('Запустите проверку');
            });
            if (gradeNode) {
              gradeNode.textContent = signal.grade || 'Нет данных';
              gradeNode.style.color = signal.accent || '#94a3b8';
            }
            if (subtitleNode) subtitleNode.textContent = signal.subtitle || 'Запустите проверку узла';

            const iconWrap = signalCard.querySelector('.rounded-full');
            if (iconWrap) iconWrap.style.background = (signal.accent || '#94a3b8') + '1A';
            const icon = signalCard.querySelector('.material-symbols-outlined');
            if (icon) icon.style.color = signal.accent || '#94a3b8';
          }
        }
    )JS");
}

QString MdmBoxShellWindow::buildRoutingScript() const {
    return QStringLiteral(R"JS(
        function setRoutingState() {
          const routeRoot = Array.from(document.querySelectorAll('h1')).find(function (n) {
            return (n.textContent || '').includes('Правила маршрутизации');
          });
          const container = routeRoot ? routeRoot.closest('.max-w-4xl') : null;
          if (!container || !routing || !routing.tabs || !routing.tabs.length) return;

          const activeTabIndex = Math.min(window.__mdmboxRouteTab || 0, routing.tabs.length - 1);
          const currentTab = routing.tabs[activeTabIndex] || routing.tabs[0];
          const routingSignature = JSON.stringify({
            defaultOutbound: routing.defaultOutbound || 'bypass',
            activeTabIndex: activeTabIndex,
            tabs: routing.tabs
          });
          if (container.dataset.mdmboxRoutingSig === routingSignature) return;
          container.dataset.mdmboxRoutingSig = routingSignature;

          function policyBadgeClass(policy) {
            if (policy === 'block') return 'text-error';
            if (policy === 'proxy') return 'text-primary';
            return 'text-secondary';
          }

          function policyIcon(policy) {
            if (policy === 'block') return 'block';
            if (policy === 'proxy') return 'shield';
            return 'public';
          }

          function policyIconWrap(policy) {
            if (policy === 'block') return 'bg-error-container/10 text-error';
            if (policy === 'proxy') return 'bg-primary/10 text-primary';
            return 'bg-tertiary-container/10 text-tertiary';
          }

          const rulesHtml = currentTab.rules.length
            ? currentTab.rules.map(function (rule) {
                return '' +
                  '<div class="bg-surface-container-lowest p-3.5 rounded-lg flex items-center justify-between border border-outline-variant/10 hover:border-outline-variant/30 transition-all">' +
                    '<div class="flex items-center gap-3 min-w-0">' +
                      '<span class="material-symbols-outlined text-outline/40">drag_indicator</span>' +
                      '<div class="w-9 h-9 rounded flex items-center justify-center shrink-0 ' + policyIconWrap(rule.policy) + '">' +
                        '<span class="material-symbols-outlined text-xl">' + policyIcon(rule.policy) + '</span>' +
                      '</div>' +
                      '<div class="min-w-0">' +
                        '<div class="font-semibold text-sm truncate">' + rule.value + '</div>' +
                        '<div class="text-[11px] text-on-surface-variant">' + rule.kind + ' • <span class="' + policyBadgeClass(rule.policy) + '">' + rule.policyLabel + '</span></div>' +
                      '</div>' +
                    '</div>' +
                    '<div class="flex items-center gap-1 shrink-0">' +
                      '<button class="p-1.5 hover:bg-surface-container-high rounded text-on-surface-variant" data-mdmbox-edit="' + rule.value.replace(/"/g, '&quot;') + '" data-mdmbox-policy="' + rule.policy + '">' +
                        '<span class="material-symbols-outlined text-lg">edit</span>' +
                      '</button>' +
                      '<button class="p-1.5 hover:bg-error/10 rounded text-error" data-mdmbox-remove="' + rule.value.replace(/"/g, '&quot;') + '" data-mdmbox-policy="' + rule.policy + '">' +
                        '<span class="material-symbols-outlined text-lg">delete</span>' +
                      '</button>' +
                    '</div>' +
                  '</div>';
              }).join('')
            : '<div class="bg-surface-container-lowest p-5 rounded-lg border border-outline-variant/20 text-sm text-on-surface-variant">Для этого режима пока нет правил.</div>';

          container.innerHTML =
            '<header class="mb-12">' +
              '<h1 class="text-3xl font-bold tracking-tight text-on-surface mb-2">Правила маршрутизации</h1>' +
              '<p class="text-on-surface-variant text-sm max-w-2xl leading-relaxed">Определите способ обработки трафика в зависимости от назначения или исходного приложения. Правила обрабатываются по порядку сверху вниз.</p>' +
            '</header>' +
            '<section class="mb-10 p-5 bg-surface-container-lowest rounded-xl border border-outline-variant/30 flex items-center justify-between gap-4">' +
              '<div class="flex items-center gap-4 min-w-0">' +
                '<div class="w-10 h-10 rounded-full bg-primary/5 flex items-center justify-center text-primary shrink-0">' +
                  '<span class="material-symbols-outlined">language</span>' +
                '</div>' +
                '<div class="min-w-0">' +
                  '<h2 class="font-semibold text-sm text-on-surface">Исходящий по умолчанию</h2>' +
                  '<p class="text-[11px] text-on-surface-variant">Политика для трафика, не подошедшего под правила</p>' +
                '</div>' +
              '</div>' +
              '<div class="relative shrink-0">' +
                '<select data-mdmbox-default-outbound="1" class="appearance-none bg-surface-container-high border-none rounded-lg px-4 py-2 pr-10 text-xs font-bold focus:ring-1 focus:ring-primary cursor-pointer min-w-[120px]">' +
                  '<option value="proxy"' + ((routing.defaultOutbound || 'bypass') === 'proxy' ? ' selected' : '') + '>Proxy</option>' +
                  '<option value="bypass"' + ((routing.defaultOutbound || 'bypass') === 'bypass' ? ' selected' : '') + '>Bypass</option>' +
                  '<option value="block"' + ((routing.defaultOutbound || 'bypass') === 'block' ? ' selected' : '') + '>Block</option>' +
                '</select>' +
                '<span class="material-symbols-outlined absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none text-on-surface-variant text-lg">expand_more</span>' +
              '</div>' +
            '</section>' +
            '<div class="flex gap-6 border-b border-outline-variant/20 mb-8">' +
              routing.tabs.map(function (tab, index) {
                const active = index === activeTabIndex;
                return '<button data-mdmbox-route-tab="' + index + '" class="pb-3 text-sm ' + (active ? 'font-bold text-primary border-b-2 border-primary' : 'font-medium text-on-surface-variant hover:text-on-surface transition-all') + '">' + tab.title + '</button>';
              }).join('') +
            '</div>' +
            '<div class="grid grid-cols-12 gap-8">' +
              '<div class="col-span-12 lg:col-span-8 space-y-3">' +
                '<div class="flex items-center justify-between mb-2">' +
                  '<h3 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Активные правила (' + currentTab.rules.length + ')</h3>' +
                  '<button data-mdmbox-add-rule="1" class="flex items-center gap-1.5 text-primary text-xs font-bold hover:opacity-80">' +
                    '<span class="material-symbols-outlined text-lg">add</span> Добавить правило' +
                  '</button>' +
                '</div>' +
                rulesHtml +
              '</div>' +
              '<div class="col-span-12 lg:col-span-4 space-y-6">' +
                '<div class="bg-surface-container-low p-5 rounded-xl space-y-2 border border-outline-variant/20">' +
                  '<h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-4">Действия</h4>' +
                  '<button data-mdmbox-import-rules="1" class="w-full flex items-center justify-between p-2.5 hover:bg-surface-container-highest rounded-lg transition-all text-xs font-medium group">' +
                    '<span>Импорт списка</span>' +
                    '<span class="material-symbols-outlined text-primary group-hover:translate-y-[-1px] transition-transform">upload</span>' +
                  '</button>' +
                  '<button data-mdmbox-export-rules="1" class="w-full flex items-center justify-between p-2.5 hover:bg-surface-container-highest rounded-lg transition-all text-xs font-medium group">' +
                    '<span>Экспорт конфига</span>' +
                    '<span class="material-symbols-outlined text-primary group-hover:translate-y-[1px] transition-transform">download</span>' +
                  '</button>' +
                  '<button data-mdmbox-reset-rules="1" class="w-full flex items-center justify-between p-2.5 hover:bg-error/5 rounded-lg transition-all text-xs font-medium text-error group mt-2">' +
                    '<span>Сбросить правила</span>' +
                    '<span class="material-symbols-outlined group-hover:rotate-45 transition-transform">restart_alt</span>' +
                  '</button>' +
                '</div>' +
              '</div>' +
            '</div>';

          const outboundSelect = container.querySelector('[data-mdmbox-default-outbound="1"]');
          if (outboundSelect) {
            outboundSelect.addEventListener('mousedown', function () {
              window.__mdmboxFreezeRefreshUntil = Date.now() + 2200;
            });
            outboundSelect.addEventListener('change', function () {
              window.__mdmboxFreezeRefreshUntil = Date.now() + 700;
              window.mdmboxBridge.routingSetDefault(outboundSelect.value);
            });
          }

          container.querySelectorAll('[data-mdmbox-route-tab]').forEach(function (button) {
            button.addEventListener('click', function () {
              window.__mdmboxFreezeRefreshUntil = Date.now() + 500;
              window.__mdmboxRouteTab = Number(button.dataset.mdmboxRouteTab || 0);
              setRoutingState();
            });
          });

          const addButton = container.querySelector('[data-mdmbox-add-rule="1"]');
          if (addButton) {
            addButton.addEventListener('click', function () {
              window.mdmboxBridge.routingAddRule(window.__mdmboxRouteTab || 0);
            });
          }

          const importButton = container.querySelector('[data-mdmbox-import-rules="1"]');
          if (importButton) {
            importButton.addEventListener('click', function () {
              window.mdmboxBridge.routingImportClipboard(window.__mdmboxRouteTab || 0);
            });
          }

          const exportButton = container.querySelector('[data-mdmbox-export-rules="1"]');
          if (exportButton) {
            exportButton.addEventListener('click', function () {
              window.mdmboxBridge.routingExportConfig();
            });
          }

          const resetButton = container.querySelector('[data-mdmbox-reset-rules="1"]');
          if (resetButton) {
            resetButton.addEventListener('click', function () {
              window.mdmboxBridge.routingResetRules(window.__mdmboxRouteTab || 0);
            });
          }

          container.querySelectorAll('[data-mdmbox-edit]').forEach(function (button) {
            button.addEventListener('click', function (ev) {
              ev.preventDefault();
              ev.stopPropagation();
              window.mdmboxBridge.routingEditRule(window.__mdmboxRouteTab || 0, button.dataset.mdmboxEdit || '', button.dataset.mdmboxPolicy || '');
            });
          });

          container.querySelectorAll('[data-mdmbox-remove]').forEach(function (button) {
            button.addEventListener('click', function (ev) {
              ev.preventDefault();
              ev.stopPropagation();
              window.mdmboxBridge.routingRemoveRule(window.__mdmboxRouteTab || 0, button.dataset.mdmboxRemove || '', button.dataset.mdmboxPolicy || '');
            });
          });
        }
    )JS");
}

QString MdmBoxShellWindow::buildLogsScript() const {
    return QStringLiteral(R"JS(
        function mdmboxEscapeHtml(value) {
          return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        }

        function mdmboxLogKind(line) {
          const lower = String(line || '').toLowerCase();
          if (lower.includes('error') || lower.includes('[error]') || lower.includes('failed')) return 'error';
          if (lower.includes('warn')) return 'warn';
          if (lower.includes('debug')) return 'debug';
          if (lower.includes('success') || lower.includes('started') || lower.includes('listening')) return 'success';
          return 'info';
        }

        function mdmboxParseLogLine(line) {
          const trimmed = String(line || '').trim();
          const timeMatch = trimmed.match(/^(\d{1,2}:\d{2}:\d{2})\s+(.*)$/);
          let timestamp = '';
          let message = trimmed;
          if (timeMatch) {
            timestamp = timeMatch[1];
            message = timeMatch[2];
          }
          const levelMatch = message.match(/^\[([A-Za-z]+)\]\s*(.*)$/);
          let level = '';
          if (levelMatch) {
            level = levelMatch[1].toUpperCase();
            message = levelMatch[2];
          } else {
            const kind = mdmboxLogKind(trimmed);
            level = kind === 'error' ? 'ERROR' : kind === 'warn' ? 'WARN' : kind === 'debug' ? 'DEBU' : 'INFO';
          }
          return { timestamp: timestamp || '--:--:--', level: level, message: message, kind: mdmboxLogKind(trimmed) };
        }

        function setLogsState() {
          const container =
            document.querySelector('main > div.flex-1.p-6.overflow-hidden.flex.flex-col') ||
            document.querySelector('main > div.flex-1') ||
            document.querySelector('main .flex-1');
          if (!container || !logs) return;

          const signature = JSON.stringify({
            total: logs.total || 0,
            errors: logs.errors || 0,
            size: logs.size || '',
            uptime: logs.uptime || '',
            last: logs.lines && logs.lines.length ? logs.lines[logs.lines.length - 1] : ''
          });
          if (container.dataset.mdmboxLogsSig === signature) return;
          container.dataset.mdmboxLogsSig = signature;
          container.style.width = '100%';
          container.style.maxWidth = '100%';
          container.style.minWidth = '0';
          container.style.boxSizing = 'border-box';
          container.style.display = 'flex';
          container.style.flexDirection = 'column';
          container.style.height = '100%';
          container.style.padding = '24px';
          container.style.overflow = 'hidden';

          const renderedLines = (logs.lines || []).map(function (raw) {
            const line = mdmboxParseLogLine(raw);
            const palette =
              line.kind === 'error' ? { level: 'text-red-500', text: 'text-red-200', row: 'bg-red-500/10 border-l-2 border-red-500 -mx-4 px-4' } :
              line.kind === 'warn' ? { level: 'text-amber-400', text: 'text-slate-200', row: '' } :
              line.kind === 'debug' ? { level: 'text-purple-400', text: 'text-slate-500 italic', row: '' } :
              line.kind === 'success' ? { level: 'text-emerald-400', text: 'text-emerald-100/80', row: '' } :
              { level: 'text-blue-400', text: 'text-slate-300', row: '' };
            return '' +
              '<div class="flex gap-4 mb-1 group ' + palette.row + '">' +
                '<span class="text-slate-600 shrink-0">' + mdmboxEscapeHtml(line.timestamp) + '</span>' +
                '<span class="' + palette.level + ' font-bold w-12 shrink-0">' + mdmboxEscapeHtml(line.level) + '</span>' +
                '<span class="' + palette.text + ' whitespace-pre-wrap break-all">' + mdmboxEscapeHtml(line.message) + '</span>' +
              '</div>';
          }).join('');

          container.innerHTML =
            '<div class="flex items-center justify-between mb-4 shrink-0">' +
              '<div class="flex items-center gap-2">' +
                '<h2 class="text-xl font-bold tracking-tight">Системный журнал</h2>' +
                '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700 uppercase">Live</span>' +
              '</div>' +
              '<div class="flex gap-2">' +
                '<button data-mdmbox-clear-logs="1" class="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold bg-white border border-slate-200 rounded-md hover:bg-slate-50 transition-all shadow-sm">' +
                  '<span class="material-symbols-outlined text-sm">delete_sweep</span>Очистить' +
                '</button>' +
                '<button data-mdmbox-export-logs="1" class="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold bg-white border border-slate-200 rounded-md hover:bg-slate-50 transition-all shadow-sm">' +
                  '<span class="material-symbols-outlined text-sm">download</span>Экспорт' +
                '</button>' +
              '</div>' +
            '</div>' +
            '<div class="flex-1 min-h-0 w-full bg-slate-950 rounded-xl shadow-2xl border border-slate-800 overflow-hidden flex flex-col">' +
              '<div class="px-4 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between shrink-0">' +
                '<div class="flex gap-4">' +
                  '<div class="flex items-center gap-1.5">' +
                    '<div class="w-2 h-2 rounded-full ' + ((logs.total || 0) > 0 ? 'bg-emerald-500' : 'bg-slate-500') + '"></div>' +
                    '<span class="text-[10px] font-mono text-slate-400 uppercase tracking-widest">' + ((logs.total || 0) > 0 ? 'Connected' : 'Idle') + '</span>' +
                  '</div>' +
                  '<div class="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Buffer: ' + String(logs.total || 0) + '</div>' +
                '</div>' +
                '<div class="flex items-center gap-3">' +
                  '<span class="text-[10px] font-mono text-slate-500">Auto-scroll</span>' +
                  '<div class="w-8 h-4 bg-blue-600 rounded-full relative"><div class="absolute right-1 top-1 w-2 h-2 bg-white rounded-full"></div></div>' +
                '</div>' +
              '</div>' +
              '<div data-mdmbox-log-output="1" class="flex-1 min-h-[280px] p-4 overflow-y-auto console-font text-[13px] leading-relaxed custom-scrollbar bg-slate-950/50">' +
                (renderedLines || '<div class=\"text-slate-500 text-sm\">Логи пока пусты.</div>') +
              '</div>' +
            '</div>' +
            '<div class="mt-4 grid grid-cols-4 gap-4 w-full shrink-0">' +
              '<div class="bg-white/50 p-3 rounded-lg border border-slate-200/50 flex flex-col"><span class="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">Всего логов</span><span class="text-lg font-semibold tracking-tight">' + String(logs.total || 0) + '</span></div>' +
              '<div class="bg-white/50 p-3 rounded-lg border border-slate-200/50 flex flex-col"><span class="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">Ошибок</span><span class="text-lg font-semibold tracking-tight text-red-500">' + String(logs.errors || 0) + '</span></div>' +
              '<div class="bg-white/50 p-3 rounded-lg border border-slate-200/50 flex flex-col"><span class="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">Размер файла</span><span class="text-lg font-semibold tracking-tight">' + mdmboxEscapeHtml(logs.size || '0 B') + '</span></div>' +
              '<div class="bg-white/50 p-3 rounded-lg border border-slate-200/50 flex flex-col"><span class="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">Аптайм</span><span class="text-lg font-semibold tracking-tight">' + mdmboxEscapeHtml(logs.uptime || '00:00:00') + '</span></div>' +
            '</div>';

          const output = container.querySelector('[data-mdmbox-log-output="1"]');
          if (output) output.scrollTop = output.scrollHeight;

          const clearButton = container.querySelector('[data-mdmbox-clear-logs="1"]');
          if (clearButton) {
            clearButton.addEventListener('click', function () {
              window.mdmboxBridge.clearLogs();
            });
          }

          const exportButton = container.querySelector('[data-mdmbox-export-logs="1"]');
          if (exportButton) {
            exportButton.addEventListener('click', function () {
              window.mdmboxBridge.exportLogs();
            });
          }
        }
    )JS");
}

void MdmBoxShellWindow::refreshPageState() {
    if (!view) return;
    if (currentPage == QStringLiteral("dashboard") || currentPage == QStringLiteral("servers")) {
        if (auto *mw = GetMainWindow()) mw->shellMaybeScheduleSignalProbe();
    }
    view->page()->runJavaScript(buildRefreshScript());
}

void MdmBoxShellWindow::triggerConnectToggle() {
    auto *mw = GetMainWindow();
    if (!mw) return;
    if (connectToggleInFlight) return;
    connectToggleInFlight = true;
    QTimer::singleShot(1500, this, [this] { connectToggleInFlight = false; });

    if (NekoGui::dataStore->started_id >= 0) {
        mw->neko_stop();
        refreshPageState();
        return;
    }

    int id = effectiveSelectedId();
    if (id < 0) return;
    if (NekoGui::dataStore->selected_id != id) {
        NekoGui::dataStore->selected_id = id;
        NekoGui::dataStore->Save();
    }
    mw->neko_start(id);
    refreshPageState();
}

void MdmBoxShellWindow::triggerTunToggle() {
    if (NekoGui::dataStore && NekoGui::dataStore->vpn_implementation != 1) {
        NekoGui::dataStore->vpn_implementation = 1;
        NekoGui::dataStore->Save();
    }
    if (NekoGui::dataStore && !NekoGui::dataStore->remember_enable) {
        NekoGui::dataStore->remember_enable = true;
        NekoGui::dataStore->Save();
    }
    if (auto *mw = GetMainWindow()) {
        mw->neko_set_spmode_vpn(!NekoGui::dataStore->spmode_vpn);
        refreshPageState();
    }
}

void MdmBoxShellWindow::triggerSystemProxyToggle() {
    if (NekoGui::dataStore && !NekoGui::dataStore->remember_enable) {
        NekoGui::dataStore->remember_enable = true;
        NekoGui::dataStore->Save();
    }
    if (auto *mw = GetMainWindow()) {
        mw->neko_set_spmode_system_proxy(!NekoGui::dataStore->spmode_system_proxy);
        refreshPageState();
    }
}

void MdmBoxShellWindow::triggerClipboardImport() {
    if (auto *mw = GetMainWindow()) {
        QMetaObject::invokeMethod(mw, "on_menu_add_from_clipboard_triggered", Qt::DirectConnection);
    }
    QTimer::singleShot(800, this, [this] { refreshPageState(); });
    QTimer::singleShot(1800, this, [this] { refreshPageState(); });
}

void MdmBoxShellWindow::triggerOpenLegacy() {
    hide();
    if (auto *mw = GetMainWindow()) {
        mw->show_group(NekoGui::dataStore->current_group);
        mw->show();
        mw->raise();
        mw->activateWindow();
    }
}

void MdmBoxShellWindow::triggerSelectServer(int id) {
    if (!NekoGui::dataStore) return;
    NekoGui::dataStore->selected_id = id;
    NekoGui::dataStore->Save();

    if (auto *mw = GetMainWindow(); mw && NekoGui::dataStore->started_id >= 0) {
        mw->neko_start(id);
    }

    refreshPageState();
}

void MdmBoxShellWindow::triggerSelectGroup(int gid) {
    if (!NekoGui::dataStore) return;
    NekoGui::dataStore->current_group = gid;
    NekoGui::dataStore->Save();

    if (auto *mw = GetMainWindow()) {
        mw->show_group(gid);
    }

    const int selectedId = effectiveSelectedId();
    if (selectedId >= 0) {
        NekoGui::dataStore->selected_id = selectedId;
        NekoGui::dataStore->Save();
    }

    refreshPageState();
}

void MdmBoxShellWindow::triggerRoutingSetDefault(const QString &policy) {
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;
    NekoGui::dataStore->routing->def_outbound = normalizedPolicy(policy);
    saveActiveRoutingState(true);
    if (auto *mw = GetMainWindow(); mw && NekoGui::dataStore->started_id >= 0) {
        mw->neko_start(NekoGui::dataStore->started_id);
    }
    refreshPageState();
}

void MdmBoxShellWindow::triggerRoutingAddRule(int tabIndex) {
    triggerRoutingEditRule(tabIndex, QString(), QString());
}

void MdmBoxShellWindow::triggerRoutingEditRule(int tabIndex, const QString &value, const QString &policy) {
    if (!NekoGui::dataStore || !NekoGui::dataStore->routing) return;

    QDialog dialog(this);
    dialog.setWindowTitle(value.isEmpty() ? tr("Добавить правило") : tr("Изменить правило"));
    dialog.setModal(true);

    auto *layout = new QVBoxLayout(&dialog);
    auto *form = new QFormLayout;
    auto *valueEdit = new QLineEdit(&dialog);
    valueEdit->setText(value);
    valueEdit->setPlaceholderText(
        tabIndex == 0 ? tr("Например: *.google.com")
                      : tabIndex == 1 ? tr("Например: Discord.exe")
                                      : tr("Например: 8.8.8.8/32"));
    form->addRow(tr("Правило"), valueEdit);

    auto *policyCombo = new QComboBox(&dialog);
    if (tabIndex == 1) {
        policyCombo->addItems({QStringLiteral("Bypass"), QStringLiteral("Proxy")});
        policyCombo->setCurrentText(policy.isEmpty()
                                        ? (NekoGui::dataStore->vpn_rule_white ? QStringLiteral("Proxy") : QStringLiteral("Bypass"))
                                        : displayPolicy(policy));
    } else {
        policyCombo->addItems({QStringLiteral("Bypass"), QStringLiteral("Proxy"), QStringLiteral("Block")});
        policyCombo->setCurrentText(policy.isEmpty() ? displayPolicy(NekoGui::dataStore->routing->def_outbound) : displayPolicy(policy));
    }
    form->addRow(tr("Политика"), policyCombo);
    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    if (dialog.exec() != QDialog::Accepted) return;

    const QString newValue = valueEdit->text().trimmed();
    if (newValue.isEmpty()) return;

    QList<RoutingRuleEntry> rules = collectRoutingRules(tabIndex);
    for (int i = rules.size() - 1; i >= 0; --i) {
        if (rules[i].value.compare(value, Qt::CaseInsensitive) == 0 && rules[i].policy == normalizedPolicy(policy)) {
            rules.removeAt(i);
        }
    }

    const QString selectedPolicy = normalizedPolicy(policyCombo->currentText());
    if (tabIndex == 1) {
        const bool newWhitelist = selectedPolicy == QStringLiteral("proxy");
        if (NekoGui::dataStore->vpn_rule_white != newWhitelist && !NekoGui::dataStore->vpn_rule_process.trimmed().isEmpty()) {
            const auto answer = QMessageBox::question(
                this,
                tr("Изменить режим процессов"),
                newWhitelist ? tr("Переключить список процессов в Proxy mode? Это изменит поведение всех правил на вкладке приложений.")
                             : tr("Переключить список процессов в Bypass mode? Это изменит поведение всех правил на вкладке приложений."));
            if (answer != QMessageBox::Yes) return;
        }
        for (auto &rule : rules) rule.policy = selectedPolicy;
    }

    rules.append({newValue, selectedPolicy});
    storeRoutingRules(tabIndex, rules);
    refreshPageState();
}

void MdmBoxShellWindow::triggerRoutingRemoveRule(int tabIndex, const QString &value, const QString &policy) {
    QList<RoutingRuleEntry> rules = collectRoutingRules(tabIndex);
    for (int i = rules.size() - 1; i >= 0; --i) {
        if (rules[i].value.compare(value, Qt::CaseInsensitive) == 0 && rules[i].policy == normalizedPolicy(policy)) {
            rules.removeAt(i);
            break;
        }
    }
    storeRoutingRules(tabIndex, rules);
    refreshPageState();
}

void MdmBoxShellWindow::triggerRoutingImportClipboard(int tabIndex) {
    const QString raw = QApplication::clipboard()->text().trimmed();
    if (raw.isEmpty()) {
        QMessageBox::information(this, tr("Импорт маршрутизации"), tr("Буфер обмена пуст."));
        return;
    }

    QList<RoutingRuleEntry> imported = collectRoutingRules(tabIndex);
    QString processPolicy = NekoGui::dataStore->vpn_rule_white ? QStringLiteral("proxy") : QStringLiteral("bypass");

    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(raw.toUtf8(), &error);
    if (error.error == QJsonParseError::NoError && document.isObject()) {
        const QJsonObject object = document.object();
        if (tabIndex == 0) {
            appendRulesFromValue(imported, object.value(QStringLiteral("direct_domain")), QStringLiteral("bypass"));
            appendRulesFromValue(imported, object.value(QStringLiteral("proxy_domain")), QStringLiteral("proxy"));
            appendRulesFromValue(imported, object.value(QStringLiteral("block_domain")), QStringLiteral("block"));
        } else if (tabIndex == 1) {
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
        const QString fallbackPolicy = tabIndex == 1
            ? (NekoGui::dataStore->vpn_rule_white ? QStringLiteral("proxy") : QStringLiteral("bypass"))
            : normalizedPolicy(NekoGui::dataStore->routing->def_outbound);
        for (QString line : lines(raw)) {
            line = line.trimmed();
            QString currentPolicy = fallbackPolicy;
            QString currentValue = line;
            const QString lower = line.toLower();
            if (lower.startsWith(QStringLiteral("[proxy]"))) {
                currentPolicy = QStringLiteral("proxy");
                currentValue = line.mid(7).trimmed();
            } else if (lower.startsWith(QStringLiteral("[bypass]")) || lower.startsWith(QStringLiteral("[direct]"))) {
                currentPolicy = QStringLiteral("bypass");
                currentValue = line.mid(line.indexOf(']') + 1).trimmed();
            } else if (lower.startsWith(QStringLiteral("[block]"))) {
                currentPolicy = QStringLiteral("block");
                currentValue = line.mid(7).trimmed();
            } else if (lower.startsWith(QStringLiteral("proxy:"))) {
                currentPolicy = QStringLiteral("proxy");
                currentValue = line.mid(6).trimmed();
            } else if (lower.startsWith(QStringLiteral("bypass:")) || lower.startsWith(QStringLiteral("direct:"))) {
                currentPolicy = QStringLiteral("bypass");
                currentValue = line.mid(line.indexOf(':') + 1).trimmed();
            } else if (lower.startsWith(QStringLiteral("block:"))) {
                currentPolicy = QStringLiteral("block");
                currentValue = line.mid(6).trimmed();
            }

            currentValue = normalizedPlainRuleValue(currentValue);
            if (!currentValue.isEmpty()) imported.append({currentValue, currentPolicy});
        }
    }

    storeRoutingRules(tabIndex, imported);
    refreshPageState();
}

void MdmBoxShellWindow::triggerRoutingExportConfig() {
    const QString path = QFileDialog::getSaveFileName(this, tr("Экспорт маршрутизации"), QStringLiteral("mdmbox-routing.txt"), tr("Text files (*.txt)"));
    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QFile::WriteOnly | QFile::Text)) return;
    file.write(QJsonDocument(buildRoutingExportObject()).toJson(QJsonDocument::Indented));
}

void MdmBoxShellWindow::triggerRoutingResetRules(int tabIndex) {
    if (QMessageBox::question(this, tr("Сбросить правила"), tr("Очистить правила текущей вкладки?")) != QMessageBox::Yes) return;

    if (tabIndex == 0) {
        NekoGui::dataStore->routing->direct_domain.clear();
        NekoGui::dataStore->routing->proxy_domain.clear();
        NekoGui::dataStore->routing->block_domain.clear();
        saveActiveRoutingState(true);
    } else if (tabIndex == 1) {
        NekoGui::dataStore->vpn_rule_process.clear();
        saveTunRuleState();
    } else {
        NekoGui::dataStore->routing->direct_ip.clear();
        NekoGui::dataStore->routing->proxy_ip.clear();
        NekoGui::dataStore->routing->block_ip.clear();
        saveActiveRoutingState(true);
    }

    refreshPageState();
}

void MdmBoxShellWindow::triggerClearLogs() {
    if (auto *mw = GetMainWindow()) {
        mw->shellClearLogs();
    }
    refreshPageState();
}

void MdmBoxShellWindow::triggerExportLogs() {
    auto *mw = GetMainWindow();
    if (!mw) return;

    const QString path = QFileDialog::getSaveFileName(this, tr("Экспорт логов"), QStringLiteral("mdmbox-logs.txt"), tr("Text files (*.txt);;All files (*.*)"));
    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text)) {
        QMessageBox::warning(this, tr("Экспорт логов"), tr("Не удалось сохранить файл."));
        return;
    }

    file.write(mw->shellLogText().toUtf8());
    file.close();
}

void MdmBoxShellWindow::triggerExitProgram() {
    allowHardClose = true;
    if (auto *mw = GetMainWindow()) {
        mw->on_menu_exit_triggered();
    }
}
