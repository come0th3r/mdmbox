#include "db/ProfileFilter.hpp"
#include "fmt/includes.h"
#include "fmt/Preset.hpp"
#include "main/HTTPRequestHelper.hpp"

#include "GroupUpdater.hpp"

#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrlQuery>

#ifndef NKR_NO_YAML

#include <yaml-cpp/yaml.h>

#endif

namespace {
    QString jsonString(const QJsonValue &value, const QString &def = "") {
        if (value.isString()) return value.toString();
        if (value.isDouble()) return QString::number(value.toInt());
        if (value.isBool()) return value.toBool() ? "true" : "false";
        return def;
    }

    int jsonInt(const QJsonValue &value, int def = 0) {
        if (value.isDouble()) return value.toInt(def);
        bool ok = false;
        auto parsed = jsonString(value).toInt(&ok);
        return ok ? parsed : def;
    }

    bool jsonBool(const QJsonValue &value, bool def = false) {
        if (value.isBool()) return value.toBool();
        auto normalized = jsonString(value).trimmed().toLower();
        if (normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on") return true;
        if (normalized == "0" || normalized == "false" || normalized == "no" || normalized == "off") return false;
        return def;
    }

    QStringList jsonStringList(const QJsonValue &value) {
        QStringList list;
        if (value.isArray()) {
            for (const auto &item: value.toArray()) {
                auto str = jsonString(item).trimmed();
                if (!str.isEmpty()) list << str;
            }
        } else {
            auto str = jsonString(value).trimmed();
            if (!str.isEmpty()) list << str;
        }
        return list;
    }

    QString firstNonEmpty(const QStringList &values) {
        for (const auto &value: values) {
            auto trimmed = value.trimmed();
            if (!trimmed.isEmpty()) return trimmed;
        }
        return {};
    }

    QString headerHostValue(const QJsonValue &value) {
        if (value.isObject()) {
            return firstNonEmpty(jsonStringList(value.toObject().value("Host")));
        }
        return firstNonEmpty(jsonStringList(value));
    }

    QJsonObject firstDefinedObject(const QJsonObject &object, const QStringList &keys) {
        for (const auto &key: keys) {
            const auto value = object.value(key);
            if (value.isObject()) return value.toObject();
        }
        return {};
    }

    void copyJsonCommonFields(const std::shared_ptr<NekoGui::ProxyEntity> &ent, const QJsonObject &proxy) {
        ent->bean->name = firstNonEmpty({
            jsonString(proxy.value("tag")),
            jsonString(proxy.value("name")),
            jsonString(proxy.value("remarks")),
            jsonString(proxy.value("ps")),
        });
        ent->bean->serverAddress = firstNonEmpty({
            jsonString(proxy.value("server")),
            jsonString(proxy.value("address")),
            jsonString(proxy.value("add")),
            jsonString(proxy.value("host")),
        });
        ent->bean->serverPort = jsonInt(proxy.value("server_port"), jsonInt(proxy.value("port")));
    }

    void applyTlsSettings(const QJsonObject &proxy, NekoGui_fmt::V2rayStreamSettings *stream) {
        auto tls = proxy.value("tls").toObject();
        bool tlsEnabled = proxy.value("tls").isBool() && proxy.value("tls").toBool();
        if (tls.contains("enabled")) tlsEnabled = jsonBool(tls.value("enabled"), tlsEnabled);
        if (jsonBool(proxy.value("tls_enabled")) || jsonBool(proxy.value("tls-enabled"))) tlsEnabled = true;
        if (tlsEnabled) stream->security = "tls";

        stream->allow_insecure =
            jsonBool(tls.value("insecure")) ||
            jsonBool(proxy.value("skip-cert-verify")) ||
            jsonBool(proxy.value("skip_cert_verify")) ||
            jsonBool(proxy.value("allowInsecure"));

        stream->sni = firstNonEmpty({
            jsonString(tls.value("server_name")),
            jsonString(proxy.value("sni")),
            jsonString(proxy.value("servername")),
            jsonString(proxy.value("serverName")),
            jsonString(proxy.value("peer")),
        });
        stream->alpn = jsonStringList(tls.value("alpn")).join(",");

        auto utls = tls.value("utls").toObject();
        stream->utlsFingerprint = firstNonEmpty({
            jsonString(utls.value("fingerprint")),
            jsonString(proxy.value("client-fingerprint")),
            jsonString(proxy.value("fingerprint")),
            jsonString(proxy.value("fp")),
        });
        if (stream->utlsFingerprint.isEmpty()) {
            stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
        }

        auto reality = tls.value("reality").toObject();
        if (!reality.isEmpty()) {
            stream->reality_pbk = jsonString(reality.value("public_key"));
            stream->reality_sid = jsonString(reality.value("short_id"));
        }
        auto realityOpts = firstDefinedObject(proxy, {"reality-opts"});
        if (!realityOpts.isEmpty()) {
            stream->reality_pbk = firstNonEmpty({stream->reality_pbk, jsonString(realityOpts.value("public-key"))});
            stream->reality_sid = firstNonEmpty({stream->reality_sid, jsonString(realityOpts.value("short-id"))});
            stream->reality_spx = jsonString(realityOpts.value("spider-x"));
        }
    }

    void applyTransportSettings(const QJsonObject &proxy, NekoGui_fmt::V2rayStreamSettings *stream) {
        auto transport = proxy.value("transport").toObject();
        auto transportType = jsonString(transport.value("type"));
        auto network = jsonString(proxy.value("network"));

        if (!transportType.isEmpty()) {
            if (transportType == "http" && transport.contains("method")) {
                stream->network = "tcp";
                stream->header_type = "http";
                stream->path = firstNonEmpty(jsonStringList(transport.value("path")));
                stream->host = headerHostValue(transport.value("headers"));
            } else {
                stream->network = transportType == "h2" ? "http" : transportType;
            }
        } else if (!network.isEmpty()) {
            stream->network = network == "h2" ? "http" : network;
        }

        if (stream->network == "ws") {
            stream->path = firstNonEmpty({
                jsonString(transport.value("path")),
                jsonString(firstDefinedObject(proxy, {"ws-opts", "ws-opt"}).value("path")),
            });
            stream->host = firstNonEmpty({
                headerHostValue(transport.value("headers")),
                headerHostValue(firstDefinedObject(proxy, {"ws-opts", "ws-opt"}).value("headers")),
                jsonString(proxy.value("host")),
            });
            stream->ws_early_data_length = jsonInt(transport.value("max_early_data"),
                                                   jsonInt(firstDefinedObject(proxy, {"ws-opts", "ws-opt"}).value("max-early-data")));
            stream->ws_early_data_name = firstNonEmpty({
                jsonString(transport.value("early_data_header_name")),
                jsonString(firstDefinedObject(proxy, {"ws-opts", "ws-opt"}).value("early-data-header-name")),
            });
        } else if (stream->network == "http") {
            stream->path = firstNonEmpty({
                jsonString(transport.value("path")),
                jsonString(firstDefinedObject(proxy, {"h2-opts", "h2-opt"}).value("path")),
            });
            stream->host = firstNonEmpty({
                jsonStringList(transport.value("host")).join(","),
                jsonStringList(firstDefinedObject(proxy, {"h2-opts", "h2-opt"}).value("host")).join(","),
                jsonString(proxy.value("host")).replace("|", ","),
            });
        } else if (stream->network == "grpc") {
            stream->path = firstNonEmpty({
                jsonString(transport.value("service_name")),
                jsonString(firstDefinedObject(proxy, {"grpc-opts", "grpc-opt"}).value("grpc-service-name")),
                jsonString(proxy.value("serviceName")),
            });
        } else if (stream->network == "httpupgrade") {
            stream->path = firstNonEmpty({jsonString(transport.value("path")), jsonString(proxy.value("path"))});
            stream->host = firstNonEmpty({jsonString(transport.value("host")), jsonString(proxy.value("host"))});
        } else if (stream->network == "tcp") {
            auto tcpHttp = firstDefinedObject(proxy, {"http-opts", "http-opt"});
            if (!tcpHttp.isEmpty()) {
                stream->header_type = "http";
                stream->path = firstNonEmpty(jsonStringList(tcpHttp.value("path")));
                stream->host = headerHostValue(tcpHttp.value("headers"));
            }
        }

        if (jsonBool(proxy.value("packet-addr"))) {
            stream->packet_encoding = "packetaddr";
        } else if (jsonBool(proxy.value("xudp"))) {
            stream->packet_encoding = "xudp";
        } else if (!jsonString(proxy.value("packet_encoding")).isEmpty()) {
            stream->packet_encoding = jsonString(proxy.value("packet_encoding"));
        }
    }

    void applyMuxSettings(const QJsonObject &proxy, NekoGui_fmt::V2rayStreamSettings *stream) {
        auto multiplex = proxy.value("multiplex").toObject();
        if (jsonBool(multiplex.value("enabled"))) {
            stream->multiplex_status = 1;
            return;
        }
        auto smux = firstDefinedObject(proxy, {"smux"});
        if (jsonBool(smux.value("enabled"))) {
            stream->multiplex_status = 1;
        }
    }

} // namespace

namespace NekoGui_sub {

    GroupUpdater *groupUpdater = new GroupUpdater;

    void RawUpdater_FixEnt(const std::shared_ptr<NekoGui::ProxyEntity> &ent) {
        if (ent == nullptr) return;
        auto stream = NekoGui_fmt::GetStreamSettings(ent->bean.get());
        if (stream == nullptr) return;
        // 1. "security"
        if (stream->security == "none" || stream->security == "0" || stream->security == "false") {
            stream->security = "";
        } else if (stream->security == "1" || stream->security == "true") {
            stream->security = "tls";
        }
        // 2. TLS SNI: v2rayN config builder generate sni like this, so set sni here for their format.
        if (stream->security == "tls" && IsIpAddress(ent->bean->serverAddress) && (!stream->host.isEmpty()) && stream->sni.isEmpty()) {
            stream->sni = stream->host;
        }
    }

    namespace {
        void appendParsedEntity(NekoGui_sub::RawUpdater *rawUpdater, const std::shared_ptr<NekoGui::ProxyEntity> &ent, bool needFix) {
            if (ent == nullptr) return;
            if (needFix) NekoGui_sub::RawUpdater_FixEnt(ent);
            NekoGui::profileManager->AddProfile(ent, rawUpdater->gid_add_to);
            rawUpdater->updated_order += ent;
        }

        std::shared_ptr<NekoGui::ProxyEntity> parseJsonProxyObject(const QJsonObject &proxy) {
            auto type = jsonString(proxy.value("type")).trimmed().toLower();
            if (type == "ss" || type == "ssr") type = "shadowsocks";
            if (type == "socks5") type = "socks";
            if (type == "mixed" || type == "direct" || type == "block" || type == "dns") return nullptr;
            if (type.isEmpty()) {
                if (proxy.contains("method") || proxy.contains("cipher")) {
                    type = "shadowsocks";
                } else {
                    return nullptr;
                }
            }

            auto ent = NekoGui::ProfileManager::NewProxyEntity(type);
            if (ent->bean == nullptr || ent->bean->version == -114514) return nullptr;
            copyJsonCommonFields(ent, proxy);

            if (type == "shadowsocks") {
                auto bean = ent->ShadowSocksBean();
                bean->method = firstNonEmpty({jsonString(proxy.value("method")), jsonString(proxy.value("cipher")), bean->method});
                bean->password = jsonString(proxy.value("password"));
                if (!jsonString(proxy.value("plugin")).isEmpty() && !jsonString(proxy.value("plugin_opts")).isEmpty()) {
                    bean->plugin = jsonString(proxy.value("plugin")) + ";" + jsonString(proxy.value("plugin_opts"));
                } else {
                    bean->plugin = jsonString(proxy.value("plugin"));
                }
                auto udpOverTcp = proxy.value("udp_over_tcp");
                if (udpOverTcp.isObject() && jsonBool(udpOverTcp.toObject().value("enabled"))) {
                    bean->uot = jsonInt(udpOverTcp.toObject().value("version"), 1);
                } else if (jsonBool(proxy.value("udp-over-tcp"))) {
                    bean->uot = jsonInt(proxy.value("udp-over-tcp-version"), 1);
                }
            } else if (type == "socks" || type == "http") {
                auto bean = ent->SocksHTTPBean();
                bean->username = jsonString(proxy.value("username"));
                bean->password = jsonString(proxy.value("password"));
            } else if (type == "vmess") {
                auto bean = ent->VMessBean();
                bean->uuid = firstNonEmpty({jsonString(proxy.value("uuid")), jsonString(proxy.value("id"))});
                bean->aid = jsonInt(proxy.value("alter_id"), jsonInt(proxy.value("alterId")));
                bean->security = firstNonEmpty({jsonString(proxy.value("security")), jsonString(proxy.value("cipher")), bean->security});
                applyTransportSettings(proxy, bean->stream.get());
                applyTlsSettings(proxy, bean->stream.get());
                applyMuxSettings(proxy, bean->stream.get());
                return ent;
            } else if (type == "trojan" || type == "vless") {
                auto bean = ent->TrojanVLESSBean();
                if (type == "vless") {
                    bean->password = firstNonEmpty({jsonString(proxy.value("uuid")), jsonString(proxy.value("id"))});
                    bean->flow = jsonString(proxy.value("flow"));
                } else {
                    bean->password = jsonString(proxy.value("password"));
                }
                applyTransportSettings(proxy, bean->stream.get());
                applyTlsSettings(proxy, bean->stream.get());
                if (type == "trojan" && bean->stream->security.isEmpty()) bean->stream->security = "tls";
                applyMuxSettings(proxy, bean->stream.get());
                return ent;
            } else if (type == "hysteria2") {
                auto bean = ent->QUICBean();
                bean->password = jsonString(proxy.value("password"));
                bean->obfsPassword = firstNonEmpty({
                    jsonString(proxy.value("obfs-password")),
                    jsonString(proxy.value("obfs").toObject().value("password")),
                });
                bean->uploadMbps = jsonInt(proxy.value("up_mbps"), jsonString(proxy.value("up")).split(" ").value(0).toInt());
                bean->downloadMbps = jsonInt(proxy.value("down_mbps"), jsonString(proxy.value("down")).split(" ").value(0).toInt());
                bean->hopPort = firstNonEmpty({jsonString(proxy.value("hop_ports")), jsonString(proxy.value("ports"))});
                bean->hopInterval = jsonInt(proxy.value("hop_interval"), bean->hopInterval);
                bean->allowInsecure = jsonBool(proxy.value("skip-cert-verify"));
                auto tls = proxy.value("tls").toObject();
                bean->allowInsecure = bean->allowInsecure || jsonBool(tls.value("insecure"));
                bean->sni = firstNonEmpty({jsonString(tls.value("server_name")), jsonString(proxy.value("sni"))});
                bean->alpn = jsonStringList(tls.value("alpn")).join(",");
                bean->caText = jsonString(tls.value("certificate"));
                return ent;
            } else if (type == "tuic") {
                auto bean = ent->QUICBean();
                bean->uuid = jsonString(proxy.value("uuid"));
                bean->password = jsonString(proxy.value("password"));
                bean->congestionControl = firstNonEmpty({jsonString(proxy.value("congestion_control")), jsonString(proxy.value("congestion-controller")), bean->congestionControl});
                bean->udpRelayMode = firstNonEmpty({jsonString(proxy.value("udp_relay_mode")), jsonString(proxy.value("udp-relay-mode")), bean->udpRelayMode});
                bean->zeroRttHandshake = jsonBool(proxy.value("zero_rtt_handshake")) || jsonBool(proxy.value("reduce-rtt"));
                bean->heartbeat = firstNonEmpty({jsonString(proxy.value("heartbeat")), bean->heartbeat});
                bean->uos = jsonBool(proxy.value("udp_over_stream"));
                auto tls = proxy.value("tls").toObject();
                bean->allowInsecure = jsonBool(proxy.value("skip-cert-verify")) || jsonBool(tls.value("insecure"));
                bean->disableSni = jsonBool(tls.value("disable_sni")) || jsonBool(proxy.value("disable-sni"));
                bean->sni = firstNonEmpty({jsonString(tls.value("server_name")), jsonString(proxy.value("sni"))});
                bean->alpn = jsonStringList(tls.value("alpn")).join(",");
                bean->caText = jsonString(tls.value("certificate"));
                return ent;
            } else {
                return nullptr;
            }

            if (auto stream = NekoGui_fmt::GetStreamSettings(ent->bean.get()); stream != nullptr) {
                applyTransportSettings(proxy, stream);
                applyTlsSettings(proxy, stream);
                applyMuxSettings(proxy, stream);
            }
            return ent;
        }

        bool looksLikeImportPayload(const QString &value) {
            auto trimmed = value.trimmed();
            return trimmed.startsWith("{") || trimmed.startsWith("[") || trimmed.contains('\n') || trimmed.contains("://") || trimmed.contains("proxies:");
        }

        bool updateFromJsonValue(NekoGui_sub::RawUpdater *rawUpdater, const QJsonValue &value, int depth) {
            if (depth > 8) return false;

            if (value.isString()) {
                const auto payload = value.toString().trimmed();
                if (!looksLikeImportPayload(payload)) return false;
                rawUpdater->update(payload);
                return true;
            }

            if (value.isArray()) {
                bool handled = false;
                for (const auto &item: value.toArray()) {
                    handled = updateFromJsonValue(rawUpdater, item, depth + 1) || handled;
                }
                return handled;
            }

            if (!value.isObject()) return false;
            const auto object = value.toObject();

            bool handled = false;
            for (const auto &key: QStringList{"links", "uris", "urls", "data", "servers", "proxies", "outbounds", "nodes"}) {
                if (object.contains(key)) {
                    handled = updateFromJsonValue(rawUpdater, object.value(key), depth + 1) || handled;
                }
            }
            for (const auto &key: QStringList{"uri", "url", "link"}) {
                auto payload = jsonString(object.value(key)).trimmed();
                if (looksLikeImportPayload(payload)) {
                    rawUpdater->update(payload);
                    handled = true;
                }
            }
            if (handled) return true;

            auto ent = parseJsonProxyObject(object);
            if (ent == nullptr) return false;
            appendParsedEntity(rawUpdater, ent, true);
            return true;
        }
    } // namespace

    void RawUpdater::update(const QString &str) {
        // Base64 encoded subscription
        if (auto str2 = DecodeB64IfValid(str); !str2.isEmpty()) {
            update(str2);
            return;
        }

        QJsonParseError jsonError;
        auto jsonDocument = QJsonDocument::fromJson(str.toUtf8(), &jsonError);
        if (jsonError.error == QJsonParseError::NoError && !jsonDocument.isNull()) {
            auto jsonValue = jsonDocument.isArray() ? QJsonValue(jsonDocument.array()) : QJsonValue(jsonDocument.object());
            if (updateFromJsonValue(this, jsonValue, 0)) {
                return;
            }
        }

        // Clash
        if (str.contains("proxies:")) {
            updateClash(str);
            return;
        }

        // Multi line
        if (str.count("\n") > 0) {
            auto list = str.split("\n");
            for (const auto &str2: list) {
                update(str2.trimmed());
            }
            return;
        }

        std::shared_ptr<NekoGui::ProxyEntity> ent;
        bool needFix = true;

        // Nekoray format
        if (str.startsWith("nekoray://")) {
            needFix = false;
            auto link = QUrl(str);
            if (!link.isValid()) return;
            ent = NekoGui::ProfileManager::NewProxyEntity(link.host());
            if (ent->bean->version == -114514) return;
            auto j = DecodeB64IfValid(link.fragment().toUtf8(), QByteArray::Base64UrlEncoding);
            if (j.isEmpty()) return;
            ent->bean->FromJsonBytes(j);
        }

        // SOCKS
        if (str.startsWith("socks5://") || str.startsWith("socks4://") ||
            str.startsWith("socks4a://") || str.startsWith("socks://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("socks");
            auto ok = ent->SocksHTTPBean()->TryParseLink(str);
            if (!ok) return;
        }

        // HTTP
        if (str.startsWith("http://") || str.startsWith("https://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("http");
            auto ok = ent->SocksHTTPBean()->TryParseLink(str);
            if (!ok) return;
        }

        // ShadowSocks
        if (str.startsWith("ss://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("shadowsocks");
            auto ok = ent->ShadowSocksBean()->TryParseLink(str);
            if (!ok) return;
        }

        // VMess
        if (str.startsWith("vmess://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("vmess");
            auto ok = ent->VMessBean()->TryParseLink(str);
            if (!ok) return;
        }

        // VLESS
        if (str.startsWith("vless://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("vless");
            auto ok = ent->TrojanVLESSBean()->TryParseLink(str);
            if (!ok) return;
        }

        // Trojan
        if (str.startsWith("trojan://")) {
            ent = NekoGui::ProfileManager::NewProxyEntity("trojan");
            auto ok = ent->TrojanVLESSBean()->TryParseLink(str);
            if (!ok) return;
        }

        // Naive
        if (str.startsWith("naive+")) {
            needFix = false;
            ent = NekoGui::ProfileManager::NewProxyEntity("naive");
            auto ok = ent->NaiveBean()->TryParseLink(str);
            if (!ok) return;
        }

        // Hysteria2
        if (str.startsWith("hysteria2://") || str.startsWith("hy2://")) {
            needFix = false;
            ent = NekoGui::ProfileManager::NewProxyEntity("hysteria2");
            auto ok = ent->QUICBean()->TryParseLink(str);
            if (!ok) return;
        }

        // TUIC
        if (str.startsWith("tuic://")) {
            needFix = false;
            ent = NekoGui::ProfileManager::NewProxyEntity("tuic");
            auto ok = ent->QUICBean()->TryParseLink(str);
            if (!ok) return;
        }

        if (ent == nullptr) return;

        // Fix
        if (needFix) RawUpdater_FixEnt(ent);

        // End
        NekoGui::profileManager->AddProfile(ent, gid_add_to);
        updated_order += ent;
    }

#ifndef NKR_NO_YAML

    QString Node2QString(const YAML::Node &n, const QString &def = "") {
        try {
            return n.as<std::string>().c_str();
        } catch (const YAML::Exception &ex) {
            qDebug() << ex.what();
            return def;
        }
    }

    QStringList Node2QStringList(const YAML::Node &n) {
        try {
            if (n.IsSequence()) {
                QStringList list;
                for (auto item: n) {
                    list << item.as<std::string>().c_str();
                }
                return list;
            } else {
                return {};
            }
        } catch (const YAML::Exception &ex) {
            qDebug() << ex.what();
            return {};
        }
    }

    int Node2Int(const YAML::Node &n, const int &def = 0) {
        try {
            return n.as<int>();
        } catch (const YAML::Exception &ex) {
            qDebug() << ex.what();
            return def;
        }
    }

    bool Node2Bool(const YAML::Node &n, const bool &def = false) {
        try {
            return n.as<bool>();
        } catch (const YAML::Exception &ex) {
            try {
                return n.as<int>();
            } catch (const YAML::Exception &ex2) {
                qDebug() << ex2.what();
            }
            qDebug() << ex.what();
            return def;
        }
    }

    // NodeChild returns the first defined children or Null Node
    YAML::Node NodeChild(const YAML::Node &n, const std::list<std::string> &keys) {
        for (const auto &key: keys) {
            auto child = n[key];
            if (child.IsDefined()) return child;
        }
        return {};
    }

#endif

    // https://github.com/Dreamacro/clash/wiki/configuration
    void RawUpdater::updateClash(const QString &str) {
#ifndef NKR_NO_YAML
        try {
            auto proxies = YAML::Load(str.toStdString())["proxies"];
            for (auto proxy: proxies) {
                auto type = Node2QString(proxy["type"]).toLower();
                auto type_clash = type;

                if (type == "ss" || type == "ssr") type = "shadowsocks";
                if (type == "socks5") type = "socks";

                auto ent = NekoGui::ProfileManager::NewProxyEntity(type);
                if (ent->bean->version == -114514) continue;
                bool needFix = false;

                // common
                ent->bean->name = Node2QString(proxy["name"]);
                ent->bean->serverAddress = Node2QString(proxy["server"]);
                ent->bean->serverPort = Node2Int(proxy["port"]);

                if (type_clash == "ss") {
                    auto bean = ent->ShadowSocksBean();
                    bean->method = Node2QString(proxy["cipher"]).replace("dummy", "none");
                    bean->password = Node2QString(proxy["password"]);
                    auto plugin_n = proxy["plugin"];
                    auto pluginOpts_n = proxy["plugin-opts"];

                    // UDP over TCP
                    if (Node2Bool(proxy["udp-over-tcp"])) {
                        bean->uot = Node2Int(proxy["udp-over-tcp-version"]);
                        if (bean->uot == 0) bean->uot = 2;
                    }

                    if (plugin_n.IsDefined() && pluginOpts_n.IsDefined()) {
                        QStringList ssPlugin;
                        auto plugin = Node2QString(plugin_n);
                        if (plugin == "obfs") {
                            ssPlugin << "obfs-local";
                            ssPlugin << "obfs=" + Node2QString(pluginOpts_n["mode"]);
                            ssPlugin << "obfs-host=" + Node2QString(pluginOpts_n["host"]);
                        } else if (plugin == "v2ray-plugin") {
                            auto mode = Node2QString(pluginOpts_n["mode"]);
                            auto host = Node2QString(pluginOpts_n["host"]);
                            auto path = Node2QString(pluginOpts_n["path"]);
                            ssPlugin << "v2ray-plugin";
                            if (!mode.isEmpty() && mode != "websocket") ssPlugin << "mode=" + mode;
                            if (Node2Bool(pluginOpts_n["tls"])) ssPlugin << "tls";
                            if (!host.isEmpty()) ssPlugin << "host=" + host;
                            if (!path.isEmpty()) ssPlugin << "path=" + path;
                            // clash only: skip-cert-verify
                            // clash only: headers
                            // clash: mux=?
                        }
                        bean->plugin = ssPlugin.join(";");
                    }

                    // sing-mux
                    auto smux = NodeChild(proxy, {"smux"});
                    if (Node2Bool(smux["enabled"])) bean->stream->multiplex_status = 1;
                } else if (type == "socks" || type == "http") {
                    auto bean = ent->SocksHTTPBean();
                    bean->username = Node2QString(proxy["username"]);
                    bean->password = Node2QString(proxy["password"]);
                    if (Node2Bool(proxy["tls"])) bean->stream->security = "tls";
                    if (Node2Bool(proxy["skip-cert-verify"])) bean->stream->allow_insecure = true;
                } else if (type == "trojan" || type == "vless") {
                    needFix = true;
                    auto bean = ent->TrojanVLESSBean();
                    if (type == "vless") {
                        bean->flow = Node2QString(proxy["flow"]);
                        bean->password = Node2QString(proxy["uuid"]);
                        // meta packet encoding
                        if (Node2Bool(proxy["packet-addr"])) {
                            bean->stream->packet_encoding = "packetaddr";
                        } else {
                            // For VLESS, default to use xudp
                            bean->stream->packet_encoding = "xudp";
                        }
                    } else {
                        bean->password = Node2QString(proxy["password"]);
                    }
                    bean->stream->security = "tls";
                    bean->stream->network = Node2QString(proxy["network"], "tcp");
                    bean->stream->sni = FIRST_OR_SECOND(Node2QString(proxy["sni"]), Node2QString(proxy["servername"]));
                    bean->stream->alpn = Node2QStringList(proxy["alpn"]).join(",");
                    bean->stream->allow_insecure = Node2Bool(proxy["skip-cert-verify"]);
                    bean->stream->utlsFingerprint = Node2QString(proxy["client-fingerprint"]);
                    if (bean->stream->utlsFingerprint.isEmpty()) {
                        bean->stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
                    }

                    // sing-mux
                    auto smux = NodeChild(proxy, {"smux"});
                    if (Node2Bool(smux["enabled"])) bean->stream->multiplex_status = 1;

                    // opts
                    auto ws = NodeChild(proxy, {"ws-opts", "ws-opt"});
                    if (ws.IsMap()) {
                        auto headers = ws["headers"];
                        for (auto header: headers) {
                            if (Node2QString(header.first).toLower() == "host") {
                                bean->stream->host = Node2QString(header.second);
                            }
                        }
                        bean->stream->path = Node2QString(ws["path"]);
                        bean->stream->ws_early_data_length = Node2Int(ws["max-early-data"]);
                        bean->stream->ws_early_data_name = Node2QString(ws["early-data-header-name"]);
                    }

                    auto grpc = NodeChild(proxy, {"grpc-opts", "grpc-opt"});
                    if (grpc.IsMap()) {
                        bean->stream->path = Node2QString(grpc["grpc-service-name"]);
                    }

                    auto reality = NodeChild(proxy, {"reality-opts"});
                    if (reality.IsMap()) {
                        bean->stream->reality_pbk = Node2QString(reality["public-key"]);
                        bean->stream->reality_sid = Node2QString(reality["short-id"]);
                    }
                } else if (type == "vmess") {
                    needFix = true;
                    auto bean = ent->VMessBean();
                    bean->uuid = Node2QString(proxy["uuid"]);
                    bean->aid = Node2Int(proxy["alterId"]);
                    bean->security = Node2QString(proxy["cipher"], bean->security);
                    bean->stream->network = Node2QString(proxy["network"], "tcp").replace("h2", "http");
                    bean->stream->sni = FIRST_OR_SECOND(Node2QString(proxy["sni"]), Node2QString(proxy["servername"]));
                    bean->stream->alpn = Node2QStringList(proxy["alpn"]).join(",");
                    if (Node2Bool(proxy["tls"])) bean->stream->security = "tls";
                    if (Node2Bool(proxy["skip-cert-verify"])) bean->stream->allow_insecure = true;
                    bean->stream->utlsFingerprint = Node2QString(proxy["client-fingerprint"]);
                    bean->stream->utlsFingerprint = Node2QString(proxy["client-fingerprint"]);
                    if (bean->stream->utlsFingerprint.isEmpty()) {
                        bean->stream->utlsFingerprint = NekoGui::dataStore->utlsFingerprint;
                    }

                    // sing-mux
                    auto smux = NodeChild(proxy, {"smux"});
                    if (Node2Bool(smux["enabled"])) bean->stream->multiplex_status = 1;

                    // meta packet encoding
                    if (Node2Bool(proxy["xudp"])) bean->stream->packet_encoding = "xudp";
                    if (Node2Bool(proxy["packet-addr"])) bean->stream->packet_encoding = "packetaddr";

                    // opts
                    auto ws = NodeChild(proxy, {"ws-opts", "ws-opt"});
                    if (ws.IsMap()) {
                        auto headers = ws["headers"];
                        for (auto header: headers) {
                            if (Node2QString(header.first).toLower() == "host") {
                                bean->stream->host = Node2QString(header.second);
                            }
                        }
                        bean->stream->path = Node2QString(ws["path"]);
                        bean->stream->ws_early_data_length = Node2Int(ws["max-early-data"]);
                        bean->stream->ws_early_data_name = Node2QString(ws["early-data-header-name"]);
                        // for Xray
                        if (Node2QString(ws["early-data-header-name"]) == "Sec-WebSocket-Protocol") {
                            bean->stream->path += "?ed=" + Node2QString(ws["max-early-data"]);
                        }
                    }

                    auto grpc = NodeChild(proxy, {"grpc-opts", "grpc-opt"});
                    if (grpc.IsMap()) {
                        bean->stream->path = Node2QString(grpc["grpc-service-name"]);
                    }

                    auto h2 = NodeChild(proxy, {"h2-opts", "h2-opt"});
                    if (h2.IsMap()) {
                        auto hosts = h2["host"];
                        for (auto host: hosts) {
                            bean->stream->host = Node2QString(host);
                            break;
                        }
                        bean->stream->path = Node2QString(h2["path"]);
                    }

                    auto tcp_http = NodeChild(proxy, {"http-opts", "http-opt"});
                    if (tcp_http.IsMap()) {
                        bean->stream->network = "tcp";
                        bean->stream->header_type = "http";
                        auto headers = tcp_http["headers"];
                        for (auto header: headers) {
                            if (Node2QString(header.first).toLower() == "host") {
                                bean->stream->host = Node2QString(header.second[0]);
                            }
                            break;
                        }
                        auto paths = tcp_http["path"];
                        for (auto path: paths) {
                            bean->stream->path = Node2QString(path);
                            break;
                        }
                    }
                } else if (type == "hysteria2") {
                    auto bean = ent->QUICBean();

                    bean->hopPort = Node2QString(proxy["ports"]);

                    bean->allowInsecure = Node2Bool(proxy["skip-cert-verify"]);
                    bean->caText = Node2QString(proxy["ca-str"]);
                    bean->sni = Node2QString(proxy["sni"]);

                    bean->obfsPassword = Node2QString(proxy["obfs-password"]);
                    bean->password = Node2QString(proxy["password"]);

                    bean->uploadMbps = Node2QString(proxy["up"]).split(" ")[0].toInt();
                    bean->downloadMbps = Node2QString(proxy["down"]).split(" ")[0].toInt();
                } else if (type == "tuic") {
                    auto bean = ent->QUICBean();

                    bean->uuid = Node2QString(proxy["uuid"]);
                    bean->password = Node2QString(proxy["password"]);

                    if (Node2Int(proxy["heartbeat-interval"]) != 0) {
                        bean->heartbeat = Int2String(Node2Int(proxy["heartbeat-interval"])) + "ms";
                    }

                    bean->udpRelayMode = Node2QString(proxy["udp-relay-mode"], bean->udpRelayMode);
                    bean->congestionControl = Node2QString(proxy["congestion-controller"], bean->congestionControl);

                    bean->disableSni = Node2Bool(proxy["disable-sni"]);
                    bean->zeroRttHandshake = Node2Bool(proxy["reduce-rtt"]);
                    bean->allowInsecure = Node2Bool(proxy["skip-cert-verify"]);
                    bean->alpn = Node2QStringList(proxy["alpn"]).join(",");
                    bean->caText = Node2QString(proxy["ca-str"]);
                    bean->sni = Node2QString(proxy["sni"]);

                    if (Node2Bool(proxy["udp-over-stream"])) bean->uos = true;

                    if (!Node2QString(proxy["ip"]).isEmpty()) {
                        if (bean->sni.isEmpty()) bean->sni = bean->serverAddress;
                        bean->serverAddress = Node2QString(proxy["ip"]);
                    }
                } else {
                    continue;
                }

                if (needFix) RawUpdater_FixEnt(ent);
                NekoGui::profileManager->AddProfile(ent, gid_add_to);
                updated_order += ent;
            }
        } catch (const YAML::Exception &ex) {
            runOnUiThread([=] {
                MessageBoxWarning("YAML Exception", ex.what());
            });
        }
#endif
    }

    // 在新的 thread 运行
    void GroupUpdater::AsyncUpdate(const QString &str, int _sub_gid, const std::function<void()> &finish) {
        auto content = str.trimmed();
        bool asURL = false;
        bool createNewGroup = false;

        if (_sub_gid < 0 && (content.startsWith("http://") || content.startsWith("https://"))) {
            auto items = QStringList{
                QObject::tr("As Subscription (add to this group)"),
                QObject::tr("As Subscription (create new group)"),
                QObject::tr("As link"),
            };
            bool ok;
            auto a = QInputDialog::getItem(nullptr,
                                           QObject::tr("url detected"),
                                           QObject::tr("%1\nHow to update?").arg(content),
                                           items, 0, false, &ok);
            if (!ok) return;
            if (items.indexOf(a) <= 1) asURL = true;
            if (items.indexOf(a) == 1) createNewGroup = true;
        }

        runOnNewThread([=] {
            auto gid = _sub_gid;
            if (createNewGroup) {
                auto group = NekoGui::ProfileManager::NewGroup();
                group->name = NetworkRequestHelper::GetSubscriptionHost(str);
                group->url = str;
                NekoGui::profileManager->AddGroup(group);
                gid = group->id;
                MW_dialog_message("SubUpdater", "NewGroup");
            }
            Update(str, gid, asURL);
            emit asyncUpdateCallback(gid);
            if (finish != nullptr) finish();
        });
    }

    void GroupUpdater::Update(const QString &_str, int _sub_gid, bool _not_sub_as_url) {
        // 创建 rawUpdater
        NekoGui::dataStore->imported_count = 0;
        auto rawUpdater = std::make_unique<RawUpdater>();
        rawUpdater->gid_add_to = _sub_gid;

        // 准备
        QString sub_user_info;
        bool asURL = _sub_gid >= 0 || _not_sub_as_url; // 把 _str 当作 url 处理（下载内容）
        auto content = _str.trimmed();
        auto group = NekoGui::profileManager->GetGroup(_sub_gid);
        if (group != nullptr && group->archive) return;

        // 网络请求
        if (asURL) {
            auto groupName = group == nullptr ? content : group->name;
            MW_show_log(">>>>>>>> " + QObject::tr("Requesting subscription: %1").arg(groupName));

            auto resp = NetworkRequestHelper::HttpGet(content);
            if (!resp.error.isEmpty()) {
                MW_show_log("<<<<<<<< " + QObject::tr("Requesting subscription %1 error: %2").arg(groupName, resp.error + "\n" + resp.data));
                return;
            }

            content = resp.data;
            sub_user_info = NetworkRequestHelper::GetHeader(resp.header, "Subscription-UserInfo");

            MW_show_log("<<<<<<<< " + QObject::tr("Subscription request fininshed: %1").arg(groupName));
        }

        QList<std::shared_ptr<NekoGui::ProxyEntity>> in;          // 更新前
        QList<std::shared_ptr<NekoGui::ProxyEntity>> out_all;     // 更新前 + 更新后
        QList<std::shared_ptr<NekoGui::ProxyEntity>> out;         // 更新后
        QList<std::shared_ptr<NekoGui::ProxyEntity>> only_in;     // 只在更新前有的
        QList<std::shared_ptr<NekoGui::ProxyEntity>> only_out;    // 只在更新后有的
        QList<std::shared_ptr<NekoGui::ProxyEntity>> update_del;  // 更新前后都有的，需要删除的新配置
        QList<std::shared_ptr<NekoGui::ProxyEntity>> update_keep; // 更新前后都有的，被保留的旧配置

        // 订阅解析前
        if (group != nullptr) {
            in = group->Profiles();
            group->sub_last_update = QDateTime::currentMSecsSinceEpoch() / 1000;
            group->info = sub_user_info;
            group->order.clear();
            group->Save();
            //
            if (NekoGui::dataStore->sub_clear) {
                MW_show_log(QObject::tr("Clearing servers..."));
                for (const auto &profile: in) {
                    NekoGui::profileManager->DeleteProfile(profile->id);
                }
            }
        }

        // 解析并添加 profile
        rawUpdater->update(content);

        if (group != nullptr) {
            out_all = group->Profiles();

            QString change_text;

            if (NekoGui::dataStore->sub_clear) {
                // all is new profile
                for (const auto &ent: out_all) {
                    change_text += "[+] " + ent->bean->DisplayTypeAndName() + "\n";
                }
            } else {
                // find and delete not updated profile by ProfileFilter
                NekoGui::ProfileFilter::OnlyInSrc_ByPointer(out_all, in, out);
                NekoGui::ProfileFilter::OnlyInSrc(in, out, only_in);
                NekoGui::ProfileFilter::OnlyInSrc(out, in, only_out);
                NekoGui::ProfileFilter::Common(in, out, update_keep, update_del, false);

                QString notice_added;
                QString notice_deleted;
                for (const auto &ent: only_out) {
                    notice_added += "[+] " + ent->bean->DisplayTypeAndName() + "\n";
                }
                for (const auto &ent: only_in) {
                    notice_deleted += "[-] " + ent->bean->DisplayTypeAndName() + "\n";
                }

                // sort according to order in remote
                group->order = {};
                for (const auto &ent: rawUpdater->updated_order) {
                    auto deleted_index = update_del.indexOf(ent);
                    if (deleted_index > 0) {
                        if (deleted_index >= update_keep.count()) continue; // should not happen
                        auto ent2 = update_keep[deleted_index];
                        group->order.append(ent2->id);
                    } else {
                        group->order.append(ent->id);
                    }
                }
                group->Save();

                // cleanup
                for (const auto &ent: out_all) {
                    if (!group->order.contains(ent->id)) {
                        NekoGui::profileManager->DeleteProfile(ent->id);
                    }
                }

                change_text = "\n" + QObject::tr("Added %1 profiles:\n%2\nDeleted %3 Profiles:\n%4")
                                         .arg(only_out.length())
                                         .arg(notice_added)
                                         .arg(only_in.length())
                                         .arg(notice_deleted);
                if (only_out.length() + only_in.length() == 0) change_text = QObject::tr("Nothing");
            }

            MW_show_log("<<<<<<<< " + QObject::tr("Change of %1:").arg(group->name) + "\n" + change_text);
            MW_dialog_message("SubUpdater", "finish-dingyue");
        } else {
            NekoGui::dataStore->imported_count = rawUpdater->updated_order.count();
            MW_dialog_message("SubUpdater", "finish");
        }
    }
} // namespace NekoGui_sub

bool UI_update_all_groups_Updating = false;

#define should_skip_group(g) (g == nullptr || g->url.isEmpty() || g->archive || (onlyAllowed && g->skip_auto_update))

void serialUpdateSubscription(const QList<int> &groupsTabOrder, int _order, bool onlyAllowed) {
    if (_order >= groupsTabOrder.size()) {
        UI_update_all_groups_Updating = false;
        return;
    }

    // calculate this group
    auto group = NekoGui::profileManager->GetGroup(groupsTabOrder[_order]);
    if (group == nullptr || should_skip_group(group)) {
        serialUpdateSubscription(groupsTabOrder, _order + 1, onlyAllowed);
        return;
    }

    int nextOrder = _order + 1;
    while (nextOrder < groupsTabOrder.size()) {
        auto nextGid = groupsTabOrder[nextOrder];
        auto nextGroup = NekoGui::profileManager->GetGroup(nextGid);
        if (!should_skip_group(nextGroup)) {
            break;
        }
        nextOrder += 1;
    }

    // Async update current group
    UI_update_all_groups_Updating = true;
    NekoGui_sub::groupUpdater->AsyncUpdate(group->url, group->id, [=] {
        serialUpdateSubscription(groupsTabOrder, nextOrder, onlyAllowed);
    });
}

void UI_update_all_groups(bool onlyAllowed) {
    if (UI_update_all_groups_Updating) {
        MW_show_log("The last subscription update has not exited.");
        return;
    }

    auto groupsTabOrder = NekoGui::profileManager->groupsTabOrder;
    serialUpdateSubscription(groupsTabOrder, 0, onlyAllowed);
}
