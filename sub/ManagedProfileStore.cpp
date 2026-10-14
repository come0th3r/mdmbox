#include "ManagedProfileStore.hpp"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QLockFile>
#include <QSaveFile>
#include <utility>

namespace {
    QList<QPair<QByteArray, QByteArray>> metadataHeaders(const NekoGui_sub::SubscriptionMetadata &m) {
        QList<QPair<QByteArray, QByteArray>> headers;
        QByteArray usage;
        auto counter = [&](const char *key, const auto &value) {
            if (value) usage += QByteArray(key) + "=" + QByteArray::number(*value) + ";";
        };
        counter("upload", m.upload); counter("download", m.download);
        counter("total", m.total); counter("expire", m.expiry);
        if (!usage.isEmpty()) headers.append({"Subscription-Userinfo", usage});
        if (m.updateHours) headers.append({"Profile-Update-Interval", QByteArray::number(*m.updateHours)});
        if (!m.title.isEmpty()) headers.append({"Profile-Title", "base64:" + m.title.toUtf8().toBase64()});
        if (!m.supportUrl.isEmpty()) headers.append({"Support-Url", m.supportUrl.toEncoded()});
        if (!m.pageUrl.isEmpty()) headers.append({"Profile-Web-Page-Url", m.pageUrl.toEncoded()});
        return headers;
    }

    constexpr qint64 MaxEnvelopeBytes = 6 * 1024 * 1024;
    bool read(const QString &path, int groupId, NekoGui_sub::ManagedProfile &profile,
              NekoGui_sub::SubscriptionMetadata &metadata, QString &error) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly) || file.size() > MaxEnvelopeBytes) {
            error = QStringLiteral("Managed profile unavailable or oversized");
            return false;
        }
        QJsonParseError parseError;
        const auto doc = QJsonDocument::fromJson(file.read(MaxEnvelopeBytes + 1), &parseError);
        const auto object = doc.object();
        if (parseError.error != QJsonParseError::NoError || object.value("schema").toInt(-1) != 1 ||
            object.value("groupId").toInt(-1) != groupId || object.value("kind").toString() != "mihomo-full" ||
            !object.value("sourceBase64").isString() || !object.value("sha256").isString()) {
            error = QStringLiteral("Invalid managed profile envelope");
            return false;
        }
        const auto encoded = object.value("sourceBase64").toString().toLatin1();
        const auto source = QByteArray::fromBase64(encoded);
        if (source.toBase64() != encoded) {
            error = QStringLiteral("Invalid managed profile encoding");
            return false;
        }
        NekoGui_sub::ManagedProfile candidate;
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(source, candidate, error)) return false;
        if (candidate.sha256 != object.value("sha256").toString().toLatin1()) {
            error = QStringLiteral("Managed profile checksum mismatch");
            return false;
        }
        QList<QPair<QByteArray, QByteArray>> headers;
        if (object.contains("metadata") && !object.value("metadata").isArray()) {
            error = QStringLiteral("Invalid managed metadata envelope");
            return false;
        }
        for (const auto &entry : object.value("metadata").toArray()) {
            const auto pair = entry.toArray();
            if (pair.size() != 2 || !pair[0].isString() || !pair[1].isString()) {
                error = QStringLiteral("Invalid managed metadata entry");
                return false;
            }
            headers.append({pair[0].toString().toUtf8(), pair[1].toString().toUtf8()});
        }
        NekoGui_sub::SubscriptionMetadata candidateMetadata;
        if (!NekoGui_sub::SubscriptionMetadata::parse(headers, candidateMetadata, error)) return false;
        profile = std::move(candidate);
        metadata = std::move(candidateMetadata);
        return true;
    }

    bool write(const QString &path, const QByteArray &bytes, QString &error) {
        QSaveFile file(path);
        file.setDirectWriteFallback(false);
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
            error = QStringLiteral("Atomic managed profile write failed");
            return false;
        }
        return true;
    }
}

namespace NekoGui_sub {
    ManagedProfileStore::ManagedProfileStore(QString directory) : directory(std::move(directory)) {}

    QString ManagedProfileStore::path(int groupId) const {
        return QDir(directory).filePath(QStringLiteral("%1.json").arg(groupId));
    }

    bool ManagedProfileStore::load(int groupId, ManagedProfile &profile, QString &error) const {
        SubscriptionMetadata metadata;
        return loadSnapshot(groupId, profile, metadata, error);
    }

    bool ManagedProfileStore::loadSnapshot(int groupId, ManagedProfile &profile, SubscriptionMetadata &metadata,
                                          QString &error) const {
        error.clear();
        if (groupId < 0) {
            error = QStringLiteral("Invalid group ID");
            return false;
        }
        return read(path(groupId), groupId, profile, metadata, error);
    }

    bool ManagedProfileStore::commit(int groupId, const QByteArray &source, const Validator &validate, QString &error) {
        return commit(groupId, source, SubscriptionMetadata{}, validate, error);
    }

    bool ManagedProfileStore::loadMetadata(int groupId, SubscriptionMetadata &metadata, QString &error) const {
        ManagedProfile profile;
        return loadSnapshot(groupId, profile, metadata, error);
    }

    bool ManagedProfileStore::commit(int groupId, const QByteArray &source, const SubscriptionMetadata &metadata,
                                     const Validator &validate, QString &error) {
        error.clear();
        SubscriptionMetadata checkedMetadata;
        const auto headers = metadataHeaders(metadata);
        if (!SubscriptionMetadata::parse(headers, checkedMetadata, error)) return false;
        if (groupId < 0 || !validate) {
            error = QStringLiteral("Group ID and core validator are required");
            return false;
        }
        ManagedProfile candidate;
        if (!ManagedProfile::ParseMihomo(source, candidate, error)) return false;
        if (!QDir().mkpath(directory)) {
            error = QStringLiteral("Managed profile directory unavailable");
            return false;
        }
        QLockFile lock(path(groupId) + QStringLiteral(".lock"));
        if (!lock.tryLock(0)) {
            error = QStringLiteral("Managed profile update already in progress");
            return false;
        }
        // Validation is serialized with commit. Callback must be bounded by its adapter.
        if (!validate(candidate, error)) {
            error = QStringLiteral("Core validation rejected managed profile");
            return false;
        }
        error.clear();
        const auto current = path(groupId);
        if (QFile::exists(current)) {
            ManagedProfile previous;
            SubscriptionMetadata previousMetadata;
            if (!read(current, groupId, previous, previousMetadata, error)) return false; // Never overwrite corruption silently.
            QFile file(current);
            if (!file.open(QIODevice::ReadOnly)) {
                error = QStringLiteral("Previous managed snapshot unavailable");
                return false;
            }
            if (!write(current + QStringLiteral(".previous"), file.read(MaxEnvelopeBytes + 1), error)) return false;
        }
        QJsonArray storedMetadata;
        for (const auto &header : headers) storedMetadata.append(QJsonArray{QString::fromUtf8(header.first), QString::fromUtf8(header.second)});
        const QJsonObject envelope{
            {"schema", 1}, {"groupId", groupId}, {"kind", "mihomo-full"},
            {"metadata", storedMetadata},
            {"sourceBase64", QString::fromLatin1(candidate.source.toBase64())},
            {"sha256", QString::fromLatin1(candidate.sha256)}};
        return write(current, QJsonDocument(envelope).toJson(QJsonDocument::Compact), error);
    }
}
