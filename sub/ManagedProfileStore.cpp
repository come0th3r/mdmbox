#include "ManagedProfileStore.hpp"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QSaveFile>
#include <utility>

namespace {
    constexpr qint64 MaxEnvelopeBytes = 6 * 1024 * 1024;
    bool read(const QString &path, int groupId, NekoGui_sub::ManagedProfile &profile, QString &error) {
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
        profile = std::move(candidate);
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
        error.clear();
        if (groupId < 0) {
            error = QStringLiteral("Invalid group ID");
            return false;
        }
        return read(path(groupId), groupId, profile, error);
    }

    bool ManagedProfileStore::commit(int groupId, const QByteArray &source, const Validator &validate, QString &error) {
        error.clear();
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
            if (!read(current, groupId, previous, error)) return false; // Never overwrite corruption silently.
            QFile file(current);
            if (!file.open(QIODevice::ReadOnly)) {
                error = QStringLiteral("Previous managed snapshot unavailable");
                return false;
            }
            if (!write(current + QStringLiteral(".previous"), file.read(MaxEnvelopeBytes + 1), error)) return false;
        }
        const QJsonObject envelope{
            {"schema", 1}, {"groupId", groupId}, {"kind", "mihomo-full"},
            {"sourceBase64", QString::fromLatin1(candidate.source.toBase64())},
            {"sha256", QString::fromLatin1(candidate.sha256)}};
        return write(current, QJsonDocument(envelope).toJson(QJsonDocument::Compact), error);
    }
}
