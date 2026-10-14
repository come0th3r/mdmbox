#include "InstallationIdentity.hpp"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QSaveFile>
#include <QUuid>

namespace NekoGui_sub {
    bool InstallationIdentity::loadOrCreate(const QString &directory, QString &identity, QString &error) {
        error.clear();
        if (directory.isEmpty() || !QDir().mkpath(directory)) {
            error = QStringLiteral("Installation identity directory unavailable");
            return false;
        }
        const auto path = QDir(directory).filePath("installation-identity.json");
        QLockFile lock(path + ".lock");
        if (!lock.tryLock(0)) {
            error = QStringLiteral("Installation identity is in use");
            return false;
        }
        if (QFile::exists(path)) {
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly) || file.size() > 1024) {
                error = QStringLiteral("Installation identity unavailable");
                return false;
            }
            QJsonParseError parseError;
            const auto object = QJsonDocument::fromJson(file.read(1025), &parseError).object();
            const auto candidate = object.value("id").toString();
            const QUuid uuid(candidate);
            if (parseError.error != QJsonParseError::NoError || object.value("schema").toInt(-1) != 1 ||
                uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != candidate) {
                error = QStringLiteral("Invalid installation identity; explicit recovery required");
                return false;
            }
            identity = candidate;
            return true;
        }
        const auto candidate = QUuid::createUuid().toString(QUuid::WithoutBraces);
        const auto bytes = QJsonDocument(QJsonObject{{"schema", 1}, {"id", candidate}}).toJson(QJsonDocument::Compact);
        QSaveFile file(path);
        file.setDirectWriteFallback(false);
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
            error = QStringLiteral("Installation identity could not be saved");
            return false;
        }
        identity = candidate;
        return true;
    }
}
