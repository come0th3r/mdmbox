#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace NekoGui_sub {
    // Detached panel document. Structural acceptance is NOT core validation.
    struct ManagedProfile {
        QByteArray source;
        QByteArray sha256;
        QStringList proxyNames;
        QStringList groupNames;
        QStringList rules;

        static bool ParseMihomo(const QByteArray &source, ManagedProfile &result, QString &error);
    };
}
