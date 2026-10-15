#pragma once

#include <QJsonObject>
#include <QJsonValue>
#include <cmath>
#include <limits>

namespace NekoGui_sub {
    struct ManagedCommandContract {
        static bool groupId(const QJsonValue &value, int &id) {
            if (!value.isDouble()) return false;
            const double number = value.toDouble();
            if (!std::isfinite(number) || number < 0 ||
                number > std::numeric_limits<int>::max() || std::floor(number) != number) return false;
            id = static_cast<int>(number);
            return true;
        }
        static QJsonObject result(const QString &command, bool accepted,
                                  const QString &error, const QJsonObject &runtime) {
            return {{QStringLiteral("schemaVersion"), 1},
                    {QStringLiteral("command"), command},
                    {QStringLiteral("accepted"), accepted},
                    {QStringLiteral("queued"), accepted},
                    {QStringLiteral("error"), error},
                    {QStringLiteral("runtime"), runtime}};
        }
    };
}
