#pragma once

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QSaveFile>
#include <QUuid>
#ifdef Q_OS_WIN
#include <qt_windows.h>
#else
#include <sys/stat.h>
#include <dirent.h>
#include <cerrno>
#endif

// Explicit, offline legacy-directory backup primitive. Not called by startup,
// not a restore/migration API. Caller must quiesce ALL writers and choose a
// private backup parent (snapshots contain secrets with inherited Windows ACLs).
namespace NekoGui::LegacyBackup {
enum class Status { Verified, UnsafePath, SourceError, WriteError, SourceChanged, InvalidBackup };
struct Result {
    Status status;
    // Populated only on success; never log this path or raw filesystem errors.
    QString directory;
    [[nodiscard]] bool ok() const { return status == Status::Verified; }
};

namespace Detail {
using Files = QMap<QString, QByteArray>;
inline constexpr qint64 MaxFileBytes = 8 * 1024 * 1024;
inline constexpr qint64 MaxTotalBytes = 64 * 1024 * 1024;
inline constexpr int MaxFiles = 4096;
// At most 255 UTF-16 units per leaf, including JSON escaping overhead.
inline constexpr qint64 MaxManifestBytes = 8 * 1024 * 1024;
inline const QStringList Directories{"groups", "profiles", "routes_box"};

inline bool leaf(const QString &name) {
    if (name.isEmpty() || name.size() > 255 || name == "." || name == ".." || name.endsWith('.') || name.endsWith(' ')) return false;
    for (const auto ch : name) {
        if (ch.unicode() < 32 || QStringLiteral("/\\:\"<>|?*").contains(ch)) return false;
    }
    return true;
}

#ifdef Q_OS_WIN
inline QString nativePath(const QString &path) {
    const auto native = QDir::toNativeSeparators(path);
    return native.startsWith("\\\\") ? QStringLiteral("\\\\?\\UNC\\") + native.mid(2) : QStringLiteral("\\\\?\\") + native;
}
#endif

// Refuse aliases, links and non-regular files. This is validation, not a TOCTOU
// sandbox against a hostile concurrent filesystem mutator.
inline bool plain(const QString &path, bool directory) {
    if (!QDir::isAbsolutePath(path)) return false;
    for (QFileInfo info(QDir::cleanPath(path));;) {
        if (!info.exists() || info.isSymLink()) return false;
        if (info.absoluteFilePath() == QDir::cleanPath(path) &&
            (directory ? !info.isDir() : !info.isFile())) return false;
#ifdef Q_OS_WIN
        const auto native = nativePath(info.absoluteFilePath());
        const auto attributes = GetFileAttributesW(reinterpret_cast<LPCWSTR>(native.utf16()));
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        if (info.isFile()) {
            const auto h = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            BY_HANDLE_FILE_INFORMATION details{};
            const auto ok = GetFileInformationByHandle(h, &details);
            CloseHandle(h);
            if (!ok || details.nNumberOfLinks != 1) return false;
        }
        if (info.canonicalFilePath().compare(info.absoluteFilePath(), Qt::CaseInsensitive) != 0) return false;
#else
        struct stat details{};
        if (::lstat(QFile::encodeName(info.absoluteFilePath()).constData(), &details) != 0 ||
            (!S_ISDIR(details.st_mode) && !S_ISREG(details.st_mode)) ||
            (S_ISREG(details.st_mode) && details.st_nlink != 1)) return false;
        if (info.canonicalFilePath() != info.absoluteFilePath()) return false;
#endif
        const auto parent = info.dir().absolutePath();
        if (parent == info.absoluteFilePath()) break;
        info.setFile(parent);
    }
    return true;
}

inline bool read(const QString &path, QByteArray &bytes, qint64 limit = MaxFileBytes) {
    if (!plain(path, false)) return false;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > limit) return false;
    bytes = file.read(limit + 1);
    return bytes.size() <= limit && file.error() == QFileDevice::NoError && file.atEnd();
}

// An unreadable directory must NEVER be confused with an empty directory.
inline bool names(const QString &directory, QStringList &result) {
    result.clear();
    if (!plain(directory, true)) return false;
#ifdef Q_OS_WIN
    const auto native = nativePath(directory);
    const auto access = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (access == INVALID_HANDLE_VALUE) return false;
    CloseHandle(access);
    WIN32_FIND_DATAW entry{};
    const auto pattern = native + QStringLiteral("\\*");
    const auto handle = FindFirstFileW(reinterpret_cast<LPCWSTR>(pattern.utf16()), &entry);
    if (handle == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    bool ok = true;
    for (;;) {
        const auto name = QString::fromWCharArray(entry.cFileName);
        if (name != "." && name != "..") result.append(name);
        if (result.size() > MaxFiles) { ok = false; break; }
        if (!FindNextFileW(handle, &entry)) { ok = GetLastError() == ERROR_NO_MORE_FILES; break; }
    }
    if (!FindClose(handle)) ok = false;
#else
    const auto handle = ::opendir(QFile::encodeName(directory).constData());
    if (!handle) return false;
    bool ok = true;
    for (;;) {
        errno = 0;
        const auto entry = ::readdir(handle);
        if (!entry) { ok = errno == 0; break; }
        const auto name = QFile::decodeName(entry->d_name);
        if (name != "." && name != "..") result.append(name);
        if (result.size() > MaxFiles) { ok = false; break; }
    }
    if (::closedir(handle) != 0) ok = false;
#endif
    result.sort(Qt::CaseSensitive);
    return ok;
}

inline bool scan(const QString &root, Files &files) {
    files.clear();
    if (!plain(root, true)) return false;
    qint64 total = 0;
    for (const auto &dir : Directories) {
        QStringList entries;
        if (!names(root + '/' + dir, entries)) return false;
        for (const auto &name : entries) {
            QByteArray bytes;
            // Reject unexpected subdirectories rather than silently omit them.
            if (!leaf(name) || files.size() >= MaxFiles || !read(root + '/' + dir + '/' + name, bytes)) return false;
            total += bytes.size();
            if (total > MaxTotalBytes) return false;
            files.insert(dir + '/' + name, bytes);
        }
    }
    return true;
}

inline QByteArray hash(const QByteArray &bytes) {
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
}

inline QByteArray manifest(const Files &files) {
    QJsonArray entries;
    for (auto it = files.begin(); it != files.end(); ++it) {
        entries.append(QJsonObject{{"path", it.key()}, {"size", static_cast<int>(it.value().size())},
            {"sha256", QString::fromLatin1(hash(it.value()))}});
    }
    return QJsonDocument(QJsonObject{{"kind", "mdmbox-legacy-directories"}, {"schema", 1},
        {"entries", entries}}).toJson(QJsonDocument::Compact);
}

inline bool writeNew(const QString &path, const QByteArray &bytes) {
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::NewOnly)) return false;
#ifndef Q_OS_WIN
    if (!file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) return false;
#endif
    if (file.write(bytes) != bytes.size() || !file.flush()) return false;
    file.close();
    QByteArray actual;
    return read(path, actual) && actual == bytes;
}
} // namespace Detail

// Verification is read-only and requires an exact tree plus canonical manifest.
// Hashes detect corruption, not malicious replacement of manifest AND payload.
[[nodiscard]] inline Result Verify(const QString &directory) {
    using namespace Detail;
    QStringList entries, directories;
    if (!names(directory, entries) || entries != QStringList{"manifest.json", "payload"} ||
        !names(directory + "/payload", directories) || directories != Directories) {
        return {Status::InvalidBackup, {}};
    }
    Files files;
    QByteArray stored;
    if (!scan(directory + "/payload", files) ||
        !read(directory + "/manifest.json", stored, MaxManifestBytes) || stored != manifest(files)) {
        return {Status::InvalidBackup, {}};
    }
    return {Status::Verified, QFileInfo(directory).canonicalFilePath()};
}

namespace Detail {
// Internal writer seam for deterministic filesystem-failure fixtures; public
// callers always use the checked NewOnly writer below.
template<typename Writer>
[[nodiscard]] inline Result create(const QString &sourceRoot, const QString &backupParent, Writer writer) {
    using namespace Detail;
    if (!plain(sourceRoot, true) || !plain(backupParent, true)) return {Status::UnsafePath, {}};
    const auto source = QFileInfo(sourceRoot).canonicalFilePath();
    const auto parent = QFileInfo(backupParent).canonicalFilePath();
#ifdef Q_OS_WIN
    const auto sensitivity = Qt::CaseInsensitive;
#else
    const auto sensitivity = Qt::CaseSensitive;
#endif
    if (parent.compare(source, sensitivity) == 0 || parent.startsWith(source + '/', sensitivity)) return {Status::UnsafePath, {}};
    Files before;
    if (!scan(source, before)) return {Status::SourceError, {}};
    const auto bytes = manifest(before);
    if (bytes.size() > MaxManifestBytes) return {Status::SourceError, {}};
    const auto name = "legacy-backup-" + QUuid::createUuid().toString(QUuid::Id128);
    const auto target = parent + '/' + name;
    if (!QDir(parent).mkdir(name) || !plain(target, true)) return {Status::WriteError, {}};
#ifndef Q_OS_WIN
    if (!QFile::setPermissions(target, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) return {Status::WriteError, {}};
#endif
    if (!QDir(target).mkdir("payload")) return {Status::WriteError, {}};
    for (const auto &dir : Directories) if (!QDir(target + "/payload").mkdir(dir)) return {Status::WriteError, {}};
    for (auto it = before.begin(); it != before.end(); ++it) {
        if (!writer(target + "/payload/" + it.key(), it.value())) return {Status::WriteError, {}};
    }
    Files after;
    if (!scan(source, after) || after != before) return {Status::SourceChanged, {}};
    // Publication marker LAST, atomic; partial/interrupted directories have no
    // usable manifest. Never overwrite or clean up retained failed attempts.
    QSaveFile marker(target + "/manifest.json");
    marker.setDirectWriteFallback(false);
    if (!marker.open(QIODevice::WriteOnly) || marker.write(bytes) != bytes.size() || !marker.commit()) return {Status::WriteError, {}};
    return Verify(target);
}
} // namespace Detail

[[nodiscard]] inline Result Create(const QString &sourceRoot, const QString &backupParent) {
    return Detail::create(sourceRoot, backupParent, Detail::writeNew);
}
} // namespace NekoGui::LegacyBackup
