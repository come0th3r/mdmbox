#pragma once

#include <memory>
#include <QProcess>
#include "CoreProcessGeneration.hpp"

namespace NekoGui_sys {
    class ExternalProcess : public QProcess {
    public:
        QString tag;
        QString program;
        QStringList arguments;
        QStringList env;

        bool managed = true; // MW_dialog_message

        ExternalProcess();
        ~ExternalProcess();

        // start & kill is one time

        virtual void Start();

        void Kill();

    protected:
        bool started = false;
        bool killed = false;
        bool crashed = false;
    };

    class CoreProcess : public ExternalProcess {
    public:
        CoreProcess(const QString &core_path, const QStringList &args);

        void Start() override;

        void Restart();
        [[nodiscard]] bool acceptsGeneration(quint64 generation) const { return generationCounter.accepts(generation); }

        int start_profile_when_core_is_up = -1;

    private:
        bool show_stderr = false;
        CoreProcessGeneration generationCounter;
        bool failed_to_start = false;
        bool restarting = false;
    };

    // 手动管理
    inline std::list<std::shared_ptr<ExternalProcess>> running_ext;

    inline QAtomicInt logCounter;
} // namespace NekoGui_sys
