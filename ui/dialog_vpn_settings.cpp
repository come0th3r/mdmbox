#include "dialog_vpn_settings.h"
#include "ui_dialog_vpn_settings.h"

#include "main/GuiUtils.hpp"
#include "main/NekoGui.hpp"
#include "ui/mainwindow_interface.h"

#include <QMessageBox>

namespace {
    QStringList tunCompatibilityPreset() {
        return {
            "Discord.exe",
            "DiscordCanary.exe",
            "DiscordPTB.exe",
            "DiscordDevelopment.exe",
            "winws.exe",
            "zapret.exe",
            "zapret-discord.exe",
            "GoodbyeDPI.exe",
            "WinDivert.exe",
        };
    }
}

DialogVPNSettings::DialogVPNSettings(QWidget *parent) : QDialog(parent), ui(new Ui::DialogVPNSettings) {
    ui->setupUi(this);
    ADD_ASTERISK(this);

    ui->fake_dns->setChecked(NekoGui::dataStore->fake_dns);
    auto vpnImplementation = NekoGui::dataStore->vpn_implementation;
    if (vpnImplementation < 0) vpnImplementation = 0;
    if (vpnImplementation > 1) vpnImplementation = 1;
    ui->vpn_implementation->setCurrentIndex(vpnImplementation);
    ui->vpn_mtu->setCurrentText(Int2String(NekoGui::dataStore->vpn_mtu));
    ui->vpn_ipv6->setChecked(NekoGui::dataStore->vpn_ipv6);
    ui->hide_console->setChecked(NekoGui::dataStore->vpn_hide_console);
#ifndef Q_OS_WIN
    ui->hide_console->setVisible(false);
#endif
    ui->strict_route->setChecked(NekoGui::dataStore->vpn_strict_route);
    ui->single_core->setChecked(NekoGui::dataStore->vpn_internal_tun);
    //
    D_LOAD_STRING_PLAIN(vpn_rule_cidr)
    D_LOAD_STRING_PLAIN(vpn_rule_process)
    //
    ui->vpn_rule_process->setPlaceholderText(tr("One item per line. Process name or full path.\n\n"
                                                "To keep Zapret/Discord working together with TUN, bypass Discord and the Zapret/WinDivert helper here."));
    connect(ui->add_compatibility_preset, &QPushButton::clicked, this, [=] {
        auto current = SplitLinesSkipSharp(ui->vpn_rule_process->toPlainText());
        for (const auto &item: tunCompatibilityPreset()) {
            if (!current.contains(item, Qt::CaseInsensitive)) current << item;
        }
        ui->vpn_rule_process->setPlainText(current.join("\n"));
    });
    connect(ui->whitelist_mode, &QCheckBox::stateChanged, this, [=](int state) {
        if (state == Qt::Checked) {
            ui->gb_cidr->setTitle(tr("Proxy CIDR"));
            ui->gb_process_name->setTitle(tr("Proxy Process / Path"));
        } else {
            ui->gb_cidr->setTitle(tr("Bypass CIDR"));
            ui->gb_process_name->setTitle(tr("Bypass Process / Path"));
        }
    });
    ui->whitelist_mode->setChecked(NekoGui::dataStore->vpn_rule_white);
}

DialogVPNSettings::~DialogVPNSettings() {
    delete ui;
}

void DialogVPNSettings::accept() {
    //
    auto mtu = ui->vpn_mtu->currentText().toInt();
    if (mtu > 10000 || mtu < 1000) mtu = 9000;
    NekoGui::dataStore->vpn_implementation = qBound(0, ui->vpn_implementation->currentIndex(), 1);
    NekoGui::dataStore->fake_dns = ui->fake_dns->isChecked();
    NekoGui::dataStore->vpn_mtu = mtu;
    NekoGui::dataStore->vpn_ipv6 = ui->vpn_ipv6->isChecked();
    NekoGui::dataStore->vpn_hide_console = ui->hide_console->isChecked();
    NekoGui::dataStore->vpn_strict_route = ui->strict_route->isChecked();
    NekoGui::dataStore->vpn_rule_white = ui->whitelist_mode->isChecked();
    bool isInternalChanged = NekoGui::dataStore->vpn_internal_tun != ui->single_core->isChecked();
    NekoGui::dataStore->vpn_internal_tun = ui->single_core->isChecked();
    //
    D_SAVE_STRING_PLAIN(vpn_rule_cidr)
    D_SAVE_STRING_PLAIN(vpn_rule_process)
    //
    QStringList msg{"UpdateDataStore"};
    if (isInternalChanged) {
        msg << "NeedRestart";
    } else {
        msg << "VPNChanged";
    }
    MW_dialog_message("", msg.join(","));
    QDialog::accept();
}

void DialogVPNSettings::on_troubleshooting_clicked() {
    auto r = QMessageBox::information(this, tr("Troubleshooting"),
                                      tr("If you have trouble starting VPN, you can force reset nekobox_core process here.\n\n"
                                         "If still not working, see documentation for more information.\n"
                                         "https://matsuridayo.github.io/n-configuration/#vpn-tun"),
                                      tr("Reset"), tr("Cancel"), "",
                                      1, 1);
    if (r == 0) {
        GetMainWindow()->StopVPNProcess(true);
    }
}
