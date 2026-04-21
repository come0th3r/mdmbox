#pragma once

#include <QWidget>
#include <QLabel>
#include <QHBoxLayout>

class MdmServerItemWidget : public QWidget {
    Q_OBJECT

public:
    explicit MdmServerItemWidget(int profileId, const QString &name, const QString &address, int latency, bool isActive, QWidget *parent = nullptr);
    ~MdmServerItemWidget() override = default;

    int getProfileId() const { return m_profileId; }

signals:
    void clicked(int profileId);

protected:
    void mousePressEvent(QMouseEvent *event) override;
    void enterEvent(QEnterEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    int m_profileId;
    bool m_isActive;
    
    QLabel *lblStatusDot;
    QWidget *badgeWidget;
    QLabel *lblBadge;
    QLabel *lblName;
    QLabel *lblActiveStatus;
    QLabel *lblLatency;
};
