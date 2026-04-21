#include "MdmServerItemWidget.h"
#include <QVBoxLayout>
#include <QMouseEvent>
#include <QStyle>

MdmServerItemWidget::MdmServerItemWidget(int profileId, const QString &name, const QString &address, int latency, bool isActive, QWidget *parent)
    : QWidget(parent), m_profileId(profileId), m_isActive(isActive) {
    
    this->setFixedHeight(70);
    this->setCursor(Qt::PointingHandCursor);
    
    auto mainLayout = new QHBoxLayout(this);
    mainLayout->setContentsMargins(20, 10, 20, 10);
    mainLayout->setSpacing(15);
    
    // Status dot
    lblStatusDot = new QLabel(this);
    lblStatusDot->setFixedSize(10, 10);
    if (m_isActive) {
        lblStatusDot->setStyleSheet("background-color: #005faa; border-radius: 5px;");
        this->setStyleSheet("background-color: rgba(0, 95, 170, 0.05); border-bottom: 1px solid #f3f3f3;");
    } else {
        lblStatusDot->setStyleSheet("background-color: #d1d5db; border-radius: 5px;");
        this->setStyleSheet("background-color: transparent; border-bottom: 1px solid #f3f3f3;");
    }
    mainLayout->addWidget(lblStatusDot);
    
    // Badge
    badgeWidget = new QWidget(this);
    badgeWidget->setFixedSize(40, 24);
    badgeWidget->setStyleSheet(m_isActive ? "background-color: #2563eb; border-radius: 4px;" : "background-color: #6b7280; border-radius: 4px;");
    auto badgeLayout = new QVBoxLayout(badgeWidget);
    badgeLayout->setContentsMargins(0, 0, 0, 0);
    lblBadge = new QLabel("VPN", badgeWidget);
    lblBadge->setStyleSheet("color: white; font-size: 10px; font-weight: bold;");
    lblBadge->setAlignment(Qt::AlignCenter);
    badgeLayout->addWidget(lblBadge);
    mainLayout->addWidget(badgeWidget);
    
    // Name and SubStatus
    auto textLayout = new QVBoxLayout();
    textLayout->setSpacing(2);
    
    lblName = new QLabel(name, this);
    lblName->setStyleSheet(m_isActive ? "color: #1a1c1c; font-size: 14px; font-weight: bold;" : "color: #1a1c1c; font-size: 14px; font-weight: 500;");
    textLayout->addWidget(lblName);
    
    if (m_isActive) {
        lblActiveStatus = new QLabel("Активен", this);
        lblActiveStatus->setStyleSheet("color: #005faa; font-size: 10px; font-weight: bold; text-transform: uppercase;");
        textLayout->addWidget(lblActiveStatus);
    } else if (!address.isEmpty()) {
        lblActiveStatus = new QLabel(address, this);
        lblActiveStatus->setStyleSheet("color: #717783; font-size: 11px;");
        textLayout->addWidget(lblActiveStatus);
    }
    
    mainLayout->addLayout(textLayout);
    mainLayout->addStretch();
    
    // Latency
    QString latencyText = latency > 0 ? QString::number(latency) + " мс" : "-";
    lblLatency = new QLabel(latencyText, this);
    lblLatency->setStyleSheet(m_isActive ? "color: #005faa; font-size: 14px; font-weight: 500;" : "color: #4b5563; font-size: 14px;");
    mainLayout->addWidget(lblLatency);
}

void MdmServerItemWidget::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton) {
        emit clicked(m_profileId);
    }
    QWidget::mousePressEvent(event);
}

void MdmServerItemWidget::enterEvent(QEnterEvent *event) {
    if (!m_isActive) {
        this->setStyleSheet("background-color: #f9fafb; border-bottom: 1px solid #f3f3f3;");
    }
    QWidget::enterEvent(event);
}

void MdmServerItemWidget::leaveEvent(QEvent *event) {
    if (!m_isActive) {
        this->setStyleSheet("background-color: transparent; border-bottom: 1px solid #f3f3f3;");
    }
    QWidget::leaveEvent(event);
}
