/********************************************************************************
** Form generated from reading UI file 'packetanalyzerwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.9.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PACKETANALYZERWINDOW_H
#define UI_PACKETANALYZERWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_PacketAnalyzerWindow
{
public:
    QWidget *centralwidget;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *PacketAnalyzerWindow)
    {
        if (PacketAnalyzerWindow->objectName().isEmpty())
            PacketAnalyzerWindow->setObjectName("PacketAnalyzerWindow");
        PacketAnalyzerWindow->resize(800, 600);
        centralwidget = new QWidget(PacketAnalyzerWindow);
        centralwidget->setObjectName("centralwidget");
        PacketAnalyzerWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(PacketAnalyzerWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 800, 21));
        PacketAnalyzerWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(PacketAnalyzerWindow);
        statusbar->setObjectName("statusbar");
        PacketAnalyzerWindow->setStatusBar(statusbar);

        retranslateUi(PacketAnalyzerWindow);

        QMetaObject::connectSlotsByName(PacketAnalyzerWindow);
    } // setupUi

    void retranslateUi(QMainWindow *PacketAnalyzerWindow)
    {
        PacketAnalyzerWindow->setWindowTitle(QCoreApplication::translate("PacketAnalyzerWindow", "PacketAnalyzerWindow", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PacketAnalyzerWindow: public Ui_PacketAnalyzerWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PACKETANALYZERWINDOW_H
