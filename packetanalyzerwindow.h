#ifndef PACKETANALYZERWINDOW_H
#define PACKETANALYZERWINDOW_H

#include <QMainWindow>
#include <QUdpSocket>
#include <QByteArray>
#include <QNetworkDatagram>
#include "packetanalyzer.h"
#include <QTableWidget>
#include <QTreeWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QSplitter>
#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui {
class PacketAnalyzerWindow;
}
QT_END_NAMESPACE


class PacketAnalyzerWindow : public QMainWindow
{
    Q_OBJECT
public:
    PacketAnalyzerWindow(QWidget *parent = nullptr);
    ~PacketAnalyzerWindow();


private slots:
    void fillFramesTable(Frame frame);


private:
    Ui::PacketAnalyzerWindow *ui;
    PacketAnalyzer* analyzer;
    QTableWidget* framesTable;

};
#endif // PACKETANALYZERWINDOW_H
