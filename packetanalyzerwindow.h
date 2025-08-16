#ifndef PACKETANALYZERWINDOW_H
#define PACKETANALYZERWINDOW_H

#include <QMainWindow>
#include <QUdpSocket>
#include <QByteArray>
#include <QNetworkDatagram>

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
    void handler();
private:
    void validation();
    Ui::PacketAnalyzerWindow *ui;
    QUdpSocket* udpsocket;

};
#endif // PACKETANALYZERWINDOW_H
