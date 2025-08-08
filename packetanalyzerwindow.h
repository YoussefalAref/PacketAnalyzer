#ifndef PACKETANALYZERWINDOW_H
#define PACKETANALYZERWINDOW_H

#include <QMainWindow>

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

private:
    Ui::PacketAnalyzerWindow *ui;
};
#endif // PACKETANALYZERWINDOW_H
