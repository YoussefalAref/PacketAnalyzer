#include "packetanalyzerwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    PacketAnalyzerWindow w;
    w.show();
    return a.exec();
}
