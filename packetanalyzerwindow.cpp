#include "packetanalyzerwindow.h"
#include "ui_packetanalyzerwindow.h"

PacketAnalyzerWindow::PacketAnalyzerWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::PacketAnalyzerWindow)
{
    ui->setupUi(this);
}

PacketAnalyzerWindow::~PacketAnalyzerWindow()
{
    delete ui;
}
