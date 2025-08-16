#include "packetanalyzerwindow.h"
#include "ui_packetanalyzerwindow.h"
#include <QDebug>


PacketAnalyzerWindow::PacketAnalyzerWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::PacketAnalyzerWindow)
{
    ui->setupUi(this);
    udpsocket=new QUdpSocket(this);

    // check if the binding works fine
    if(!udpsocket->bind(QHostAddress::AnyIPv4,2000))
    {
        qDebug()<<"Failed to bind";
        return;
    }

    //connection that handles the program
    connect(udpsocket,&QUdpSocket::readyRead,this,&PacketAnalyzerWindow::handler);


}

//to recieve the data and check it and analyzer function called inside
void PacketAnalyzerWindow::handler(){
    while(udpsocket->hasPendingDatagrams())
    {
        QNetworkDatagram loadedDatagram=udpsocket->receiveDatagram();
        QByteArray frameArray= loadedDatagram.data();
        //call validation function
        //inside the validation call the analyzer for the complete values
        //create a function that takes the validation
    }
}


//I'm thinking to make like an enum flags to determine what is the reason for invalid packets
void PacketAnalyzerWindow::validation(){

}



PacketAnalyzerWindow::~PacketAnalyzerWindow()
{
    delete ui;
}
