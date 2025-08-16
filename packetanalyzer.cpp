#include "packetanalyzer.h"

PacketAnalyzer::PacketAnalyzer() {
    udpsocket=new QUdpSocket(this);

    // check if the binding works fine
    if(!udpsocket->bind(QHostAddress::AnyIPv4,2000))
    {
        qDebug()<<"Failed to bind";
        return;
    }
    //connection that handles the program
    connect(udpsocket,&QUdpSocket::readyRead,this,&PacketAnalyzer::handler);

}
