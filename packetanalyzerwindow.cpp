#include "packetanalyzerwindow.h"
#include "ui_packetanalyzerwindow.h"
#include <QHeaderView>
#include <QDebug>


PacketAnalyzerWindow::PacketAnalyzerWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::PacketAnalyzerWindow)
{
    ui->setupUi(this);
    //main splitter
    QSplitter* mainSplitter = new QSplitter(Qt::Vertical);
    setCentralWidget(mainSplitter);

    //splitter between the table and filters
    QSplitter* topSplitter = new QSplitter(Qt::Horizontal);

    // Setup the table
    framesTable = new QTableWidget(0, 8);
    framesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    framesTable->setSelectionMode(QAbstractItemView::SingleSelection);
    framesTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    QStringList headersLabels = {"#","Type", "Ip", "Port", "IP", "Port", "Type", "Validity"};
    framesTable->setColumnWidth(0,30);
    framesTable->verticalHeader()->setVisible(true);
    framesTable->verticalHeader()->setDefaultAlignment(Qt::AlignRight | Qt::AlignCenter);
    framesTable->setHorizontalHeaderLabels(headersLabels);
    topSplitter->addWidget(framesTable);

    // Buttons for filters
    QWidget* filters = new QWidget;
    QVBoxLayout* filterslay = new QVBoxLayout(filters);
    filterslay->addWidget(new QPushButton("Click"));
    filterslay->addWidget(new QPushButton("Click"));
    filterslay->addWidget(new QPushButton("Click"));
    filterslay->addStretch();
    filters->setLayout(filterslay);
    topSplitter->addWidget(filters);

    // Tree widget
    QTreeWidget* frameTree = new QTreeWidget;

    // Setting the main Splitter
    mainSplitter->addWidget(topSplitter);
    mainSplitter->addWidget(frameTree);

    //Size initilaization
    topSplitter->setSizes(QList<int>() << 450 << 100);
    mainSplitter->setSizes(QList<int>() << 300 << 200);

    // Connections
    // connect(analyzer, &PacketAnalyzer::recievedPacket, this, &PacketAnalyzerWindow::fillFramesTable);

}




void PacketAnalyzerWindow::fillFramesTable(Frame frame){
    framesTable->insertRow(framesTable->rowCount());
    // switch(frame.type){
    // case Protocol::ETHERTYPE_ARP:
    //     framesTable->
    //     break;
    // case Protocol::ETHERTYPE_IPV4:
    //     break;
    // case Protocol::ETHERTYPE_IPV6:
    //     break

}
}
PacketAnalyzerWindow::~PacketAnalyzerWindow()
{
    delete ui;
}
