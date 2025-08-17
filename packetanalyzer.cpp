#include "packetanalyzer.h"

// Constructor implementation (already provided)
PacketAnalyzer::PacketAnalyzer() {
    udpsocket = new QUdpSocket(this);
    if(!udpsocket->bind(QHostAddress::AnyIPv4, 2000)) {
        qDebug() << "Failed to bind";
        return;
    }

    connect(udpsocket, &QUdpSocket::readyRead, this, &PacketAnalyzer::handler);
}

// Main handler function
void PacketAnalyzer::handler() {
    while(udpsocket->hasPendingDatagrams()) {
        QNetworkDatagram datagram = udpsocket->receiveDatagram();
        QByteArray frameData = datagram.data();

        // Extract and store the frame
        Frame frame = extractFrame(frameData);
        Packets.append(frame);

        // Emit signal with the received packet
        emit recievedPacket(frame);

        // Debug print
        printFrame(frame);
    }
}

// Validation function - checks what parts are corrupted/missing
CorruptionFlag PacketAnalyzer::validatePacket(const QByteArray& frameData) {
    CorruptionFlag flags = CorruptionFlag::NONE;
    size_t dataSize = frameData.size();

    // Check Ethernet header
    if (dataSize < Protocol::ETH_HEADER_SIZE) {
        flags |= CorruptionFlag::ETH_HEADER_MISSING;
        return flags;  // Can't proceed without Ethernet header
    }

    const uint8_t* data = reinterpret_cast<const uint8_t*>(frameData.data());
    uint16_t etherType = qFromBigEndian<uint16_t>(data + 12);
    size_t offset = Protocol::ETH_HEADER_SIZE;

    // Check based on Ethernet type
    switch (etherType) {
    case Protocol::ETHERTYPE_ARP:
        if (dataSize < offset + Protocol::ARP_SIZE) {
            flags |= CorruptionFlag::ARP_INCOMPLETE;
        }
        break;

    case Protocol::ETHERTYPE_IPV4: {
        if (dataSize < offset + Protocol::IPV4_MIN_HEADER_SIZE) {
            flags |= CorruptionFlag::IPV4_HEADER_INCOMPLETE;
            break;
        }

        uint8_t ihl = (data[offset] & 0x0F) * 4;
        uint16_t totalLength = qFromBigEndian<uint16_t>(data + offset + 2);
        uint8_t protocol = data[offset + 9];

        if (dataSize < offset + ihl) {
            flags |= CorruptionFlag::IPV4_HEADER_INCOMPLETE;
            break;
        }

        offset += ihl;

        // Check transport layer
        switch (protocol) {
        case Protocol::IPPROTO_TCP:
            if (dataSize < offset + Protocol::TCP_MIN_HEADER_SIZE) {
                flags |= CorruptionFlag::TCP_HEADER_INCOMPLETE;
            } else {
                uint8_t tcpDataOffset = (data[offset + 12] >> 4) * 4;
                if (dataSize < offset + tcpDataOffset) {
                    flags |= CorruptionFlag::TCP_HEADER_INCOMPLETE;
                }
                // Check if payload exists
                size_t expectedPayloadSize = totalLength - ihl - tcpDataOffset;
                if (expectedPayloadSize > 0 && dataSize < offset + tcpDataOffset + expectedPayloadSize) {
                    flags |= CorruptionFlag::PAYLOAD_TRUNCATED;
                }
            }
            break;

        case Protocol::IPPROTO_UDP:
            if (dataSize < offset + Protocol::UDP_HEADER_SIZE) {
                flags |= CorruptionFlag::UDP_HEADER_INCOMPLETE;
            } else {
                uint16_t udpLength = qFromBigEndian<uint16_t>(data + offset + 4);
                if (udpLength > Protocol::UDP_HEADER_SIZE) {
                    size_t payloadSize = udpLength - Protocol::UDP_HEADER_SIZE;
                    if (dataSize < offset + Protocol::UDP_HEADER_SIZE + payloadSize) {
                        flags |= CorruptionFlag::PAYLOAD_TRUNCATED;
                    }
                }
            }
            break;

        case Protocol::IPPROTO_ICMP:
            if (dataSize < offset + Protocol::ICMP_HEADER_SIZE) {
                flags |= CorruptionFlag::ICMP_HEADER_INCOMPLETE;
            }
            break;
        }
        break;
    }

    case Protocol::ETHERTYPE_IPV6: {
        if (dataSize < offset + Protocol::IPV6_HEADER_SIZE) {
            flags |= CorruptionFlag::IPV6_HEADER_INCOMPLETE;
            break;
        }

        uint16_t payloadLength = qFromBigEndian<uint16_t>(data + offset + 4);
        uint8_t nextHeader = data[offset + 6];
        offset += Protocol::IPV6_HEADER_SIZE;

        // Check transport layer
        switch (nextHeader) {
        case Protocol::IPPROTO_TCP:
            if (dataSize < offset + Protocol::TCP_MIN_HEADER_SIZE) {
                flags |= CorruptionFlag::TCP_HEADER_INCOMPLETE;
            } else {
                uint8_t tcpDataOffset = (data[offset + 12] >> 4) * 4;
                if (dataSize < offset + tcpDataOffset) {
                    flags |= CorruptionFlag::TCP_HEADER_INCOMPLETE;
                }
                size_t expectedPayloadSize = payloadLength - tcpDataOffset;
                if (expectedPayloadSize > 0 && dataSize < offset + tcpDataOffset + expectedPayloadSize) {
                    flags |= CorruptionFlag::PAYLOAD_TRUNCATED;
                }
            }
            break;

        case Protocol::IPPROTO_UDP:
            if (dataSize < offset + Protocol::UDP_HEADER_SIZE) {
                flags |= CorruptionFlag::UDP_HEADER_INCOMPLETE;
            } else {
                uint16_t udpLength = qFromBigEndian<uint16_t>(data + offset + 4);
                if (udpLength > Protocol::UDP_HEADER_SIZE) {
                    size_t payloadSize = udpLength - Protocol::UDP_HEADER_SIZE;
                    if (dataSize < offset + Protocol::UDP_HEADER_SIZE + payloadSize) {
                        flags |= CorruptionFlag::PAYLOAD_TRUNCATED;
                    }
                }
            }
            break;

        case Protocol::IPPROTO_ICMPV6:
            if (dataSize < offset + Protocol::ICMP_HEADER_SIZE) {
                flags |= CorruptionFlag::ICMP_HEADER_INCOMPLETE;
            }
            break;
        }
        break;
    }
    }

    return flags;
}


// Frame completion function - ensures frame has enough bytes for safe extraction
QByteArray PacketAnalyzer::completeFrame(const QByteArray& frameData, CorruptionFlag corruptionFlags) {
    QByteArray completedData = frameData;
    size_t currentSize = frameData.size();
    size_t requiredSize = currentSize;

    // Determine required size based on corruption flags
    if (corruptionFlags & CorruptionFlag::ETH_HEADER_MISSING) {
        requiredSize = Protocol::ETH_HEADER_SIZE;
    } else if (currentSize >= Protocol::ETH_HEADER_SIZE) {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(frameData.data());
        uint16_t etherType = qFromBigEndian<uint16_t>(data + 12);

        switch (etherType) {
        case Protocol::ETHERTYPE_ARP:
            requiredSize = Protocol::ETH_HEADER_SIZE + Protocol::ARP_SIZE;
            break;

        case Protocol::ETHERTYPE_IPV4: {
            requiredSize = Protocol::ETH_HEADER_SIZE + Protocol::IPV4_MIN_HEADER_SIZE;
            if (currentSize >= requiredSize) {
                uint8_t ihl = (data[Protocol::ETH_HEADER_SIZE] & 0x0F) * 4;
                uint16_t totalLength = (currentSize >= Protocol::ETH_HEADER_SIZE + 4) ?
                                           qFromBigEndian<uint16_t>(data + Protocol::ETH_HEADER_SIZE + 2) :
                                           Protocol::MAX_PACKET_SIZE;

                // Limit total length to reasonable size
                if (totalLength > Protocol::MAX_PACKET_SIZE) {
                    totalLength = Protocol::MAX_PACKET_SIZE;
                }

                requiredSize = Protocol::ETH_HEADER_SIZE + totalLength;
            }
            break;
        }

        case Protocol::ETHERTYPE_IPV6: {
            requiredSize = Protocol::ETH_HEADER_SIZE + Protocol::IPV6_HEADER_SIZE;
            if (currentSize >= requiredSize) {
                uint16_t payloadLength = qFromBigEndian<uint16_t>(data + Protocol::ETH_HEADER_SIZE + 4);

                // Limit payload length to reasonable size
                if (payloadLength > Protocol::MAX_PACKET_SIZE) {
                    payloadLength = Protocol::MAX_PACKET_SIZE;
                }

                requiredSize = Protocol::ETH_HEADER_SIZE + Protocol::IPV6_HEADER_SIZE + payloadLength;
            }
            break;
        }

        default:
            // Unknown protocol, ensure we have at least some data
            requiredSize = Protocol::ETH_HEADER_SIZE + 64;  // Arbitrary minimum
            break;
        }
    }

    // Pad with 0xFF if needed
    if (currentSize < requiredSize) {
        size_t paddingNeeded = requiredSize - currentSize;
        QByteArray padding(paddingNeeded, static_cast<char>(Protocol::MISSING_DATA_FILL));
        completedData.append(padding);

        qDebug() << "Frame padded: added" << paddingNeeded << "bytes of 0xFF";
    }

    return completedData;
}

// Main extraction function
Frame PacketAnalyzer::extractFrame(const QByteArray& frameData) {
    Frame frame;
    frame.rawData = frameData;

    // First, validate the packet
    frame.corruptionFlags = validatePacket(frameData);

    // Complete the frame if necessary
    frame.completedData = completeFrame(frameData, frame.corruptionFlags);

    // Now extract from the completed data
    const uint8_t* data = reinterpret_cast<const uint8_t*>(frame.completedData.data());
    size_t dataSize = frame.completedData.size();

    // Extract Ethernet header
    extractEthernet(frame, data, dataSize);

    return frame;
}

// Ethernet extraction
void PacketAnalyzer::extractEthernet(Frame& frame, const uint8_t* data, size_t dataSize) {
    if (dataSize >= Protocol::ETH_HEADER_SIZE) {
        memcpy(frame.dest, data, 6);
        memcpy(frame.src, data + 6, 6);
        frame.type = qFromBigEndian<uint16_t>(data + 12);

        size_t offset = Protocol::ETH_HEADER_SIZE;

        switch (frame.type) {
        case Protocol::ETHERTYPE_ARP:
            extractARP(frame.arp, data + offset, dataSize - offset);
            break;

        case Protocol::ETHERTYPE_IPV4:
            extractIPv4(frame.ipv4, data + offset, dataSize - offset);
            break;

        case Protocol::ETHERTYPE_IPV6:
            extractIPv6(frame.ipv6, data + offset, dataSize - offset);
            break;
        }
    }
}

// ARP extraction
void PacketAnalyzer::extractARP(ARPPacket& arp, const uint8_t* data, size_t dataSize) {
    if (dataSize >= Protocol::ARP_SIZE) {
        arp.hardware_type = qFromBigEndian<uint16_t>(data);
        arp.protocol_type = qFromBigEndian<uint16_t>(data + 2);
        arp.hardware_size = data[4];
        arp.protocol_size = data[5];
        arp.opcode = qFromBigEndian<uint16_t>(data + 6);
        memcpy(arp.sender_mac, data + 8, 6);
        arp.sender_ip = qFromBigEndian<uint32_t>(data + 14);
        memcpy(arp.target_mac, data + 18, 6);
        arp.target_ip = qFromBigEndian<uint32_t>(data + 24);
        arp.isValid = true;
    }
}

// IPv4 extraction
void PacketAnalyzer::extractIPv4(IPv4Packet& ipv4, const uint8_t* data, size_t dataSize) {
    if (dataSize >= Protocol::IPV4_MIN_HEADER_SIZE) {
        ipv4.ihl = (data[0] & 0x0F);
        ipv4.tos = data[1];
        ipv4.total_length = qFromBigEndian<uint16_t>(data + 2);
        ipv4.id = qFromBigEndian<uint16_t>(data + 4);
        ipv4.flags = qFromBigEndian<uint16_t>(data + 6);
        ipv4.ttl = data[8];
        ipv4.protocol = data[9];
        ipv4.checksum = qFromBigEndian<uint16_t>(data + 10);
        ipv4.src_ip = qFromBigEndian<uint32_t>(data + 12);
        ipv4.dest_ip = qFromBigEndian<uint32_t>(data + 16);
        ipv4.isValid = true;

        size_t headerLength = ipv4.ihl * 4;
        if (dataSize >= headerLength) {
            size_t transportOffset = headerLength;
            size_t transportDataSize = dataSize - transportOffset;
            size_t ipPayloadSize = ipv4.total_length - headerLength;

            switch (ipv4.protocol) {
            case Protocol::IPPROTO_TCP:
                extractTCP(ipv4.tcp, data + transportOffset, transportDataSize, ipPayloadSize);
                break;

            case Protocol::IPPROTO_UDP:
                extractUDP(ipv4.udp, data + transportOffset, transportDataSize);
                break;

            case Protocol::IPPROTO_ICMP:
                extractICMP(ipv4.icmp, data + transportOffset, transportDataSize);
                break;
            }
        }
    }
}

// IPv6 extraction
void PacketAnalyzer::extractIPv6(IPv6Packet& ipv6, const uint8_t* data, size_t dataSize) {
    if (dataSize >= Protocol::IPV6_HEADER_SIZE) {
        ipv6.version_traffic_class_flow_label = qFromBigEndian<uint32_t>(data);
        ipv6.payload_length = qFromBigEndian<uint16_t>(data + 4);
        ipv6.next_header = data[6];
        ipv6.hop_limit = data[7];
        memcpy(ipv6.src_ip, data + 8, 16);
        memcpy(ipv6.dest_ip, data + 24, 16);
        ipv6.isValid = true;

        size_t transportOffset = Protocol::IPV6_HEADER_SIZE;
        size_t transportDataSize = dataSize - transportOffset;

        switch (ipv6.next_header) {
        case Protocol::IPPROTO_TCP:
            extractTCP(ipv6.tcp, data + transportOffset, transportDataSize, ipv6.payload_length);
            break;

        case Protocol::IPPROTO_UDP:
            extractUDP(ipv6.udp, data + transportOffset, transportDataSize);
            break;

        case Protocol::IPPROTO_ICMPV6:
            extractICMP(ipv6.icmp, data + transportOffset, transportDataSize);
            break;
        }
    }
}

// TCP extraction with payload
void PacketAnalyzer::extractTCP(TCPHeader& tcp, const uint8_t* data, size_t dataSize, size_t totalIPPayloadSize) {
    if (dataSize >= Protocol::TCP_MIN_HEADER_SIZE) {
        tcp.src_port = qFromBigEndian<uint16_t>(data);
        tcp.dest_port = qFromBigEndian<uint16_t>(data + 2);
        tcp.seq_num = qFromBigEndian<uint32_t>(data + 4);
        tcp.ack_num = qFromBigEndian<uint32_t>(data + 8);
        tcp.data_offset = (data[12] >> 4);
        tcp.flags = qFromBigEndian<uint16_t>(data + 12) & 0x01FF;
        tcp.window_size = qFromBigEndian<uint16_t>(data + 14);
        tcp.checksum = qFromBigEndian<uint16_t>(data + 16);
        tcp.urgent_pointer = qFromBigEndian<uint16_t>(data + 18);
        tcp.isValid = true;

        // Extract payload
        size_t tcpHeaderSize = tcp.data_offset * 4;
        if (dataSize > tcpHeaderSize) {
            size_t payloadSize = dataSize - tcpHeaderSize;
            tcp.expectedPayloadSize = totalIPPayloadSize - tcpHeaderSize;

            // Copy actual payload data
            tcp.payload = QByteArray(reinterpret_cast<const char*>(data + tcpHeaderSize), payloadSize);

            // Check if payload is complete
            tcp.payloadComplete = (payloadSize >= tcp.expectedPayloadSize);

            // If payload is truncated but we know expected size, fill with 0xFF
            if (!tcp.payloadComplete && tcp.expectedPayloadSize > payloadSize) {
                size_t missingBytes = tcp.expectedPayloadSize - payloadSize;
                QByteArray padding(missingBytes, static_cast<char>(Protocol::MISSING_DATA_FILL));
                tcp.payload.append(padding);
            }
        }
    }
}

// UDP extraction with payload
void PacketAnalyzer::extractUDP(UDPHeader& udp, const uint8_t* data, size_t dataSize) {
    if (dataSize >= Protocol::UDP_HEADER_SIZE) {
        udp.src_port = qFromBigEndian<uint16_t>(data);
        udp.dest_port = qFromBigEndian<uint16_t>(data + 2);
        udp.length = qFromBigEndian<uint16_t>(data + 4);
        udp.checksum = qFromBigEndian<uint16_t>(data + 6);
        udp.isValid = true;

        // Extract payload
        if (udp.length > Protocol::UDP_HEADER_SIZE) {
            udp.expectedPayloadSize = udp.length - Protocol::UDP_HEADER_SIZE;

            if (dataSize > Protocol::UDP_HEADER_SIZE) {
                size_t availablePayloadSize = dataSize - Protocol::UDP_HEADER_SIZE;
                size_t payloadSize = qMin(availablePayloadSize, udp.expectedPayloadSize);

                // Copy actual payload data
                udp.payload = QByteArray(reinterpret_cast<const char*>(data + Protocol::UDP_HEADER_SIZE), payloadSize);

                // Check if payload is complete
                udp.payloadComplete = (payloadSize >= udp.expectedPayloadSize);

                // If payload is truncated, fill with 0xFF
                if (!udp.payloadComplete) {
                    size_t missingBytes = udp.expectedPayloadSize - payloadSize;
                    QByteArray padding(missingBytes, static_cast<char>(Protocol::MISSING_DATA_FILL));
                    udp.payload.append(padding);
                }
            } else {
                // No payload data available, fill entirely with 0xFF
                udp.payload = QByteArray(udp.expectedPayloadSize, static_cast<char>(Protocol::MISSING_DATA_FILL));
                udp.payloadComplete = false;
            }
        }
    }
}

// ICMP extraction with payload
void PacketAnalyzer::extractICMP(ICMPHeader& icmp, const uint8_t* data, size_t dataSize) {
    if (dataSize >= Protocol::ICMP_HEADER_SIZE) {
        icmp.type = data[0];
        icmp.code = data[1];
        icmp.checksum = qFromBigEndian<uint16_t>(data + 2);
        icmp.rest_of_header = qFromBigEndian<uint32_t>(data + 4);
        icmp.isValid = true;

        // Extract ICMP payload/data (if any)
        if (dataSize > Protocol::ICMP_HEADER_SIZE) {
            size_t payloadSize = dataSize - Protocol::ICMP_HEADER_SIZE;
            icmp.payload = QByteArray(reinterpret_cast<const char*>(data + Protocol::ICMP_HEADER_SIZE), payloadSize);
            icmp.payloadComplete = true;  // For ICMP, we consider whatever we have as complete
            icmp.expectedPayloadSize = payloadSize;
        }
    }
}

// Print functions for debugging
void PacketAnalyzer::printFrame(const Frame& frame) {
    qDebug() << "\n=== Frame Analysis ===";
    qDebug() << "Raw data size:" << frame.rawData.size() << "bytes";
    qDebug() << "Completed data size:" << frame.completedData.size() << "bytes";

    // Print corruption status
    if (frame.hasCorruption()) {
        qDebug() << "Corruption detected:" << frame.getCorruptionString();
    } else {
        qDebug() << "No corruption detected";
    }

    // Print Ethernet header
    qDebug() << "\n--- Ethernet Header ---";
    qDebug() << QString("Destination MAC: %1:%2:%3:%4:%5:%6")
                    .arg(frame.dest[0], 2, 16, QChar('0'))
                    .arg(frame.dest[1], 2, 16, QChar('0'))
                    .arg(frame.dest[2], 2, 16, QChar('0'))
                    .arg(frame.dest[3], 2, 16, QChar('0'))
                    .arg(frame.dest[4], 2, 16, QChar('0'))
                    .arg(frame.dest[5], 2, 16, QChar('0'));

    qDebug() << QString("Source MAC: %1:%2:%3:%4:%5:%6")
                    .arg(frame.src[0], 2, 16, QChar('0'))
                    .arg(frame.src[1], 2, 16, QChar('0'))
                    .arg(frame.src[2], 2, 16, QChar('0'))
                    .arg(frame.src[3], 2, 16, QChar('0'))
                    .arg(frame.src[4], 2, 16, QChar('0'))
                    .arg(frame.src[5], 2, 16, QChar('0'));

    qDebug() << QString("EtherType: 0x%1").arg(frame.type, 4, 16, QChar('0'));

    // Print payload based on type
    switch (frame.type) {
    case Protocol::ETHERTYPE_ARP:
        if (frame.arp.isValid) {
            qDebug() << "\n--- ARP Packet ---";
            qDebug() << "Operation:" << (frame.arp.opcode == 1 ? "Request" : "Reply");
            qDebug() << QString("Sender IP: %1.%2.%3.%4")
                            .arg((frame.arp.sender_ip >> 24) & 0xFF)
                            .arg((frame.arp.sender_ip >> 16) & 0xFF)
                            .arg((frame.arp.sender_ip >> 8) & 0xFF)
                            .arg(frame.arp.sender_ip & 0xFF);
        }
        break;

    case Protocol::ETHERTYPE_IPV4:
        if (frame.ipv4.isValid) {
            qDebug() << "\n--- IPv4 Packet ---";
            qDebug() << "Protocol:" << frame.ipv4.protocol;
            qDebug() << "Total Length:" << frame.ipv4.total_length;

            if (frame.ipv4.tcp.isValid) {
                printTCPHeader(frame.ipv4.tcp);
            } else if (frame.ipv4.udp.isValid) {
                printUDPHeader(frame.ipv4.udp);
            } else if (frame.ipv4.icmp.isValid) {
                printICMPHeader(frame.ipv4.icmp);
            }
        }
        break;

    case Protocol::ETHERTYPE_IPV6:
        if (frame.ipv6.isValid) {
            qDebug() << "\n--- IPv6 Packet ---";
            qDebug() << "Next Header:" << frame.ipv6.next_header;
            qDebug() << "Payload Length:" << frame.ipv6.payload_length;

            if (frame.ipv6.tcp.isValid) {
                printTCPHeader(frame.ipv6.tcp);
            } else if (frame.ipv6.udp.isValid) {
                printUDPHeader(frame.ipv6.udp);
            } else if (frame.ipv6.icmp.isValid) {
                printICMPHeader(frame.ipv6.icmp);
            }
        }
        break;
    }
}

void PacketAnalyzer::printTCPHeader(const TCPHeader& tcp) {
    qDebug() << "\n--- TCP Header ---";
    qDebug() << "Source Port:" << tcp.src_port;
    qDebug() << "Destination Port:" << tcp.dest_port;
    qDebug() << "Sequence Number:" << tcp.seq_num;
    qDebug() << "Acknowledgment Number:" << tcp.ack_num;
    qDebug() << "Data Offset:" << tcp.data_offset << "words";
    qDebug() << "Flags:" << QString("0x%1").arg(tcp.flags, 3, 16, QChar('0'));
    qDebug() << "Window Size:" << tcp.window_size;

    // Print payload info
    qDebug() << "\n--- TCP Payload ---";
    qDebug() << "Expected payload size:" << tcp.expectedPayloadSize << "bytes";
    qDebug() << "Actual payload size:" << tcp.payload.size() << "bytes";
    qDebug() << "Payload complete:" << (tcp.payloadComplete ? "Yes" : "No");

    if (!tcp.payload.isEmpty()) {
        // Print first 32 bytes of payload in hex
        qDebug() << "Payload preview (hex):";
        QByteArray preview = tcp.payload.left(32);
        QString hexString;
        for (int i = 0; i < preview.size(); ++i) {
            hexString += QString("%1 ").arg(static_cast<uint8_t>(preview[i]), 2, 16, QChar('0'));
            if ((i + 1) % 16 == 0) hexString += "\n";
        }
        qDebug().noquote() << hexString;

        // Check if payload contains padding (0xFF)
        int paddingStart = tcp.payload.indexOf(static_cast<char>(Protocol::MISSING_DATA_FILL));
        if (paddingStart >= 0) {
            qDebug() << "Note: Payload contains padding (0xFF) starting at byte" << paddingStart;
        }
    }
}

void PacketAnalyzer::printUDPHeader(const UDPHeader& udp) {
    qDebug() << "\n--- UDP Header ---";
    qDebug() << "Source Port:" << udp.src_port;
    qDebug() << "Destination Port:" << udp.dest_port;
    qDebug() << "Length:" << udp.length;
    qDebug() << "Checksum:" << QString("0x%1").arg(udp.checksum, 4, 16, QChar('0'));

    // Print payload info
    qDebug() << "\n--- UDP Payload ---";
    qDebug() << "Expected payload size:" << udp.expectedPayloadSize << "bytes";
    qDebug() << "Actual payload size:" << udp.payload.size() << "bytes";
    qDebug() << "Payload complete:" << (udp.payloadComplete ? "Yes" : "No");

    if (!udp.payload.isEmpty()) {
        // Print first 32 bytes of payload
        qDebug() << "Payload preview (hex):";
        QByteArray preview = udp.payload.left(32);
        QString hexString;
        for (int i = 0; i < preview.size(); ++i) {
            hexString += QString("%1 ").arg(static_cast<uint8_t>(preview[i]), 2, 16, QChar('0'));
            if ((i + 1) % 16 == 0) hexString += "\n";
        }
        qDebug().noquote() << hexString;

        // Check if payload contains padding
        int paddingStart = udp.payload.indexOf(static_cast<char>(Protocol::MISSING_DATA_FILL));
        if (paddingStart >= 0) {
            qDebug() << "Note: Payload contains padding (0xFF) starting at byte" << paddingStart;
        }
    }
}

void PacketAnalyzer::printICMPHeader(const ICMPHeader& icmp) {
    qDebug() << "\n--- ICMP Header ---";
    qDebug() << "Type:" << icmp.type;
    qDebug() << "Code:" << icmp.code;
    qDebug() << "Checksum:" << QString("0x%1").arg(icmp.checksum, 4, 16, QChar('0'));
    qDebug() << "Rest of Header:" << QString("0x%1").arg(icmp.rest_of_header, 8, 16, QChar('0'));

    // Print payload info
    if (!icmp.payload.isEmpty()) {
        qDebug() << "\n--- ICMP Data ---";
        qDebug() << "Data size:" << icmp.payload.size() << "bytes";

        // Print first 32 bytes of data
        qDebug() << "Data preview (hex):";
        QByteArray preview = icmp.payload.left(32);
        QString hexString;
        for (int i = 0; i < preview.size(); ++i) {
            hexString += QString("%1 ").arg(static_cast<uint8_t>(preview[i]), 2, 16, QChar('0'));
            if ((i + 1) % 16 == 0) hexString += "\n";
        }
        qDebug().noquote() << hexString;
    }
}

// Helper function to get corruption string
QString Frame::getCorruptionString() const {
    QStringList corruptions;

    if (corruptionFlags & CorruptionFlag::ETH_HEADER_MISSING)
        corruptions << "Ethernet header missing";
    if (corruptionFlags & CorruptionFlag::ETH_DEST_MAC_MISSING)
        corruptions << "Destination MAC missing";
    if (corruptionFlags & CorruptionFlag::ETH_SRC_MAC_MISSING)
        corruptions << "Source MAC missing";
    if (corruptionFlags & CorruptionFlag::ETH_TYPE_MISSING)
        corruptions << "EtherType missing";
    if (corruptionFlags & CorruptionFlag::ARP_INCOMPLETE)
        corruptions << "ARP packet incomplete";
    if (corruptionFlags & CorruptionFlag::IPV4_HEADER_INCOMPLETE)
        corruptions << "IPv4 header incomplete";
    if (corruptionFlags & CorruptionFlag::IPV4_ADDRESSES_MISSING)
        corruptions << "IPv4 addresses missing";
    if (corruptionFlags & CorruptionFlag::IPV6_HEADER_INCOMPLETE)
        corruptions << "IPv6 header incomplete";
    if (corruptionFlags & CorruptionFlag::IPV6_ADDRESSES_MISSING)
        corruptions << "IPv6 addresses missing";
    if (corruptionFlags & CorruptionFlag::TCP_HEADER_INCOMPLETE)
        corruptions << "TCP header incomplete";
    if (corruptionFlags & CorruptionFlag::UDP_HEADER_INCOMPLETE)
        corruptions << "UDP header incomplete";
    if (corruptionFlags & CorruptionFlag::ICMP_HEADER_INCOMPLETE)
        corruptions << "ICMP header incomplete";
    if (corruptionFlags & CorruptionFlag::PAYLOAD_MISSING)
        corruptions << "Payload missing";
    if (corruptionFlags & CorruptionFlag::PAYLOAD_TRUNCATED)
        corruptions << "Payload truncated";

    return corruptions.join(", ");
}
