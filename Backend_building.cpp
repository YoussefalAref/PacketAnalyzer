#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <QByteArray>
#include <QString>
#include <QDebug>
#include <QtEndian>
#include <cstdint>
#include <cstring>

// Protocol type constants
namespace Protocol {
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;

// IP protocols
constexpr uint8_t IPPROTO_ICMP = 1;
constexpr uint8_t IPPROTO_TCP = 6;
constexpr uint8_t IPPROTO_UDP = 17;
constexpr uint8_t IPPROTO_ICMPV6 = 58;

// Minimum sizes
constexpr size_t ETH_HEADER_SIZE = 14;
constexpr size_t ARP_SIZE = 28;  // ARP packet size after Ethernet header
constexpr size_t IPV4_MIN_HEADER_SIZE = 20;
constexpr size_t IPV6_HEADER_SIZE = 40;
constexpr size_t TCP_MIN_HEADER_SIZE = 20;
constexpr size_t UDP_HEADER_SIZE = 8;
constexpr size_t ICMP_HEADER_SIZE = 8;
}

// Corruption flags - indicates which part is corrupted/missing
enum class CorruptionFlag : uint32_t {
    NONE                = 0x00000000,
    ETH_HEADER_MISSING  = 0x00000001,
    ETH_DEST_MAC_MISSING = 0x00000002,
    ETH_SRC_MAC_MISSING = 0x00000004,
    ETH_TYPE_MISSING    = 0x00000008,

    // ARP corruption
    ARP_INCOMPLETE      = 0x00000010,

    // IPv4 corruption
    IPV4_HEADER_INCOMPLETE = 0x00000100,
    IPV4_ADDRESSES_MISSING = 0x00000200,

    // IPv6 corruption
    IPV6_HEADER_INCOMPLETE = 0x00001000,
    IPV6_ADDRESSES_MISSING = 0x00002000,

    // Transport layer corruption
    TCP_HEADER_INCOMPLETE = 0x00010000,
    UDP_HEADER_INCOMPLETE = 0x00020000,
    ICMP_HEADER_INCOMPLETE = 0x00040000,

    // Payload corruption
    PAYLOAD_MISSING     = 0x00100000
};

// Allow bitwise operations
inline CorruptionFlag operator|(CorruptionFlag a, CorruptionFlag b) {
    return static_cast<CorruptionFlag>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline CorruptionFlag& operator|=(CorruptionFlag& a, CorruptionFlag b) {
    return a = a | b;
}

inline bool operator&(CorruptionFlag a, CorruptionFlag b) {
    return (static_cast<uint32_t>(a) & static_cast<uint32_t>(b)) != 0;
}

// Structure definitions matching the C program
struct TCPHeader {
    uint16_t src_port = 0xFFFF;     // -1 indicates not set
    uint16_t dest_port = 0xFFFF;
    uint32_t seq_num = 0xFFFFFFFF;
    uint32_t ack_num = 0xFFFFFFFF;
    uint8_t data_offset = 0xFF;
    uint16_t flags = 0xFFFF;
    uint16_t window_size = 0xFFFF;
    uint16_t checksum = 0xFFFF;
    uint16_t urgent_pointer = 0xFFFF;
    bool isValid = false;
};

struct UDPHeader {
    uint16_t src_port = 0xFFFF;
    uint16_t dest_port = 0xFFFF;
    uint16_t length = 0xFFFF;
    uint16_t checksum = 0xFFFF;
    bool isValid = false;
};

struct ICMPHeader {
    uint8_t type = 0xFF;
    uint8_t code = 0xFF;
    uint16_t checksum = 0xFFFF;
    uint32_t rest_of_header = 0xFFFFFFFF;
    bool isValid = false;
};

struct ARPPacket {
    uint16_t hardware_type = 0xFFFF;
    uint16_t protocol_type = 0xFFFF;
    uint8_t hardware_size = 0xFF;
    uint8_t protocol_size = 0xFF;
    uint16_t opcode = 0xFFFF;
    uint8_t sender_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t sender_ip = 0xFFFFFFFF;
    uint8_t target_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t target_ip = 0xFFFFFFFF;
    bool isValid = false;
};

struct IPv4Packet {
    uint8_t ihl = 0xFF;
    uint8_t tos = 0xFF;
    uint16_t total_length = 0xFFFF;
    uint16_t id = 0xFFFF;
    uint16_t flags = 0xFFFF;
    uint8_t ttl = 0xFF;
    uint8_t protocol = 0xFF;
    uint16_t checksum = 0xFFFF;
    uint32_t src_ip = 0xFFFFFFFF;
    uint32_t dest_ip = 0xFFFFFFFF;
    bool isValid = false;

    // Transport layer - only one will be valid
    TCPHeader tcp;
    UDPHeader udp;
    ICMPHeader icmp;
};

struct IPv6Packet {
    uint32_t version_traffic_class_flow_label = 0xFFFFFFFF;
    uint16_t payload_length = 0xFFFF;
    uint8_t next_header = 0xFF;
    uint8_t hop_limit = 0xFF;
    uint8_t src_ip[16];
    uint8_t dest_ip[16];
    bool isValid = false;

    // Transport layer - only one will be valid
    TCPHeader tcp;
    UDPHeader udp;
    ICMPHeader icmp;

    IPv6Packet() {
        memset(src_ip, 0xFF, 16);
        memset(dest_ip, 0xFF, 16);
    }
};

struct Frame {
    // Ethernet header
    uint8_t dest[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t src[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint16_t type = 0xFFFF;

    // Payload - only one will be valid
    ARPPacket arp;
    IPv4Packet ipv4;
    IPv6Packet ipv6;

    // Corruption tracking
    CorruptionFlag corruptionFlags = CorruptionFlag::NONE;

    // Raw data
    QByteArray rawData;

    // Helper methods
    bool hasCorruption() const { return corruptionFlags != CorruptionFlag::NONE; }
    bool isCorrupted(CorruptionFlag flag) const { return (corruptionFlags & flag); }
    QString getCorruptionString() const;
};

class PacketAnalyzer {
public:
    // Validation function - checks what parts are corrupted/missing
    static CorruptionFlag validatePacket(const QByteArray& frameData);

    // Extraction function - extracts data and fills struct (even if corrupted)
    static Frame extractFrame(const QByteArray& frameData);

    // Debug print functions
    static void printFrame(const Frame& frame);
    static void printTCPHeader(const TCPHeader& tcp);
    static void printUDPHeader(const UDPHeader& udp);
    static void printICMPHeader(const ICMPHeader& icmp);

private:
    // Helper extraction functions
    static void extractEthernet(Frame& frame, const uint8_t* data, size_t dataSize);
    static void extractARP(ARPPacket& arp, const uint8_t* data, size_t dataSize);
    static void extractIPv4(IPv4Packet& ipv4, const uint8_t* data, size_t dataSize);
    static void extractIPv6(IPv6Packet& ipv6, const uint8_t* data, size_t dataSize);
    static void extractTCP(TCPHeader& tcp, const uint8_t* data, size_t dataSize);
    static void extractUDP(UDPHeader& udp, const uint8_t* data, size_t dataSize);
    static void extractICMP(ICMPHeader& icmp, const uint8_t* data, size_t dataSize);
};

// ==================== IMPLEMENTATION ====================

CorruptionFlag PacketAnalyzer::validatePacket(const QByteArray& frameData) {
    CorruptionFlag flags = CorruptionFlag::NONE;
    size_t dataSize = frameData.size();

    // Check Ethernet header
    if (dataSize < Protocol::ETH_HEADER_SIZE) {
        flags |= CorruptionFlag::ETH_HEADER_MISSING;
        return flags; // If Ethernet header is missing, everything else is missing too
    }

    // Check if we have complete Ethernet header parts
    if (dataSize < 6) {
        flags |= CorruptionFlag::ETH_DEST_MAC_MISSING;
        return flags;
    }
    if (dataSize < 12) {
        flags |= CorruptionFlag::ETH_SRC_MAC_MISSING;
        return flags;
    }
    if (dataSize < 14) {
        flags |= CorruptionFlag::ETH_TYPE_MISSING;
        return flags;
    }

    // Get EtherType
    const uint8_t* data = reinterpret_cast<const uint8_t*>(frameData.constData());
    uint16_t etherType = qFromBigEndian<uint16_t>(data + 12);

    // Check payload based on EtherType
    switch (etherType) {
    case Protocol::ETHERTYPE_ARP:
        if (dataSize < Protocol::ETH_HEADER_SIZE + Protocol::ARP_SIZE) {
            flags |= CorruptionFlag::ARP_INCOMPLETE;
        }
        break;

    case Protocol::ETHERTYPE_IPV4: {
        if (dataSize < Protocol::ETH_HEADER_SIZE + Protocol::IPV4_MIN_HEADER_SIZE) {
            flags |= CorruptionFlag::IPV4_HEADER_INCOMPLETE;
            break;
        }

        // Get actual IPv4 header length
        uint8_t ihl = (data[14] & 0x0F) * 4;
        if (ihl < Protocol::IPV4_MIN_HEADER_SIZE ||
            dataSize < Protocol::ETH_HEADER_SIZE + ihl) {
            flags |= CorruptionFlag::IPV4_HEADER_INCOMPLETE;
            break;
        }

        // Check if IP addresses are present
        if (dataSize < Protocol::ETH_HEADER_SIZE + 20) {
            flags |= CorruptionFlag::IPV4_ADDRESSES_MISSING;
            break;
        }

        // Check transport protocol
        uint8_t protocol = data[23]; // Protocol field in IPv4 header
        size_t transportOffset = Protocol::ETH_HEADER_SIZE + ihl;

        switch (protocol) {
        case Protocol::IPPROTO_TCP:
            if (dataSize < transportOffset + Protocol::TCP_MIN_HEADER_SIZE) {
                flags |= CorruptionFlag::TCP_HEADER_INCOMPLETE;
            }
            break;
        case Protocol::IPPROTO_UDP:
            if (dataSize < transportOffset + Protocol::UDP_HEADER_SIZE) {
                flags |= CorruptionFlag::UDP_HEADER_INCOMPLETE;
            }
            break;
        case Protocol::IPPROTO_ICMP:
            if (dataSize < transportOffset + Protocol::ICMP_HEADER_SIZE) {
                flags |= CorruptionFlag::ICMP_HEADER_INCOMPLETE;
            }
            break;
        }
        break;
    }

    case Protocol::ETHERTYPE_IPV6: {
        if (dataSize < Protocol::ETH_HEADER_SIZE + Protocol::IPV6_HEADER_SIZE) {
            flags |= CorruptionFlag::IPV6_HEADER_INCOMPLETE;
            break;
        }

        // Check if IPv6 addresses are complete
        if (dataSize < Protocol::ETH_HEADER_SIZE + 40) {
            flags |= CorruptionFlag::IPV6_ADDRESSES_MISSING;
            break;
        }

        // Check transport protocol
        uint8_t nextHeader = data[20]; // Next Header field in IPv6
        size_t transportOffset = Protocol::ETH_HEADER_SIZE + Protocol::IPV6_HEADER_SIZE;

        switch (nextHeader) {
        case Protocol::IPPROTO_TCP:
            if (dataSize < transportOffset + Protocol::TCP_MIN_HEADER_SIZE) {
                flags |= CorruptionFlag::TCP_HEADER_INCOMPLETE;
            }
            break;
        case Protocol::IPPROTO_UDP:
            if (dataSize < transportOffset + Protocol::UDP_HEADER_SIZE) {
                flags |= CorruptionFlag::UDP_HEADER_INCOMPLETE;
            }
            break;
        case Protocol::IPPROTO_ICMPV6:
            if (dataSize < transportOffset + Protocol::ICMP_HEADER_SIZE) {
                flags |= CorruptionFlag::ICMP_HEADER_INCOMPLETE;
            }
            break;
        }
        break;
    }
    }

    return flags;
}

Frame PacketAnalyzer::extractFrame(const QByteArray& frameData) {
    Frame frame;
    frame.rawData = frameData;

    // First validate to know what's corrupted
    frame.corruptionFlags = validatePacket(frameData);

    const uint8_t* data = reinterpret_cast<const uint8_t*>(frameData.constData());
    size_t dataSize = frameData.size();

    // Extract Ethernet header (if present)
    if (!(frame.corruptionFlags & CorruptionFlag::ETH_HEADER_MISSING)) {
        extractEthernet(frame, data, dataSize);

        // Extract payload based on EtherType
        if (frame.type != 0xFFFF) {
            switch (frame.type) {
            case Protocol::ETHERTYPE_ARP:
                if (!(frame.corruptionFlags & CorruptionFlag::ARP_INCOMPLETE)) {
                    extractARP(frame.arp, data + 14, dataSize - 14);
                }
                break;

            case Protocol::ETHERTYPE_IPV4:
                if (!(frame.corruptionFlags & CorruptionFlag::IPV4_HEADER_INCOMPLETE)) {
                    extractIPv4(frame.ipv4, data + 14, dataSize - 14);
                }
                break;

            case Protocol::ETHERTYPE_IPV6:
                if (!(frame.corruptionFlags & CorruptionFlag::IPV6_HEADER_INCOMPLETE)) {
                    extractIPv6(frame.ipv6, data + 14, dataSize - 14);
                }
                break;
            }
        }
    }

    return frame;
}

void PacketAnalyzer::extractEthernet(Frame& frame, const uint8_t* data, size_t dataSize) {
    if (dataSize >= 6) {
        memcpy(frame.dest, data, 6);
    }
    if (dataSize >= 12) {
        memcpy(frame.src, data + 6, 6);
    }
    if (dataSize >= 14) {
        frame.type = qFromBigEndian<uint16_t>(data + 12);
    }
}

void PacketAnalyzer::extractARP(ARPPacket& arp, const uint8_t* data, size_t dataSize) {
    if (dataSize < Protocol::ARP_SIZE) return;

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

void PacketAnalyzer::extractIPv4(IPv4Packet& ipv4, const uint8_t* data, size_t dataSize) {
    if (dataSize < Protocol::IPV4_MIN_HEADER_SIZE) return;

    ipv4.ihl = (data[0] & 0x0F) * 4;
    ipv4.tos = data[1];
    ipv4.total_length = qFromBigEndian<uint16_t>(data + 2);
    ipv4.id = qFromBigEndian<uint16_t>(data + 4);
    ipv4.flags = qFromBigEndian<uint16_t>(data + 6);
    ipv4.ttl = data[8];
    ipv4.protocol = data[9];
    ipv4.checksum = qFromBigEndian<uint16_t>(data + 10);

    if (dataSize >= 20) {
        ipv4.src_ip = qFromBigEndian<uint32_t>(data + 12);
        ipv4.dest_ip = qFromBigEndian<uint32_t>(data + 16);
    }

    ipv4.isValid = true;

    // Extract transport layer if present
    if (ipv4.ihl != 0xFF && dataSize >= ipv4.ihl) {
        const uint8_t* transportData = data + ipv4.ihl;
        size_t transportSize = dataSize - ipv4.ihl;

        switch (ipv4.protocol) {
        case Protocol::IPPROTO_TCP:
            extractTCP(ipv4.tcp, transportData, transportSize);
            break;
        case Protocol::IPPROTO_UDP:
            extractUDP(ipv4.udp, transportData, transportSize);
            break;
        case Protocol::IPPROTO_ICMP:
            extractICMP(ipv4.icmp, transportData, transportSize);
            break;
        }
    }
}

void PacketAnalyzer::extractIPv6(IPv6Packet& ipv6, const uint8_t* data, size_t dataSize) {
    if (dataSize < Protocol::IPV6_HEADER_SIZE) return;

    ipv6.version_traffic_class_flow_label = qFromBigEndian<uint32_t>(data);
    ipv6.payload_length = qFromBigEndian<uint16_t>(data + 4);
    ipv6.next_header = data[6];
    ipv6.hop_limit = data[7];

    if (dataSize >= 40) {
        memcpy(ipv6.src_ip, data + 8, 16);
        memcpy(ipv6.dest_ip, data + 24, 16);
    }

    ipv6.isValid = true;

    // Extract transport layer if present
    if (dataSize >= Protocol::IPV6_HEADER_SIZE) {
        const uint8_t* transportData = data + Protocol::IPV6_HEADER_SIZE;
        size_t transportSize = dataSize - Protocol::IPV6_HEADER_SIZE;

        switch (ipv6.next_header) {
        case Protocol::IPPROTO_TCP:
            extractTCP(ipv6.tcp, transportData, transportSize);
            break;
        case Protocol::IPPROTO_UDP:
            extractUDP(ipv6.udp, transportData, transportSize);
            break;
        case Protocol::IPPROTO_ICMPV6:
            extractICMP(ipv6.icmp, transportData, transportSize);
            break;
        }
    }
}

void PacketAnalyzer::extractTCP(TCPHeader& tcp, const uint8_t* data, size_t dataSize) {
    if (dataSize < Protocol::TCP_MIN_HEADER_SIZE) return;

    tcp.src_port = qFromBigEndian<uint16_t>(data);
    tcp.dest_port = qFromBigEndian<uint16_t>(data + 2);
    tcp.seq_num = qFromBigEndian<uint32_t>(data + 4);
    tcp.ack_num = qFromBigEndian<uint32_t>(data + 8);

    uint16_t dof = qFromBigEndian<uint16_t>(data + 12);
    tcp.data_offset = (dof >> 12) * 4;
    tcp.flags = dof & 0x01FF;

    tcp.window_size = qFromBigEndian<uint16_t>(data + 14);
    tcp.checksum = qFromBigEndian<uint16_t>(data + 16);
    tcp.urgent_pointer = qFromBigEndian<uint16_t>(data + 18);

    tcp.isValid = true;
}

void PacketAnalyzer::extractUDP(UDPHeader& udp, const uint8_t* data, size_t dataSize) {
    if (dataSize < Protocol::UDP_HEADER_SIZE) return;

    udp.src_port = qFromBigEndian<uint16_t>(data);
    udp.dest_port = qFromBigEndian<uint16_t>(data + 2);
    udp.length = qFromBigEndian<uint16_t>(data + 4);
    udp.checksum = qFromBigEndian<uint16_t>(data + 6);

    udp.isValid = true;
}

void PacketAnalyzer::extractICMP(ICMPHeader& icmp, const uint8_t* data, size_t dataSize) {
    if (dataSize < Protocol::ICMP_HEADER_SIZE) return;

    icmp.type = data[0];
    icmp.code = data[1];
    icmp.checksum = qFromBigEndian<uint16_t>(data + 2);
    icmp.rest_of_header = qFromBigEndian<uint32_t>(data + 4);

    icmp.isValid = true;
}

// Debug print functions
void PacketAnalyzer::printTCPHeader(const TCPHeader& tcp) {
    if (!tcp.isValid) {
        qDebug() << "TCP Header: INVALID/MISSING";
        return;
    }

    qDebug() << "TCP Header:";
    qDebug() << "  Source Port:" << (tcp.src_port != 0xFFFF ? QString::number(tcp.src_port) : "N/A");
    qDebug() << "  Destination Port:" << (tcp.dest_port != 0xFFFF ? QString::number(tcp.dest_port) : "N/A");
    qDebug() << "  Sequence Number:" << (tcp.seq_num != 0xFFFFFFFF ? QString::number(tcp.seq_num) : "N/A");
    qDebug() << "  Acknowledgment Number:" << (tcp.ack_num != 0xFFFFFFFF ? QString::number(tcp.ack_num) : "N/A");
    qDebug() << "  Data Offset:" << (tcp.data_offset != 0xFF ? QString::number(tcp.data_offset) : "N/A");
    qDebug() << "  Flags:" << QString("0x%1").arg(tcp.flags != 0xFFFF ? tcp.flags : 0, 3, 16, QChar('0'));
    qDebug() << "  Window Size:" << (tcp.window_size != 0xFFFF ? QString::number(tcp.window_size) : "N/A");
    qDebug() << "  Checksum:" << QString("0x%1").arg(tcp.checksum, 4, 16, QChar('0'));
    qDebug() << "  Urgent Pointer:" << (tcp.urgent_pointer != 0xFFFF ? QString::number(tcp.urgent_pointer) : "N/A");
}

void PacketAnalyzer::printUDPHeader(const UDPHeader& udp) {
    if (!udp.isValid) {
        qDebug() << "UDP Header: INVALID/MISSING";
        return;
    }

    qDebug() << "UDP Header:";
    qDebug() << "  Source Port:" << (udp.src_port != 0xFFFF ? QString::number(udp.src_port) : "N/A");
    qDebug() << "  Destination Port:" << (udp.dest_port != 0xFFFF ? QString::number(udp.dest_port) : "N/A");
    qDebug() << "  Length:" << (udp.length != 0xFFFF ? QString::number(udp.length) : "N/A");
    qDebug() << "  Checksum:" << QString("0x%1").arg(udp.checksum, 4, 16, QChar('0'));
}

void PacketAnalyzer::printICMPHeader(const ICMPHeader& icmp) {
    if (!icmp.isValid) {
        qDebug() << "ICMP Header: INVALID/MISSING";
        return;
    }

    qDebug() << "ICMP Header:";
    qDebug() << "  Type:" << (icmp.type != 0xFF ? QString::number(icmp.type) : "N/A");
    qDebug() << "  Code:" << (icmp.code != 0xFF ? QString::number(icmp.code) : "N/A");
    qDebug() << "  Checksum:" << QString("0x%1").arg(icmp.checksum, 4, 16, QChar('0'));
    qDebug() << "  Rest of Header:" << QString("0x%1").arg(icmp.rest_of_header, 8, 16, QChar('0'));
}

void PacketAnalyzer::printFrame(const Frame& frame) {
    qDebug() << "\n=== Frame Content ===";

    // Print corruption status
    if (frame.hasCorruption()) {
        qDebug() << "CORRUPTION DETECTED:" << frame.getCorruptionString();
    } else {
        qDebug() << "Frame Status: COMPLETE";
    }

    // Print Ethernet header
    QString destMac = QString("%1:%2:%3:%4:%5:%6")
                          .arg(frame.dest[0], 2, 16, QChar('0'))
                          .arg(frame.dest[1], 2, 16, QChar('0'))
                          .arg(frame.dest[2], 2, 16, QChar('0'))
                          .arg(frame.dest[3], 2, 16, QChar('0'))
                          .arg(frame.dest[4], 2, 16, QChar('0'))
                          .arg(frame.dest[5], 2, 16, QChar('0'));

    QString srcMac = QString("%1:%2:%3:%4:%5:%6")
                         .arg(frame.src[0], 2, 16, QChar('0'))
                         .arg(frame.src[1], 2, 16, QChar('0'))
                         .arg(frame.src[2], 2, 16, QChar('0'))
                         .arg(frame.src[3], 2, 16, QChar('0'))
                         .arg(frame.src[4], 2, 16, QChar('0'))
                         .arg(frame.src[5], 2, 16, QChar('0'));

    qDebug() << "Destination MAC:" << (frame.dest[0] != 0xFF ? destMac : "N/A");
    qDebug() << "Source MAC:" << (frame.src[0] != 0xFF ? srcMac : "N/A");
    qDebug() << "EtherType:" << QString("0x%1").arg(frame.type != 0xFFFF ? frame.type : 0, 4, 16, QChar('0'));

    // Print payload based on type
    switch (frame.type) {
    case Protocol::ETHERTYPE_ARP:
        qDebug() << "\nPayload: ARP";
        if (frame.arp.isValid) {
            qDebug() << "  Hardware Type:" << QString("0x%1").arg(frame.arp.hardware_type, 4, 16, QChar('0'));
            qDebug() << "  Protocol Type:" << QString("0x%1").arg(frame.arp.protocol_type, 4, 16, QChar('0'));
            qDebug() << "  Hardware Size:" << frame.arp.hardware_size;
            qDebug() << "  Protocol Size:" << frame.arp.protocol_size;
            qDebug() << "  Opcode:" << QString("0x%1").arg(frame.arp.opcode, 4, 16, QChar('0'));

            QString senderMac = QString("%1:%2:%3:%4:%5:%6")
                                    .arg(frame.arp.sender_mac[0], 2, 16, QChar('0'))
                                    .arg(frame.arp.sender_mac[1], 2, 16, QChar('0'))
                                    .arg(frame.arp.sender_mac[2], 2, 16, QChar('0'))
                                    .arg(frame.arp.sender_mac[3], 2, 16, QChar('0'))
                                    .arg(frame.arp.sender_mac[4], 2, 16, QChar('0'))
                                    .arg(frame.arp.sender_mac[5], 2, 16, QChar('0'));

            QString targetMac = QString("%1:%2:%3:%4:%5:%6")
                                    .arg(frame.arp.target_mac[0], 2, 16, QChar('0'))
                                    .arg(frame.arp.target_mac[1], 2, 16, QChar('0'))
                                    .arg(frame.arp.target_mac[2], 2, 16, QChar('0'))
                                    .arg(frame.arp.target_mac[3], 2, 16, QChar('0'))
                                    .arg(frame.arp.target_mac[4], 2, 16, QChar('0'))
                                    .arg(frame.arp.target_mac[5], 2, 16, QChar('0'));

            qDebug() << "  Sender MAC:" << senderMac;
            qDebug() << "  Target MAC:" << targetMac;

            // Convert IPs to readable format
            QHostAddress senderIp(frame.arp.sender_ip);
            QHostAddress targetIp(frame.arp.target_ip);
            qDebug() << "  Sender IP:" << senderIp.toString();
            qDebug() << "  Target IP:" << targetIp.toString();
        } else {
            qDebug() << "  ARP packet is incomplete/invalid";
        }
        break;

    case Protocol::ETHERTYPE_IPV4:
        qDebug() << "\nPayload: IPv4";
        if (frame.ipv4.isValid) {
            qDebug() << "  IHL:" << frame.ipv4.ihl;
            qDebug() << "  TOS:" << frame.ipv4.tos;
            qDebug() << "  Total Length:" << frame.ipv4.total_length;
            qDebug() << "  ID:" << frame.ipv4.id;
            qDebug() << "  Flags:" << QString("0x%1").arg(frame.ipv4.flags, 4, 16, QChar('0'));
            qDebug() << "  TTL:" << frame.ipv4.ttl;
            qDebug() << "  Protocol:" << frame.ipv4.protocol;
            qDebug() << "  Checksum:" << QString("0x%1").arg(frame.ipv4.checksum, 4, 16, QChar('0'));

            QHostAddress srcIp(frame.ipv4.src_ip);
            QHostAddress destIp(frame.ipv4.dest_ip);
            qDebug() << "  Source IP:" << (frame.ipv4.src_ip != 0xFFFFFFFF ? srcIp.toString() : "N/A");
            qDebug() << "  Destination IP:" << (frame.ipv4.dest_ip != 0xFFFFFFFF ? destIp.toString() : "N/A");

            // Print transport layer
            switch (frame.ipv4.protocol) {
            case Protocol::IPPROTO_TCP:
                printTCPHeader(frame.ipv4.tcp);
                break;
            case Protocol::IPPROTO_UDP:
                printUDPHeader(frame.ipv4.udp);
                break;
            case Protocol::IPPROTO_ICMP:
                printICMPHeader(frame.ipv4.icmp);
                break;
            default:
                if (frame.ipv4.protocol != 0xFF) {
                    qDebug() << "  Unknown transport protocol:" << frame.ipv4.protocol;
                }
                break;
            }
        } else {
            qDebug() << "  IPv4 packet is incomplete/invalid";
        }
        break;

    case Protocol::ETHERTYPE_IPV6:
        qDebug() << "\nPayload: IPv6";
        if (frame.ipv6.isValid) {
            qDebug() << "  Version/Traffic/Flow:" << QString("0x%1").arg(frame.ipv6.version_traffic_class_flow_label, 8, 16, QChar('0'));
            qDebug() << "  Payload Length:" << frame.ipv6.payload_length;
            qDebug() << "  Next Header:" << frame.ipv6.next_header;
            qDebug() << "  Hop Limit:" << frame.ipv6.hop_limit;

            // Convert IPv6 addresses
            QHostAddress srcIpv6(frame.ipv6.src_ip);
            QHostAddress destIpv6(frame.ipv6.dest_ip);
            qDebug() << "  Source IP:" << srcIpv6.toString();
            qDebug() << "  Destination IP:" << destIpv6.toString();

            // Print transport layer
            switch (frame.ipv6.next_header) {
            case Protocol::IPPROTO_TCP:
                printTCPHeader(frame.ipv6.tcp);
                break;
            case Protocol::IPPROTO_UDP:
                printUDPHeader(frame.ipv6.udp);
                break;
            case Protocol::IPPROTO_ICMPV6:
                printICMPHeader(frame.ipv6.icmp);
                break;
            default:
                if (frame.ipv6.next_header != 0xFF) {
                    qDebug() << "  Unknown transport protocol:" << frame.ipv6.next_header;
                }
                break;
            }
        } else {
            qDebug() << "  IPv6 packet is incomplete/invalid";
        }
        break;

    default:
        if (frame.type != 0xFFFF) {
            qDebug() << "Unknown frame type:" << QString("0x%1").arg(frame.type, 4, 16, QChar('0'));
        }
        break;
    }

    qDebug() << "===================\n";
}

QString Frame::getCorruptionString() const {
    if (corruptionFlags == CorruptionFlag::NONE) {
        return "No corruption detected";
    }

    QStringList errors;

    if (corruptionFlags & CorruptionFlag::ETH_HEADER_MISSING)
        errors << "Ethernet header missing";
    if (corruptionFlags & CorruptionFlag::ETH_DEST_MAC_MISSING)
        errors << "Ethernet destination MAC missing";
    if (corruptionFlags & CorruptionFlag::ETH_SRC_MAC_MISSING)
        errors << "Ethernet source MAC missing";
    if (corruptionFlags & CorruptionFlag::ETH_TYPE_MISSING)
        errors << "Ethernet type field missing";
    if (corruptionFlags & CorruptionFlag::ARP_INCOMPLETE)
        errors << "ARP packet incomplete";
    if (corruptionFlags & CorruptionFlag::IPV4_HEADER_INCOMPLETE)
        errors << "IPv4 header incomplete";
    if (corruptionFlags & CorruptionFlag::IPV4_ADDRESSES_MISSING)
        errors << "IPv4 addresses missing";
    if (corruptionFlags & CorruptionFlag::IPV6_HEADER_INCOMPLETE)
        errors << "IPv6 header incomplete";
    if (corruptionFlags & CorruptionFlag::IPV6_ADDRESSES_MISSING)
        errors << "IPv6 addresses missing";
    if (corruptionFlags & CorruptionFlag::TCP_HEADER_INCOMPLETE)
        errors << "TCP header incomplete";
    if (corruptionFlags & CorruptionFlag::UDP_HEADER_INCOMPLETE)
        errors << "UDP header incomplete";
    if (corruptionFlags & CorruptionFlag::ICMP_HEADER_INCOMPLETE)
        errors << "ICMP header incomplete";
    if (corruptionFlags & CorruptionFlag::PAYLOAD_MISSING)
        errors << "Payload missing";

    return errors.join(", ");
}

