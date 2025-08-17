#ifndef PACKETANALYZER_H
#define PACKETANALYZER_H

#include <QByteArray>
#include <QString>
#include <QDebug>
#include <QtEndian>
#include <cstdint>
#include <cstring>
#include <QList>
#include <QUdpSocket>
#include <QNetworkDatagram>

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

// Maximum expected packet size (standard MTU)
constexpr size_t MAX_PACKET_SIZE = 1500;

// Fill value for missing data
constexpr uint8_t MISSING_DATA_FILL = 0xFF;
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
    PAYLOAD_MISSING     = 0x00100000,
    PAYLOAD_TRUNCATED   = 0x00200000
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

    // Application layer payload
    QByteArray payload;
    size_t expectedPayloadSize = 0;  // Expected size based on IP total length
    bool payloadComplete = false;
};

struct UDPHeader {
    uint16_t src_port = 0xFFFF;
    uint16_t dest_port = 0xFFFF;
    uint16_t length = 0xFFFF;
    uint16_t checksum = 0xFFFF;
    bool isValid = false;

    // Application layer payload
    QByteArray payload;
    size_t expectedPayloadSize = 0;  // Expected size based on UDP length field
    bool payloadComplete = false;
};

struct ICMPHeader {
    uint8_t type = 0xFF;
    uint8_t code = 0xFF;
    uint16_t checksum = 0xFFFF;
    uint32_t rest_of_header = 0xFFFFFFFF;
    bool isValid = false;

    // ICMP data/payload
    QByteArray payload;
    size_t expectedPayloadSize = 0;
    bool payloadComplete = false;
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

    // Completed data (after padding)
    QByteArray completedData;

    // Helper methods
    bool hasCorruption() const { return corruptionFlags != CorruptionFlag::NONE; }
    bool isCorrupted(CorruptionFlag flag) const { return (corruptionFlags & flag); }
    QString getCorruptionString() const;
};

class PacketAnalyzer : public QObject {
    Q_OBJECT

private:
    QList<Frame> Packets;
    QUdpSocket* udpsocket;

public:
    PacketAnalyzer();

private:
    // Validation function - checks what parts are corrupted/missing
    CorruptionFlag validatePacket(const QByteArray& frameData);

    // Frame completion function - pads incomplete frames with 0xFF
    QByteArray completeFrame(const QByteArray& frameData, CorruptionFlag corruptionFlags);

    // Extraction function - extracts data and fills struct (even if corrupted)
    Frame extractFrame(const QByteArray& frameData);

    // Debug print functions
    void printFrame(const Frame& frame);
    void printTCPHeader(const TCPHeader& tcp);
    void printUDPHeader(const UDPHeader& udp);
    void printICMPHeader(const ICMPHeader& icmp);

    // Helper extraction functions
    void extractEthernet(Frame& frame, const uint8_t* data, size_t dataSize);
    void extractARP(ARPPacket& arp, const uint8_t* data, size_t dataSize);
    void extractIPv4(IPv4Packet& ipv4, const uint8_t* data, size_t dataSize);
    void extractIPv6(IPv6Packet& ipv6, const uint8_t* data, size_t dataSize);
    void extractTCP(TCPHeader& tcp, const uint8_t* data, size_t dataSize, size_t totalIPPayloadSize);
    void extractUDP(UDPHeader& udp, const uint8_t* data, size_t dataSize);
    void extractICMP(ICMPHeader& icmp, const uint8_t* data, size_t dataSize);

    // App engine
private slots:
    void handler();

signals:
    void recievedPacket(Frame frame);
};

#endif // PACKETANALYZER_H
