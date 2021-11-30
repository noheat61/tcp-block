#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final
{
    uint16_t sport_;
    uint16_t dport_;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;

    uint16_t sport() { return ntohs(sport_); }
    uint16_t dport() { return ntohs(dport_); }
    uint8_t offset() { return (offset_reserved & 0xF0) >> 4; }
    uint8_t reserved() { return offset_reserved & 0x0F; }

    enum : uint8_t
    {
        Urg = 0x20,
        Ack = 0x10,
        Psh = 0x08,
        Rst = 0x04,
        Syn = 0x02,
        Fin = 0x01
    };
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)