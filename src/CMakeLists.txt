project(arpspoof)
add_executable(arpspoof)
target_sources(arpspoof PRIVATE arpspoof.cpp Packet.cpp EthPacket.cpp IpPacket.cpp TcpPacket.cpp ArpPacket.cpp UnknownPacket.cpp Utils.cpp IpAddr.cpp MacAddr.cpp PacketBuilder.cpp)
target_compile_options(arpspoof PRIVATE -Wall)

set_target_properties(
    arpspoof
    PROPERTIES
    CXX_STANDARD 17
)

target_link_libraries(
    arpspoof
    pcap
)

install(
    TARGETS arpspoof
    RUNTIME DESTINATION bin
)
