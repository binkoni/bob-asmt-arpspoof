project(arpspoof)
add_executable(arpspoof)
target_sources(arpspoof PRIVATE arpspoof.cpp Pdu.cpp EthPdu.cpp Ip4Pdu.cpp TcpPdu.cpp ArpPdu.cpp RawPdu.cpp Utils.cpp Ip4Addr.cpp MacAddr.cpp PacketBuilder.cpp Packet.cpp)
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
