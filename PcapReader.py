from scapy.all import PcapReader

pcap_file = "capture1.pcap"

with PcapReader(pcap_file) as pcap:
    for i, packet in enumerate(pcap, start=1):
        print(f"\n========== Packet {i} ==========")
        packet.show()

        if i == 1:
            break

print("Finished reading first 5 packets.")


