from scapy.all import rdpcap

# Read the pcap file from the current working folder
pcap_file = "capture1.pcap"
packets = rdpcap(pcap_file)

# Print the total number of packets
print(f"Total packets: {len(packets)}")

# Print every packet with all decoded protocol details
for i, packet in enumerate(packets[:5], start=1):
    print(f"\n========== Packet {i} ==========")
    packet.show()