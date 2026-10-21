
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
from scapy.utils import PcapReader
from scapy.layers.dot11 import Dot11


# ==================================================
# CONFIGURATION
# ==================================================

PCAP_FILE = Path(
    "capture1.pcap"
)

OUTPUT_DIR = Path("output")
BIN_SECONDS = 1.0

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ==================================================
# ANALYZE PCAP
# ==================================================

records = []

if not PCAP_FILE.is_file():
    raise FileNotFoundError(f"PCAP file not found: {PCAP_FILE}")

print(f"Reading PCAP: {PCAP_FILE}")

with PcapReader(str(PCAP_FILE)) as capture:
    for packet in capture:

        # Only analyze decoded 802.11 frames
        if not packet.haslayer(Dot11):
            continue

        dot11 = packet.getlayer(Dot11)

        # Frame type 2 = 802.11 Data
        if int(dot11.type) != 2:
            continue

        timestamp = float(packet.time)

        # Length of 802.11 MAC frame, excluding Radiotap
        frame_bytes = len(bytes(dot11))

        # Retry flag: bit 3 of FCfield
        fcfield = int(dot11.FCfield)

        is_retry = bool(fcfield & 0x08)


        # Sequence and fragment numbers
        sequence_control = int(dot11.SC)
        sequence_number = (sequence_control >> 4) & 0x0FFF
        fragment_number = sequence_control & 0x0F

        records.append({
            "timestamp": timestamp,
            "frame_bytes": frame_bytes,
            "is_retry": is_retry,
            "subtype": int(dot11.subtype),
            "transmitter": dot11.addr2 or "",
            "receiver": dot11.addr1 or "",
            "bssid": dot11.addr3 or "",
            "sequence_number": sequence_number,
            "fragment_number": fragment_number,
        })


if not records:
    raise ValueError(
        "No 802.11 data frames found in the PCAP."
    )


# ==================================================
# PROCESS DATA
# ==================================================

df = pd.DataFrame(records)

# Time relative to first captured data frame
df["time_s"] = df["timestamp"] - df["timestamp"].min()

# Assign packets to 1-second bins
df["time_bin"] = (
    df["time_s"] // BIN_SECONDS
).astype(int)

# Total captured bytes per second
throughput = (
    df.groupby("time_bin")
    .agg(
        captured_bytes=("frame_bytes", "sum"),
        data_frames=("frame_bytes", "count"),
        retry_frames=("is_retry", "sum"),
    )
    .reset_index()
)

# Include empty seconds between the first and last data frames
throughput = (
    throughput.set_index("time_bin")
    .reindex(
        range(int(df["time_bin"].max()) + 1),
        fill_value=0,
    )
    .rename_axis("time_bin")
    .reset_index()
)

throughput["time_s"] = (
    throughput["time_bin"] * BIN_SECONDS
)

# Calculate captured 802.11 MAC-frame throughput in Mbps
throughput["throughput_mbps"] = (
    throughput["captured_bytes"] * 8
    / BIN_SECONDS / 1_000_000
)

# Retry-excluded throughput estimate
non_retry = df[~df["is_retry"]].groupby("time_bin")[
    "frame_bytes"
].sum()

throughput["non_retry_bytes"] = (
    throughput["time_bin"].map(non_retry).fillna(0)
)

throughput["non_retry_mbps"] = (
    throughput["non_retry_bytes"] * 8
    / BIN_SECONDS / 1_000_000
)

throughput["retry_rate_pct"] = (
    throughput["retry_frames"]
    / throughput["data_frames"].replace(0, float("nan"))
    * 100
).fillna(0)


# ==================================================
# SAVE CSV REPORTS
# ==================================================

df.to_csv(OUTPUT_DIR / "frame_details.csv", index=False)

throughput.to_csv(
    OUTPUT_DIR / "throughput_by_second.csv",
    index=False,
)

total_frames = len(df)
total_retries = int(df["is_retry"].sum())
duration_s = float(df["time_s"].max())

summary = pd.DataFrame([{
    "file": PCAP_FILE.name,
    "data_frames": total_frames,
    "retry_frames": total_retries,
    "retry_rate_pct": (
        total_retries / total_frames * 100
    ),
    "duration_s": duration_s,
    "total_mac_bytes": int(df["frame_bytes"].sum()),
}])

summary.to_csv(OUTPUT_DIR / "summary.csv", index=False)


# ==================================================
# PLOT 1: THROUGHPUT VS TIME
# ==================================================

plt.figure(figsize=(12, 5))

plt.plot(
    throughput["time_s"],
    throughput["throughput_mbps"],
    marker=".",
    linewidth=1.2,
    label="All captured data frames",
)

plt.plot(
    throughput["time_s"],
    throughput["non_retry_mbps"],
    linewidth=1.2,
    label="Retry-excluded estimate",
)

plt.xlabel("Time (seconds)")
plt.ylabel("Throughput (Mbps)")
plt.title(f"802.11 Data-Frame Throughput: {PCAP_FILE.name}")
plt.grid(True, alpha=0.3)
plt.legend()
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "throughput.png",
    dpi=150,
)
plt.show()


# ==================================================
# PLOT 2: RETRY RATE VS TIME
# ==================================================

plt.figure(figsize=(12, 4))

plt.plot(
    throughput["time_s"],
    throughput["retry_rate_pct"],
    marker=".",
    linewidth=1.2,
)

plt.xlabel("Time (seconds)")
plt.ylabel("Retry frames (%)")
plt.title("802.11 Data-Frame Retry Rate")
plt.grid(True, alpha=0.3)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "retry_rate.png",
    dpi=150,
)
plt.show()


# ==================================================
# SUMMARY
# ==================================================

print("\nAnalysis complete")
print(f"PCAP: {PCAP_FILE}")
print(f"Data frames: {total_frames}")
print(f"Retry frames: {total_retries}")
print(f"Retry rate: {total_retries / total_frames * 100:.2f}%")
print(f"Duration: {duration_s:.2f} seconds")
print(f"Total MAC-frame bytes: {int(df['frame_bytes'].sum())}")
print(f"Output directory: {OUTPUT_DIR.resolve()}")
