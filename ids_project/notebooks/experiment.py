"""
This module is used to read and convert packet data from pcapng file to csv format

"""

import pyshark
import pandas as pd
from tqdm import tqdm

# Specify the path to the pcapng file
PCAPNG_FILE = '../data/raw/http_request.pcapng'

# Create an empty list to store the packets
packets_list = []
packets_df = pd.DataFrame()  # Initialize the final DataFrame

# Open the pcapng file using FileCapture
capture = pyshark.FileCapture(PCAPNG_FILE)

# Set the batch size for DataFrame conversion and CSV file path
BATCH_SIZE = 1000  # Adjust the batch size as needed
CSV_FILE_PATH = '../data/interim/normal_pyshark.csv'

# Initialize counter and limit
COUNT = 0
LIMIT = 185000

# Initialize batch counter
BATCH_COUNT = 0

# Iterate over the packets
for packet in tqdm(capture, desc="Reading packets", unit="packets", total=LIMIT):
    if COUNT >= LIMIT:
        break

    # Increment the loop counter
    COUNT +=1

    # Create empty packet dictionary
    packet_data = {}

    # Extract the fields from the packet into the dictionary
    if 'IP' in packet:
        packet_data.update({
            'timestamp': packet.sniff_time.timestamp(),
            'ip_version': packet.ip.version,
            'ip_header_length': packet.ip.hdr_len,
            'ip_dscp': getattr(packet.ip, 'ip.dsfield.dscp'),
            'ip_ecn': getattr(packet.ip, 'ip.dsfield.ecn'),
            'ip_total_length': packet.ip.len,
            'ip_identification': packet.ip.id,
            'ip_flags': packet.ip.flags,
            'ip_fragment_offset': packet.ip.frag_offset,
            'ip_ttl': packet.ip.ttl,
            'ip_protocol': packet.ip.proto,
            'ip_header_checksum': packet.ip.checksum,
            'ip_source_ip': packet.ip.src,
            'ip_destination_ip': packet.ip.dst
        })

    if 'TCP' in packet:
        packet_data.update({
            'tcp_sport': packet.tcp.srcport,
            'tcp_dport': packet.tcp.dstport,
            'tcp_seq': packet.tcp.seq,
            'tcp_ack': packet.tcp.ack,
            'tcp_flags': packet.tcp.flags,
            'tcp_window': packet.tcp.window_size,
            'tcp_chksum': packet.tcp.checksum,
            'tcp_urgptr': packet.tcp.urgent_pointer,
            'tcp_time_relative': packet.tcp.time_relative,
            'tcp_time_delta': packet.tcp.time_delta
        })

    if 'UDP' in packet:
        packet_data.update({
            'udp_sport': packet.udp.srcport,
            'udp_dport': packet.udp.dstport,
            'udp_len': packet.udp.length,
            'udp_chksum': packet.udp.checksum,
            'udp_time_relative': packet.udp.time_relative,
            'udp_time_delta': packet.udp.time_delta
        })

    # Append the dictionary to the list
    packets_list.append(packet_data)

    # Convert packets_list to DataFrame after batch size is reached
    if len(packets_list) >= BATCH_SIZE:
        batch_df = pd.DataFrame(packets_list)
        packets_df = pd.concat([packets_df, batch_df], ignore_index=True)
        packets_list = []  # Clear the packets_list

        # Increment the batch counter
        BATCH_COUNT += 1

        # save batch to csv
        if BATCH_COUNT == 1:
            # First update: Clear the existing file and add headers
            packets_df.to_csv(CSV_FILE_PATH, index=False, header=True, mode='w')
        else:
            # Subsequent updates: Append rows without headers
            packets_df.to_csv(CSV_FILE_PATH, index=False, header=False, mode='a')
        packets_df = pd.DataFrame()  # Clear the packets_df

# Convert any remaining packets in packets_list to DataFrame
if len(packets_list) > 0:
    batch_df = pd.DataFrame(packets_list)
    packets_df = pd.concat([packets_df, batch_df], ignore_index=True)

# Save any remaining packets_df to a CSV file
if not packets_df.empty:
    packets_df.to_csv(CSV_FILE_PATH, index=False, header=False, mode='a')
