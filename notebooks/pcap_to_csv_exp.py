"""
External pcapng file version
This module is used to read and convert packet data from pcapng file to csv format

"""

import re
import pyshark
import pandas as pd
from tqdm import tqdm



def pcapng_to_csv(PCAPNG_FILE: str, CSV_FOLDER_PATH: str, CSV_NAME: str=None, BATCH_SIZE: int = 1000,
                  data_desc_path: str = '../data/external/dataset_description.xlsx',
                  ):
    """_summary_

    Args:
        PCAPNG_FILE (str): _description_
        CSV_FILE_PATH (str): _description_
        BATCH_SIZE (int, optional): _description_. Defaults to 1000.
        data_desc_path (str, optional): _description_. Defaults to '../data/external/dataset_description.xlsx'.

    Returns:
        _type_: _description_
    """    
    # Load data description
    data_description = pd.read_excel(data_desc_path, 
                                 sheet_name='Files & description', 
                                 header=2)

    # Create an empty list to store the packets
    packets_list = []
    packets_df = pd.DataFrame()  # Initialize the final DataFrame

    # Open the pcapng file using FileCapture
    capture = pyshark.FileCapture(PCAPNG_FILE)

    # Get pcapng filename
    file_name = re.search(r'([^/\\]+)\.\w+$', PCAPNG_FILE).group(1)

    # Set CSV file path
    if CSV_NAME != None:
        CSV_FILE_PATH = str(CSV_FOLDER_PATH+"/"+CSV_NAME+".csv")
    else:
        CSV_FILE_PATH = str(CSV_FOLDER_PATH+"/"+file_name+".csv")

    # Initialize counter and limit
    COUNT = 0
    LIMIT = int(data_description[data_description['File Name']==\
                             str(file_name+".pcap")]\
                            ['# Total Packets'].iloc[0])

    # Initialize batch counter
    BATCH_COUNT = 0

    # Iterate over the packets
    for packet in tqdm(capture, desc="Reading packets", unit=" packets", total=LIMIT):
        if COUNT >= LIMIT:
            break

        # Increment the loop counter
        COUNT +=1

        # Create empty packet dictionary
        packet_data = {}

        # Extract IP fields from the packet into the dictionary
        ip_fields = [
            'version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'len', 'id', 'flags',
            'flags_rb', 'flags_df', 'flags_mf', 'frag_offset', 'ttl', 'proto', 'checksum',
            'checksum_status', 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host'
            ]

        if 'IP' in packet:
            packet_data.update({
                'timestamp': packet.sniff_time.timestamp(),
                **{f'ip_{field}': getattr(packet.ip, field) if hasattr(packet.ip, field) else '' for field in ip_fields}
            })
        else:
            packet_data.update({
                **{f'ip_{field}': None for field in ip_fields}
            })

        # Extract TCP fields from the packet into the dictionary
        tcp_fields = [
            'srcport', 'dstport', 'port', 'stream', 'completeness', 'len', 'seq', 'seq_raw',
            'nxtseq', 'ack', 'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ae', 'flags_cwr',
            'flags_ece', 'flags_urg', 'flags_ack', 'flags_push', 'flags_reset', 'flags_syn',
            'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'window_size_scalefactor',
            'checksum', 'checksum_status', 'urgent_pointer', '', 'time_relative', 'time_delta',
            'analysis', 'analysis_bytes_in_flight', 'analysis_push_bytes_sent'
            ]

        if 'TCP' in packet:
            packet_data.update({
                **{f'tcp_{field}': getattr(packet.tcp, field) if hasattr(packet.tcp, field) else '' for field in tcp_fields}
            })
        else:
            packet_data.update({
                **{f'tcp_{field}': None for field in tcp_fields}
            })

        # Extract UDP fields from the packet into the dictionary
        udp_fields = [
            'srcport', 'dstport', 'port', 'length', 'checksum', 'checksum_status', 'stream',
            'time_relative', 'time_delta'
            ]

        if 'UDP' in packet:
            packet_data.update({
                **{f'udp_{field}': getattr(packet.udp, field) if hasattr(packet.udp, field) else '' for field in udp_fields}
            })
        else:
            packet_data.update({
                **{f'udp_{field}': None for field in udp_fields}
            })

        # Extract ETH fields from the packet into the dictionary
        eth_fields = [
            'dst', 'dst_resolved', 'dst_oui', 'dst_oui_resolved', 'addr', 'addr_resolved', 'addr_oui',
            'addr_oui_resolved', 'dst_lg', 'lg', 'dst_ig', 'ig', 'src', 'src_resolved', 'src_oui',
            'src_oui_resolved', 'src_lg', 'src_ig', 'type'
            ]

        if 'ETH' in packet:
            packet_data.update({
                **{f'eth_{field}': getattr(packet.eth, field) if hasattr(packet.eth, field) else '' for field in eth_fields}
            })
        else:
            packet_data.update({
                **{f'eth_{field}': None for field in eth_fields}
            })

        # Extract ICMP fields from the packet into the dictionary
        icmp_fields = [
            'type', 'code', 'checksum', 'checksum_status', 'ident', 'ident_le', 'seq',
            'seq_le', 'data_len'
            ]

        if 'ICMP' in packet:
            packet_data.update({
                **{f'icmp_{field}': getattr(packet.icmp, field) if hasattr(packet.icmp, field) else '' for field in icmp_fields}
            })
        else:
            packet_data.update({
                **{f'icmp_{field}': None for field in icmp_fields}
            })

        # Extract ARP fields from the packet into the dictionary
        arp_fields = [
            'hw_type', 'proto_type', 'hw_size', 'proto_size', 'opcode', 'src_hw_mac',
            'src_proto_ipv4', 'dst_hw_mac', 'dst_proto_ipv4'
            ]

        if 'ARP' in packet:
            packet_data.update({
                **{f'arp_{field}': getattr(packet.arp, field) if hasattr(packet.arp, field) else '' for field in arp_fields}
            })
        else:
            packet_data.update({
                **{f'arp_{field}': None for field in arp_fields}
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

    packets_csv: pd.DataFrame = pd.read_csv(CSV_FILE_PATH)
    return packets_csv

# ----------------------------------------------------------------
# # Demo
# if __name__ == '__main__':

#     # Specify the path to the pcapng file
#     PCAPNG_FILE_PATH = '../data/external/dos-synflooding-5-dec.pcap'

#     # Specify destination file path
#     CSV_FILE = '../data/interim'

#     # Set the batch size for DataFrame conversion and CSV file path
#     # BATCH_SIZE = 1000  # Adjust the batch size as needed

#     benign = pcapng_to_csv(PCAPNG_FILE=PCAPNG_FILE_PATH,
#                   CSV_FOLDER_PATH=CSV_FILE)

#     print(benign.head())
