"""
External pcapng file version
This module is used to read and convert packet data from pcapng file to csv format

"""

import re
import pyshark
import pandas as pd
from tqdm import tqdm



def pcapng_to_csv(PCAPNG_FILE: str, CSV_FOLDER_PATH: str, BATCH_SIZE: int = 1000,
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

        # Extract the fields from the packet into the dictionary
        if 'IP' in packet:
            packet_data.update({
                'timestamp': packet.sniff_time.timestamp(),
                'ip_version': packet.ip.version if hasattr(packet.ip, 'version') else '',
                'ip_header_length': packet.ip.hdr_len if hasattr(packet.ip, 'hdr_len') else '',
                'ip_dscp': getattr(packet.ip, 'ip.dsfield.dscp') if hasattr(packet.ip, 'ip.dsfield.dscp') else '',
                'ip_ecn': getattr(packet.ip, 'ip.dsfield.ecn') if hasattr(packet.ip, 'ip.dsfield.ecn') else '',
                'ip_total_length': packet.ip.len if hasattr(packet.ip, 'len') else '',
                'ip_identification': packet.ip.id if hasattr(packet.ip, 'id') else '',
                'ip_flags': packet.ip.flags if hasattr(packet.ip, 'flags') else '',
                'ip_fragment_offset': packet.ip.frag_offset if hasattr(packet.ip, 'frag_offset') else '',
                'ip_ttl': packet.ip.ttl if hasattr(packet.ip, 'ttl') else '',
                'ip_protocol': packet.ip.proto if hasattr(packet.ip, 'proto') else '',
                'ip_header_checksum': packet.ip.checksum if hasattr(packet.ip, 'checksum') else '',
                'ip_source_ip': packet.ip.src if hasattr(packet.ip, 'src') else '',
                'ip_destination_ip': packet.ip.dst if hasattr(packet.ip, 'dst') else ''
            })


        if 'TCP' in packet:
            packet_data.update({
                'tcp_sport': packet.tcp.srcport if hasattr(packet.tcp, 'srcport') else '',
                'tcp_dport': packet.tcp.dstport if hasattr(packet.tcp, 'dstport') else '',
                'tcp_seq': packet.tcp.seq if hasattr(packet.tcp, 'seq') else '',
                'tcp_ack': packet.tcp.ack if hasattr(packet.tcp, 'ack') else '',
                'tcp_flags': packet.tcp.flags if hasattr(packet.tcp, 'flags') else '',
                'tcp_window': packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else '',
                'tcp_chksum': packet.tcp.checksum if hasattr(packet.tcp, 'checksum') else '',
                'tcp_urgptr': packet.tcp.urgent_pointer if hasattr(packet.tcp, 'urgent_pointer') else '',
                'tcp_time_relative': packet.tcp.time_relative if hasattr(packet.tcp, 'time_relative') else '',
                'tcp_time_delta': packet.tcp.time_delta if hasattr(packet.tcp, 'time_delta') else ''
            })


        if 'UDP' in packet:
            packet_data.update({
                'udp_sport': packet.udp.srcport if hasattr(packet.udp, 'srcport') else '',
                'udp_dport': packet.udp.dstport if hasattr(packet.udp, 'dstport') else '',
                'udp_len': packet.udp.length if hasattr(packet.udp, 'length') else '',
                'udp_chksum': packet.udp.checksum if hasattr(packet.udp, 'checksum') else '',
                'udp_time_relative': packet.udp.time_relative if hasattr(packet.udp, 'time_relative') else '',
                'udp_time_delta': packet.udp.time_delta if hasattr(packet.udp, 'time_delta') else ''
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
# Demo
if __name__ == '__main__':

    # Specify the path to the pcapng file
    PCAPNG_FILE_PATH = '../data/external/scan-hostport-6-dec.pcap'

    # Specify destination file path
    CSV_FILE = '../data/interim'

    # Set the batch size for DataFrame conversion and CSV file path
    # BATCH_SIZE = 1000  # Adjust the batch size as needed

    benign = pcapng_to_csv(PCAPNG_FILE=PCAPNG_FILE_PATH,
                  CSV_FOLDER_PATH=CSV_FILE)

    print(benign.head())
