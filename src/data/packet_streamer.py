"""
This module is used to read and convert packet data from pcapng file to pandas dataframe
on demand

"""

import pyshark
from pyshark import FileCapture
import pandas as pd
from pandas import DataFrame
from tqdm import tqdm


def pcap_stream(PCAPNG_FILE: str) -> DataFrame:
    """Yield packets from a PCAP file as DataFrame

    Uses pyshark to read PCAP file and then parses the specified fields
    to generte DataFrame format of the data

    Args:
        PCAPNG_FILE (str): _description_

    Returns:
        DataFrame: _description_

    Yields:
        Iterator[DataFrame]: _description_
    """    

    # Open the pcapng file using FileCapture
    capture = pyshark.FileCapture(PCAPNG_FILE, keep_packets=False)

    # Iterate over the packets
    for packet in tqdm(capture, desc="Reading packets", unit=" packets"):

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
                'timestamp': packet.sniff_time.timestamp(),
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

        # convert dictionary to dataframe
        df = pd.DataFrame(packet_data, index=[0])
        yield df

    # Close the capture session
    capture.close()

# ----------------------------------------------------------------
# # Demo
# if __name__ == '__main__':

#     # Specify the path to the pcapng file
#     PCAPNG_FILE_PATH = './data/external/dos-synflooding-5-dec.pcap'

#     # Specify destination file path
#     CSV_FILE = './data/interim'

#     # Set the batch size for DataFrame conversion and CSV file path
#     # BATCH_SIZE = 1000  # Adjust the batch size as needed

#     benign = pcapng_to_csv(PCAPNG_FILE=PCAPNG_FILE_PATH,
#                   CSV_FOLDER_PATH=CSV_FILE)

#     print(benign.head())

