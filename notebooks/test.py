from src.features.build_features import (
                                         convert_to_float,
                                         )
from src.data.packet_streamer import pcap_stream  
import pandas as pd
import numpy as np
import joblib


filename = 'mitm-arpspoofing-4-dec.pcap'
file_path = './data/external/'
# Get temp dir
# main_directory = os.path.dirname(os.path.abspath(__file__))
# directory_path = os.path.join(main_directory, "temp")

# Define new file file path
# file_path = os.path.join(directory_path, filename)
temp_df = pd.DataFrame()
for i in pcap_stream(file_path+filename):
    temp_df = pd.concat([temp_df, i], axis=0)
print('\nPreprocessing data')

# Define unprocessed csv file file path
unprocessed_csv_file_path = './notebooks/'+str(filename[:-5]+'unprocessed.csv')
temp_df.to_csv(unprocessed_csv_file_path, index=False, header=True, mode='w')

# temp_np_array = inference_preprocess(temp_df)
scaler = joblib.load('./src/features/scaler.pkl')
optimal_features =[
                'timestamp', 'ip_len', 'ip_id', 'ip_flags', 'ip_ttl', 'ip_proto',
                'ip_checksum', 'ip_dst', 'ip_dst_host','tcp_srcport', 'tcp_dstport',
                'tcp_port', 'tcp_stream', 'tcp_completeness', 'tcp_seq_raw', 'tcp_ack',
                'tcp_ack_raw', 'tcp_flags_reset', 'tcp_flags_syn', 'tcp_window_size_value',
                'tcp_window_size', 'tcp_window_size_scalefactor', 'tcp_', 'udp_srcport',
                'udp_dstport', 'udp_port', 'udp_length', 'udp_time_delta', 'eth_dst_oui',
                'eth_addr_oui', 'eth_dst_lg', 'eth_lg', 'eth_ig', 'eth_src_oui', 'eth_type',
                'icmp_type', 'icmp_code', 'icmp_checksum', 'icmp_checksum_status', 'arp_opcode'
                ]
data_optimal_features = temp_df[optimal_features]
data_floats = convert_to_float(data_optimal_features)
data_scaled = scaler.transform(data_floats)

# Define new csv file file path
csv_file_path = './notebooks/'+str(filename[:-5]+'.csv')
np.savetxt(csv_file_path, data_scaled, delimiter=',')