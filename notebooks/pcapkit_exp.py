from pcapkit import extract
"""
Parse through the pcap file and save it as json.

The json file can then be inspected to update the required fields in the
pcapng_to_csv function
"""
json_file = extract(fin='../data/external/scan-hostport-6-dec.pcap',
                    fout='../data/interim/test.json',
                    format='json',
                    extension=False,
                    verbose=True,
                    engine='pyshark')

# Import from another folder trick
# import sys
# sys.path.append('C:/Users/Abraham Audu/Documents/BizDocs Files/THE THREE/Intrusion Detection System/ids_project/ids_project/src/data')
# from data_filters import apply_filters

