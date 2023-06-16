"""
Loads all pcap files in the given directory, converts them to csv
and lables the data in each csv file.

Saves labelled files in specified directory
"""

import os

def scan_directory(directory):
    pcap_files = []
    for filename in os.listdir(directory):
        if filename.endswith(".pcap"):
            pcap_files.append(filename)
    return pcap_files

# Specify the directory you want to scan
directory_path = "../data/external"

# Call the function to scan the directory and get the list of .pcap files
pcap_files_list = scan_directory(directory_path)

# Print the list of .pcap files
