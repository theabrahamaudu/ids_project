"""
Loads all pcap files in the given directory, converts them to csv
and lables the data in each csv file.

Saves labelled files in specified directory
"""

import os
import pandas as pd
from tqdm import tqdm
from src.data.pcap_to_csv import pcapng_to_csv
import src.data.data_filters as data_filters
from src.utils.pipeline_log_config import pipeline as logger

def scan_directory(directory: str, extension: str) -> list:
    """Check specified directory and return list of files with
    specified extension

    Args:
        directory (str): path string to directory e.g. "./the/directory"
        extension (str): extension type to be searched for e.g. ".csv"

    Returns:
        list: strings of file names with specified extension
    """    
    files: list = []
    for filename in os.listdir(directory):
        if filename.endswith(extension):
            files.append(filename)
    return files


def load_and_filter_files(directory_path: str,
                          pcap_files_list: list,
                          destination_path: str,
                          merge: bool=False,
                          pick_up: bool=False):
    """Load .pcap files from specified directory, filter them according to the rules
    defined in `data_filters` module and create a new column with appropriate datapoint
    labels. Save new dataframe to specified destination path.

    Args:
        directory_path (str): Path to load .pcap files
        pcap_files_list (list): List of files in the directory to be filtered.
        destination_path (str): Path to save labelled files
        merge (bool, optional): if True, merges all the filtered data into one file. Defaults to False.
        pick_up (bool, optional): if True, scans destination path to skip already filtered files. Defaults to False.
    """    

    # Scan destination path for existing csv files
    existing_csv = scan_directory(destination_path,".csv")
    
    print(f"Converting {len(pcap_files_list)} pcap files to csv\n")
    logger.info(f"Converting {len(pcap_files_list)} pcap files to csv\n")


    # Initialize fails counter
    FAILS = 0

    # Loop through the files in the directory and load each one
    for filename in pcap_files_list:

        # Scan destination path if pick_up is True
        if pick_up==True and str(filename[:-5]+".csv") in existing_csv:
            print(f"{filename} already converted\n")
            logger.info("'pick_up' set to continue from last run")
            logger.info(f"{filename} already converted\n")
        else:

            try:
                print(f"Coverting {filename} to csv...")
                logger.info(f"Coverting {filename} to csv...")
                # Convert file to csv
                csv_file = pcapng_to_csv(
                    PCAPNG_FILE=str(directory_path+"/"+filename),
                    CSV_FOLDER_PATH='./data/interim'
                )
                # Load converted csv to memory
                data_df = pd.read_csv(str("./data/interim"+"/"+filename[:-5]+".csv"))
                
                print(f"Adding labels to {filename[:-5]}.csv...\n")
                logger.info(f"Adding labels to {filename[:-5]}.csv...\n")
                # filter the files using the specific filter function for each file
                if "benign-dec.pcap" in filename:
                    data_labelled = data_filters.benign_dec(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "mitm-arpspoofing-1-dec.pcap" in filename or\
                "mitm-arpspoofing-2-dec.pcap" in filename or\
                "mitm-arpspoofing-3-dec.pcap" in filename:
                    data_labelled = data_filters.mitm_arpspoofing_1_3_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "mitm-arpspoofing-4-dec.pcap" in filename or\
                "mitm-arpspoofing-5-dec.pcap" in filename or\
                "mitm-arpspoofing-6-dec.pcap" in filename:
                    data_labelled = data_filters.mitm_arpspoofing_4_6_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "dos-synflooding-1-dec.pcap" in filename or\
                "dos-synflooding-2-dec.pcap" in filename:
                    data_labelled = data_filters.dos_synflooding_1_2_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "dos-synflooding-3-dec.pcap" in filename:
                    data_labelled = data_filters.dos_synflooding_3_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "dos-synflooding-4-dec.pcap" in filename or\
                "dos-synflooding-5-dec.pcap" in filename or\
                "dos-synflooding-6-dec.pcap" in filename:
                    data_labelled = data_filters.dos_synflooding_4_6_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-hostport-1-dec.pcap" in filename:
                    data_labelled = data_filters.scan_hostport_1_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-hostport-2-dec.pcap" in filename:
                    data_labelled = data_filters.scan_hostport_2_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-hostport-3-dec.pcap" in filename:
                    data_labelled = data_filters.scan_hostport_3_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-hostport-4-dec.pcap" in filename:
                    data_labelled = data_filters.scan_hostport_4_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-hostport-5-dec.pcap" in filename:
                    data_labelled = data_filters.scan_hostport_5_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-hostport-6-dec.pcap" in filename:
                    data_labelled = data_filters.scan_hostport_6_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-portos-1-dec.pcap" in filename or\
                "scan-portos-2-dec.pcap" in filename or\
                "scan-portos-3-dec.pcap" in filename:
                    data_labelled = data_filters.scan_portos_1_3_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "scan-portos-4-dec.pcap" in filename or\
                "scan-portos-5-dec.pcap" in filename or\
                "scan-portos-6-dec.pcap" in filename:
                    data_labelled = data_filters.scan_portos_4_6_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "mirai-udpflooding-1-dec.pcap" in filename or\
                "mirai-udpflooding-2-dec.pcap" in filename or\
                "mirai-udpflooding-3-dec.pcap" in filename or\
                "mirai-udpflooding-4-dec.pcap" in filename:
                    data_labelled = data_filters.mirai_udpflooding_1_4_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "mirai-ackflooding-1-dec.pcap" in filename or\
                "mirai-ackflooding-2-dec.pcap" in filename or\
                "mirai-ackflooding-3-dec.pcap" in filename or\
                "mirai-ackflooding-4-dec.pcap" in filename:
                    data_labelled = data_filters.mirai_ackflooding_1_4_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "mirai-httpflooding-1-dec.pcap" in filename or\
                "mirai-httpflooding-2-dec.pcap" in filename or\
                "mirai-httpflooding-3-dec.pcap" in filename or\
                "mirai-httpflooding-4-dec.pcap" in filename:
                    data_labelled = data_filters.mirai_httpflooding_1_4_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "mirai-hostbruteforce-1-dec.pcap" in filename or\
                "mirai-hostbruteforce-3-dec.pcap" in filename or\
                "mirai-hostbruteforce-5-dec.pcap" in filename:
                    data_labelled = data_filters.mirai_hostbruteforce_1_3_n_5_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')

                if "mirai-hostbruteforce-2-dec.pcap" in filename or\
                "mirai-hostbruteforce-4-dec.pcap" in filename:
                    data_labelled = data_filters.mirai_hostbruteforce_2_n_4_dec_filter(data_df)
                    data_labelled.to_csv(str(destination_path+"/"+filename[:-5]+".csv"),
                                        index=False, header=True, mode='w')
            except Exception as e:
                print(f"An error occured with file '{filename}': \n", e)
                logger.warning(f"An error occured with file '{filename}': \n", e)
                FAILS+=1
                

    print(f"\n{len(pcap_files_list) - FAILS} pcap files labelled and saved to csv\n",
          f"{FAILS} files could not be converted. Read terminal logs for details")
    logger.info(f"\n{len(pcap_files_list) - FAILS} pcap files labelled and saved to csv\n{FAILS} files could not be converted. Read terminal logs for details")

    # If merge is set to true, create a csv file with all the data
    if merge is True:
        print(f"Merging {len(pcap_files_list)} csv files...")
        logger.info("Merge set to True")
        logger.info(f"Merging {len(pcap_files_list)} csv files...")
        # Initialize counter
        COUNT = 0

        for filename in tqdm(pcap_files_list,
                             desc="Merging Files",
                             unit=" files",
                             total=len(pcap_files_list)):

            # Increment counter
            COUNT+=1
            labelled_dataframe = pd.read_csv(str(destination_path+"/"+filename[:-5]+".csv"))

            if COUNT == 1:
                # Create new marge file
                labelled_dataframe.to_csv(str(destination_path+"/"+"all_data_labelled.csv"),
                                          index=False, header=True, mode='w')
            else:
                # Update merge file
                labelled_dataframe.to_csv(str(destination_path+"/"+"all_data_labelled.csv"),
                                          index=False, header=False, mode='a')
        
        print(f"|| {COUNT} csv files merged and saved to {destination_path} ||")
        logger.info(f"|| {COUNT} csv files merged and saved to {destination_path} ||")

        
        
# if __name__ == '__main__':
#     # Specify the directory to scan
#     directory_path = "./data/external"

#     # Labelled data directory
#     destination_path = './data/labelled'

#     # Call the function to scan the directory and get the list of .pcap files
#     pcap_files_list = scan_directory(directory_path, ".pcap")

#     # Remove noted bad files
#     pcap_files_list.remove('dos-synflooding-6-dec.pcap')
#     pcap_files_list.remove('mirai-hostbruteforce-3-dec.pcap')

#     print(pcap_files_list)

#     # the_list = ['dos-synflooding-4-dec.pcap', 'mirai-udpflooding-3-dec.pcap', 'scan-portos-4-dec.pcap',
#     #             'mitm-arpspoofing-4-dec.pcap']

#     load_and_filter_files(directory_path=directory_path,
#                           pcap_files_list=pcap_files_list,
#                           destination_path=destination_path,
#                           merge=True,
#                           pick_up=True)