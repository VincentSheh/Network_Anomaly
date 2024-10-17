import requests
import argparse
import pandas as pd
import pickle
from io import StringIO
import numpy as np
import os
import time
def record_csv(result_df, file_path):
    unlabeled_df = pd.read_csv(file_path)
    unlabeled_df.to_csv("x.csv", index=False)
    result_df.to_csv("result.csv", index=False)
    unlabeled_df["Label"] = result_df["Label"]
    
    # Get Available Filename
    filenumber = 0
    folder = "./cicflowmeter/s0_lm_training_data/"
    filename = "train"
    filepath = os.path.join(folder,f"{filename}_{filenumber}.csv")
    while os.path.exists(filepath):
        filenumber+=1
        filepath = os.path.join(folder, f"{filename}_{filenumber}.csv")  
    # Write to CSV
    unlabeled_df.to_csv(filepath, index=False)
    print("record_csv() Saved File to", filepath)  
    
    
def retrain_lm(training_folder, url):
    # Send the retraining request to LM
    merge_csv(training_folder)
    files = {'file': open(training_folder+"final_merged.csv", 'rb')}
    print(url, files['file'])
    response = requests.post(url, files=files)
    if response.status_code == 200:
        print(f"\033[32mLocal Model Started Training\033[0m")
    else:
        print(f"\033[31mFailed to start training: {response.status_code} {response.text}\033[0m")
    # Flush Training Folder file
    
    
def send_csv(url, file_path, record_flag, offload_url = ""): 
    data = {'offload_url': offload_url}
    files = {'file': open(file_path, 'rb')}
    print(files["file"], data)
    response = requests.post(url, files=files, data=data)
    if response.status_code == 200:
        # Convert JSON response back into DataFrame
        json_data = response.json()
        df = pd.DataFrame(json_data, columns=["origin_ip", "Label"])
        if record_flag:
            print("Recording Data")
            record_csv(df, file_path)
        return df
    else:
        print(f"Failed to fetch data. Status code: {response.status_code}")
        return None

def merge_csv(file_path):
    # Get the directory of the provided file path
    directory = os.path.dirname(file_path)

    # List all files in the directory
    path_list = os.listdir(directory)

    # Create an empty DataFrame to hold the merged content
    full_df = pd.DataFrame()

    # Loop through the list of files to read, merge, and delete them
    for file in path_list:
        full_file_path = os.path.join(directory, file)
        try:
            # Attempt to read the current file into a DataFrame
            curr_file_df = pd.read_csv(full_file_path)
            if not curr_file_df.empty:
                # Concatenate the current DataFrame with the full DataFrame
                full_df = pd.concat([curr_file_df, full_df], axis=0, ignore_index=True)
            # Delete the file after reading
            os.remove(full_file_path)
            print(f"Deleted file: {full_file_path}")
        except Exception as e:
            print(f"Error reading or deleting file {full_file_path}: {e}")

    # Save the merged DataFrame to a new CSV file
    # final_merged_path = os.path.join(directory, "final_merged.csv")
    # full_df.to_csv(final_merged_path, index=False)
    # print(f"Merged all CSV files into {final_merged_path}")
    # print(f"Merged CSV Files {path_list} in {directory}")
    
def get_state_parameters(state, lm_url, gm_url):
    time_ellapsed = 0
    if state == 0: #Send Detection Task directly to the Selected Model and Record the Datas for training
        decision = "detect"
        record_flag = True
        time_ellapsed += 1 #TODO: Record in terminal script
        url = gm_url #? Or other_lm_url
        offload_url = ""
    if state == 1: #Send Detection Task to Local Model
        decision = "detect"
        record_flag = False
        url = lm_url
        offload_url = ""
    if state == 2: #Send Detection Task to Local Model which will forward it to selected LM
        decision = "offload"
        record_flag = False
        url = lm_url #? Or other_lm_url
        offload_url = gm_url + decision
    if state == 3: #Send Recorded Training Data to GM then Retrain and #TODO: Perform Training of LM
        decision = "retrain"
        record_flag = True
        url = gm_url
        offload_url = ""
    url = url + decision
        
    return record_flag, url, offload_url

def main():
    parser = argparse.ArgumentParser(description='Upload File to CSV.')
    parser.add_argument('-f','--file_path', type=str, help='Path to the CSV file to send.')
    parser.add_argument('-s','--curr_state', type=int, help='Current State of the Local IDS: 0 1 2 3')
    parser.add_argument('-t','--transition_to_on', action='store_true', help='Whether to transition from s0 to s1')
    args = parser.parse_args()
    #TODO: Query LMM for offloading URL
    lm_url = "http://192.168.50.54:30050/"
    gm_url = "http://192.168.50.167:5050/"
    block_threshold = 20
    
    record_flag, url, offload_url = get_state_parameters(args.curr_state, lm_url, gm_url)
    if args.transition_to_on == True: # S0 --> S1 Transition
        print("Retraining LM")
        retrain_lm("./cicflowmeter/s0_lm_training_data/", lm_url + "retrain")
    if args.curr_state == 3: #!S3: Doesn't perform detection?
        print("Training GM..")
        send_csv(url, args.file_path, record_flag, offload_url)     
        print("\033[32mFinish Training GM\033[0m")    
    try:
        labeled_df = send_csv(url, args.file_path, record_flag, offload_url) # TODO: if offload, incorportae the url to post request
        
        if labeled_df is not None and not labeled_df.empty:
            block_list_file="malicious_ip.txt"
            malicious_ip = labeled_df.loc[labeled_df["Label"] == 1, "origin_ip"]
            unique, counts = np.unique(malicious_ip, return_counts=True)
    
            # Convert to dictionary
            ip_count_dict = dict(zip(unique, counts))            
            if len(malicious_ip) > 0:
                with open(block_list_file, "w") as file:
                    for ip, count in ip_count_dict.items():
                        if count >= block_threshold:
                            print(f"\033[95mBlocking {ip} with {count} occurrences\033[0m")
                            file.write(f"{ip}\n")  # Write IP to block list file
            else:
                print("\033[92mNo Malicious Traffic Detected\033[0m")
            # merge_csv(args.file_path)
        else:
            print("No data returned from the server or the DataFrame is empty.")
    except Exception as e:
        print(f"An error occurred: {e}")
    # Merge All CSV File in the directory
    # merge_csv(args.file_path)
    return 0

if __name__ == '__main__':
    main()
    #sudo python3 upload_csv.py -f ./cicflowmeter/hls_benign/final_merged.csv -s 1          
    