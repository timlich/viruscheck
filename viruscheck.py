import os
import argparse
import hashlib
import requests
import time
import mimetypes
import json
from collections import OrderedDict


def fileUploads(fileHashList, completedHashList, folderPath, apiKey):
    for key, value in fileHashList.items():
        if value in completedHashList:
            print(key + " has already been uploaded, skipping") # Skip all files previous uploaded
        else: 
            virusTotalUpload(folderPath, key, apiKey)
    return


def virusTotalUpload(folderPath, fileName, apiKey): # Actually upload the files
    url = "https://www.virustotal.com/api/v3/files"

    mime_type, encoding = mimetypes.guess_type(fileName)

    files = {"file": (fileName, open(os.path.join(folderPath, fileName), "rb"), mime_type)}
    headers = {
        "accept": "application/json",
        "x-apikey": apiKey
    }

    requests.post(url, files=files, headers=headers)
    print(fileName + " has been uploaded")
    time.sleep(10) # Wait 10 seconds for the report to be generated on new file uploads
    return


def checkFileHash(fileHashList, apiKey): # Get the scan results from API
    scanResults = {"Results":[]}
    for key, value in fileHashList.items():
        url = "https://www.virustotal.com/api/v3/files/" + value

        headers = {
            "accept": "application/json",
            "x-apikey": apiKey
        }
        response = requests.get(url, headers=headers)
        print(key + " has been reported malicious by " + str(response.json()['data']['attributes']['last_analysis_stats']['malicious']) + " vendor(s).")
        scanResults["Results"].append(response.json()) # This builds the JSON object which will be written to the output file
    return(scanResults)


def getFileHash(fullFilePath):
    with open(fullFilePath, 'rb') as file_check:
        data = file_check.read()
        sha256_hash = hashlib.sha256(data).hexdigest()
    return(sha256_hash)


def getSystemFolder(): # This function gets the home directory of the user and then appends 'Downloads' with the proper syntax for the system
    return(os.path.join(os.path.expanduser('~'), 'Downloads'))


def main():
    parser = argparse.ArgumentParser(description='VirusTotal checker')
    parser.add_argument('-apikey', required=True, help='your VirusTotal API key')
    parser.add_argument('--sendhidden', '-sh', dest="sendhidden", action='store_false', default='True')
    parser.add_argument('--directory', '-d', dest="directory", type=str, default=getSystemFolder()) # Parse the directory
    args = parser.parse_args()
    folderPath = args.directory
    apiKey = args.apikey
    fileList = []
    fileHashList = OrderedDict()
    completedHashList = []
    try:
        fileList = os.listdir(folderPath)
    except:
        print("This folder doesn't exist")
    for x in fileList:
        if os.path.isfile(os.path.join(folderPath, x)):  # Filters out directories
            if x[0] != '.' or args.sendhidden == False:  # Filters hidden files unless argument -sh was set
                if os.path.getsize(os.path.join(folderPath, x)) < 31457280: # Limits to 30MB, VT file size limit
                    fileHashList[x] = getFileHash(os.path.join(folderPath, x)) # Add file name and sha256 hash to ordered dictionary

    print("Checking the following files:")
    for key, value in fileHashList.items():
        print(key)
    print("\n")

    try: # This opens the file listed below and and then adds the hashes in the file to a list for later comparison
        with open('Virustotal_API_Response.txt', "r") as f:
            completedScans = json.load(f)
        f.close()
        for sha256Hash in completedScans["Results"]:
            completedHashList.append(sha256Hash["data"]['attributes']['sha256']) 
    except:
        print("Results file doesn't exist, it will be created!\n")

    fileUploads(fileHashList, completedHashList, folderPath, apiKey)

    print("\n")

    jsonData = checkFileHash(fileHashList, apiKey) # Get file reports, jsonData is the aggregate data for each response
    with open('Virustotal_API_Response.txt','w') as file: # Save json to file
        json.dump(jsonData, file, indent = 4)
    file.close()

    print("\nAll API responses saved in Virustotal_API_Response.txt file")

if __name__ ==  "__main__":
    main()