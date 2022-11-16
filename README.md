# Viruscheck
This is a script to automatically upload selected files in a folder to VirusTotal and return a result

## Options
### API Key:
Usage: -apikey "key" (without quotes)

This is required to use VirusTotal's API

### Directory:
Usage: -d, --directory /path/to/files/ (C:\path\to\files on Windows)

This defaults to the current user's Downloads directory (highly recommended to set if you don't want your downloads uploaded to VT)

Default Linux Path: ~/Downloads/

Default Windows Path: C:\Users\\"current user"\Downloads

### Send Hidden Files
Usage: -sh, --sendhidden

This allows for the uploading of hidden files, which is disabled by default

## Output
There are three main parts to this script. The first gathers all the files under 30MB (VT limit) and then filters hidden files (unless the flag has been set which uploads hidden files). The second part will compare the hash of each file to any hashes found in "Virustotal_API_Response.txt" to avoid repeatedly upload the same file to VT. Leftover files are then uploaded. The third part takes each file hash (regardless of whether the file was actually uploaded to VT in the second step) and then gets the file report. All file reports are then aggregated into the file "Virustotal_API_Response.txt". 

## TODO
I need to fix the requests to properly account for any errors in the responses, e.g. 400 status codes. These wouldn't properly be handled because there is no data returned with a 400 error so subsequent code wouldn't be unable to parse data from the response. I also want to implement a rate limit to prevent hitting the VT limit per hour.