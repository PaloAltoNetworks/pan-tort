####!/usr/bin/env python3
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import os
import os.path
import json
import time
import requests

from panrc import hostname, api_key

def main():

    """hash_data main module"""

    libpath = os.path.dirname(os.path.abspath(__file__))
    sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]

    malware_values = {'0': 'benign', '1': 'malware', '2': 'grayware'}

#supported hashtypes are: md5, sha1, sha256

    if len(sys.argv) < 2:
        print('\nEnter the hash type after hash_data.py [md5, sha1, sha256]\n')
        sys.exit(1)
    elif sys.argv[1] == 'md5' or sys.argv[1] == 'sha1' or sys.argv[1] == 'sha256':
        hashtype = sys.argv[1]
    else:
        print('\nOnly hash types md5, sha1, or sha256 are supported\n')
        sys.exit(1)

    AFoutput_dict = {}
    hashList = []

 # Use counters to create a simple output stats file in tandem with json details

    HashCounters = {}
    HashCountValues = ['total samples', 'malware', 'mal_inactive_sig', 'mal_active_sig',
                       'mal_no_sig', 'grayware', 'benign', 'No sample found']

    for value in HashCountValues:
        HashCounters[value] = 0

# Used for Elasticsearch bulk import
# Formatting requires index data per document record
    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = 'hash-data'
    index_tag_inner['_type'] = 'hash-data'

# Map starting index to 1 if a new run or one more than the last value as a continuing run
# Useful with augmenting data or errors result in the app ending prematurely

    index = 1

# read the hash list file - a simple text list of malware sample hashes
# the text file is converted to a simple python list

    with open('hash_list.txt', 'r') as hashFile:
        hashList = hashFile.read().splitlines()

# query each hash to get malware verdict
# index lines are specific to Elastic search bulk inputs

    for hashvalue in hashList:
        index_tag_inner['_id'] = index
        index_tag_full['index'] = index_tag_inner
        hash_data_dict = {}
        print('\nworking with hash = {0}\n'.format(hashvalue))

        query = {"operator": "all",
                 "children": [{"field":"sample.sha256", "operator":"is", "value":hashvalue}]
                }

        search_values = {"apiKey": api_key,
                         "query": query,
                         "size": 1,
                         "from": 0,
                         "sort": {"create_date": {"order": "desc"}},
                         "scope": "global",
                         "artifactSource": "af"
                        }

        headers = {"Content-Type": "application/json"}
        search_url = 'https://{0}/api/v1.0/samples/search'.format(hostname)
        try:
            search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
            print('     Search query posted to Autofocus\n')
            search.raise_for_status()
        except requests.exceptions.HTTPError:
            print(search)
            print(search.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        search_dict = {}
        search_dict = json.loads(search.text)

        cookie = search_dict['af_cookie']
        print('     Tracking cookie is {0}'.format(cookie))

        for timer in range(60):

            time.sleep(5)
            try:
                results_url = 'https://{0}/api/v1.0/samples/results/'.format(hostname) + cookie
                results_values = {"apiKey": api_key}
                results = requests.post(results_url, headers=headers, data=json.dumps(results_values))
                results.raise_for_status()
            except requests.exceptions.HTTPError:
                print(results)
                print(results.text)
                print('\nCorrect errors and rerun the application\n')
                sys.exit()

            AFoutput_dict = results.json()

            if 'total' in AFoutput_dict:
                if AFoutput_dict['total'] == 0:
                    print('     Now waiting for a hit...')
                else:
                    break
            else:
                print('     Autofocus still queuing up the search...')

# AFoutput is json output converted to python dictionary

        hash_data_dict['hashtype'] = hashtype
        hash_data_dict['hashvalue'] = hashvalue

        if AFoutput_dict['hits']:

# initial AF query to get sample data include sha256 hash and WF verdict

            verdict_num = AFoutput_dict['hits'][0]['_source']['malware']
            verdict_text = malware_values[str(verdict_num)]
            hash_data_dict['verdict'] = verdict_text
            hash_data_dict['filetype'] = AFoutput_dict['hits'][0]['_source']['filetype']
            hash_data_dict['sha256hash'] = AFoutput_dict['hits'][0]['_source']['sha256']
            hash_data_dict['create_date'] = AFoutput_dict['hits'][0]['_source']['create_date']
            if 'tag' in AFoutput_dict['hits'][0]['_source']:
                hash_data_dict['tag'] = AFoutput_dict['hits'][0]['_source']['tag']
            print('\n     Hash verdict is {0}\n'.format(verdict_text))

# second AF query to get coverage info from sample analysis
# Print each coverage section to the screen - can comment out the print statements

            print('\n     Searching Autofocus for current signature coverage...\n')

            search_values = {"apiKey": api_key,
                             "coverage": 'true',
                             "sections": ["coverage"],
                            }

            headers = {"Content-Type": "application/json"}
            search_url = 'https://{0}/api/v1.0/sample/{1}/analysis'.format(hostname, hash_data_dict['sha256hash'])

            try:
                search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
                search.raise_for_status()
            except requests.exceptions.HTTPError:
                print(search)
                print(search.text)
                print('\nCorrect errors and rerun the application\n')
                sys.exit()

            """
            # Comment or uncomment this section to see or hide sig query results
            # ------------------------------
            AFoutput_analysis = {}
            AFoutput_analysis = json.loads(search.text)
            print('\nDNS Sig coverage: \n' +
                  json.dumps(AFoutput_analysis['coverage']['dns_sig'],
                             indent=4, sort_keys=False))
            hash_data_dict['dns_sig'] = AFoutput_analysis['coverage']['dns_sig']

            print('\nWF_AV Sig coverage: \n' +
                  json.dumps(AFoutput_analysis['coverage']['wf_av_sig'],
                             indent=4, sort_keys=False))
            hash_data_dict['wf_av_sig'] = AFoutput_analysis['coverage']['wf_av_sig']

            print('\nFile URL Sig coverage: \n' +
                  json.dumps(AFoutput_analysis['coverage']['fileurl_sig'],
                             indent=4, sort_keys=False))
            hash_data_dict['fileurl_sig'] = AFoutput_analysis['coverage']['fileurl_sig']

            # -------------------------------
            """

# Check all the sig states [true or false] to see active vs inactive sigs for malware

            if verdict_text == 'malware':
                sigSearch = json.dumps(hash_data_dict)
                if sigSearch.find('true') != -1:
                    HashCounters['mal_active_sig'] += 1
                elif sigSearch.find('true') == -1 and sigSearch.find('false') != -1:
                    HashCounters['mal_inactive_sig'] += 1
                else:
                    HashCounters['mal_no_sig'] += 1


# If no hash found then tag as 'no sample found'
# These hashes can be check in VirusTotal to see if unsupported file type for Wildfire

        else:
            hash_data_dict['verdict'] = 'No sample found'
            print('\n     No sample found in Autofocus for this hash')
            verdict_text = 'No sample found'

        HashCounters[verdict_text] += 1

# write hash data to text file; for index = 1 create new file; for index > 1 append to file
# hash_data_estack uses the non-pretty format with index to bulk load into ElasticSearch
# hash_data_pretty has readable formatting to view the raw hash context data

        if index == 1:
            with open('hash_data_estack.json', 'w') as hashFile:
                hashFile.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hashFile.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

            with open('hash_data_pretty.json', 'w') as hashFile:
                hashFile.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

        else:
            with open('hash_data_estack.json', 'a') as hashFile:
                hashFile.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hashFile.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

            with open('hash_data_pretty.json', 'a') as hashFile:
                hashFile.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

            with open('hash_data_stats.json', 'w') as hashFile:
                hashFile.write(json.dumps(HashCounters, indent=4, sort_keys=False) + "\n")

# print and write to file the current hash count stats
        HashCounters['total samples'] = index
        print('\nCurrent hash count stats:\n')
        print(json.dumps(HashCounters, indent=4, sort_keys=False) + '\n')
        with open('hash_data_stats.json', 'w') as hashFile:
            hashFile.write(json.dumps(HashCounters, indent=4, sort_keys=False) + "\n")

        index += 1

if __name__ == '__main__':
    main()
