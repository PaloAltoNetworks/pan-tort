####!/usr/bin/env python3
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import json
import time
import requests

from panrc import hostname, api_key


def init_hash_counters():

    """
    initialize hash counters
    :return: send back hash counters = zero
    """

    hash_counters = {}
    hash_count_values = ['total samples', 'malware', 'mal_inactive_sig', 'mal_active_sig',
                         'mal_no_sig', 'grayware', 'benign', 'phishing', 'No sample found']

    for value in hash_count_values:
        hash_counters[value] = 0

    return hash_counters


def elk_index(elk_index_name):

    """
    set up elasticsearch bulk load index
    :param elk_index_name: name of data index in elasticsearch
    :return: index tag to write as line in the output json file
    """

    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = elk_index_name
    index_tag_inner['_type'] = elk_index_name
    index_tag_full['index'] = index_tag_inner

    return index_tag_full


def get_hash_list(filename):

    """
    read in the list of hashes from a text file
    :param filename: name of the hashfile
    :return: return list of hash values
    """

    with open(filename, 'r') as hash_file:
        hash_list = hash_file.read().splitlines()

    return hash_list


def init_query(hashvalue):

    """
    initial query into autofocus for a specific hash value
    :param hashvalue: hash for the search
    :return: autofocus response from initial query
    """


    query = {"operator": "all",
             "children": [{"field":"sample.sha256", "operator":"is", "value":hashvalue}]
            }

    search_values = {"apiKey": api_key,
                     "query": query,
                     "size": 1,
                     "from": 0,
                     "sort": {"create_date": {"order": "desc"}},
                     "scope": "public",
                     "artifactSource": "af"
                    }

    headers = {"Content-Type": "application/json"}
    search_url = f'https://{hostname}/api/v1.0/samples/search'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        print('Search query posted to Autofocus')
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    search_dict = json.loads(search.text)

    return search_dict


def get_query_results(search_dict):

    """
    keep checking autofocus until a hit or search complete
    :param search_dict: initial response including the cookie value
    :return: autofocus search results dictionary or null if no hits
    """

    autofocus_results = {}

    cookie = search_dict['af_cookie']
    print(f'Tracking cookie is {cookie}')

    for timer in range(60):

        time.sleep(5)
        try:
            results_url = f'https://{hostname}/api/v1.0/samples/results/' + cookie
            headers = {"Content-Type": "application/json"}
            results_values = {"apiKey": api_key}
            results = requests.post(results_url, headers=headers, data=json.dumps(results_values))
            results.raise_for_status()
        except requests.exceptions.HTTPError:
            print(results)
            print(results.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        autofocus_results = results.json()

        if 'total' in autofocus_results:
            if autofocus_results['total'] == 0 and autofocus_results['af_in_progress'] == 'true':
                print('     Now waiting for a hit...')
            elif autofocus_results['total'] == 0 and autofocus_results['af_in_progress'] == 'false':
                break
            else:
                break
        else:
            print('Autofocus still queuing up the search...')

    return autofocus_results


def get_sample_data(hashvalue, af_hashtype, hash_counters):

    """
    primary function to do both the init query and keep checking until search complete
    :param hashvalue: sample hash value
    :param af_hashtype: hash type to send into the init query
    :param hash_counters: updating running stats counters
    :return: update dictionary with sample data
    """

    malware_values = {'0': 'benign', '1': 'malware', '2': 'grayware', '3': 'phishing'}


    hash_data_dict = {}
    print(f'\nworking with hash = {hashvalue}')

    search_dict = init_query(hashvalue)
    autofocus_results = get_query_results(search_dict)


    # AFoutput is json output converted to python dictionary

    hash_data_dict['hashtype'] = af_hashtype
    hash_data_dict['hashvalue'] = hashvalue

    if autofocus_results['hits']:

    # initial AF query to get sample data include sha256 hash and WF verdict

        verdict_num = autofocus_results['hits'][0]['_source']['malware']
        verdict_text = malware_values[str(verdict_num)]
        hash_data_dict['verdict'] = verdict_text
        hash_data_dict['filetype'] = autofocus_results['hits'][0]['_source']['filetype']
        hash_data_dict['sha256hash'] = autofocus_results['hits'][0]['_source']['sha256']
        hash_data_dict['create_date'] = autofocus_results['hits'][0]['_source']['create_date']
        if 'tag' in autofocus_results['hits'][0]['_source']:
            hash_data_dict['tag'] = autofocus_results['hits'][0]['_source']['tag']
        print(f'Hash verdict is {verdict_text}')

        hash_counters[verdict_text] += 1

    # If no hash found then tag as 'no sample found'
    # These hashes can be check in VirusTotal to see if unsupported file type for Wildfire
    else:
        hash_data_dict['verdict'] = 'No sample found'
        hash_counters['No sample found'] += 1
        print('\nNo sample found in Autofocus for this hash')

    return hash_data_dict


def get_sig_coverage(sample_data, hash_counters):

    """
    secondary search into sample artifacts to get sig coverage data
    :param sample_data: base sample data dictionary to append sig data
    :param hash_counters: running stats counters
    :return: complete hash data set and hash running counters
    """

    print('Searching Autofocus for current signature coverage...')

    search_values = {"apiKey": api_key,
                     "coverage": 'true',
                     "sections": ["coverage"],
                    }

    headers = {"Content-Type": "application/json"}
    hashvalue = sample_data['sha256hash']
    search_url = f'https://{hostname}/api/v1.0/sample/{hashvalue}/analysis'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    results_analysis = json.loads(search.text)
    sample_data['dns_sig'] = results_analysis['coverage']['dns_sig']
    sample_data['wf_av_sig'] = results_analysis['coverage']['wf_av_sig']
    sample_data['fileurl_sig'] = results_analysis['coverage']['fileurl_sig']

    # Check all the sig states [true or false] to see active vs inactive sigs for malware

    if sample_data['verdict'] == 'malware':
        sig_search = json.dumps(sample_data)
        if sig_search.find('true') != -1:
            hash_counters['mal_active_sig'] += 1
        elif sig_search.find('true') == -1 and sig_search.find('false') != -1:
            hash_counters['mal_inactive_sig'] += 1
        else:
            hash_counters['mal_no_sig'] += 1

        # If no hash found then tag as 'no sample found'
        # These hashes can be check in VirusTotal to see if unsupported file type for Wildfire

    return sample_data, hash_counters


def write_to_file(index, index_tag_full, hash_data_dict, hash_counters):

    """
    write to 3 files: simple stats, full data as pretty json, and elasticsearch (estack) bulk load file
    :param index: simple check to see if should append or write to file
    :param index_tag_full: complete set of index data for json entry
    :param hash_data_dict: sample and sig data for json entry
    :param hash_counters: running stats counters
    :return: go back when write complete
    """

    if index == 1:
        with open('hash_data_estack.json', 'w') as hash_file:
            hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
            hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

        with open('hash_data_pretty.json', 'w') as hash_file:
            hash_file.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

    else:
        with open('hash_data_estack.json', 'a') as hash_file:
            hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
            hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

        with open('hash_data_pretty.json', 'a') as hash_file:
            hash_file.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

    # print and write to file the current hash count stats
    hash_counters['total samples'] = index
    print('\nCurrent hash count stats:\n')
    print(json.dumps(hash_counters, indent=4, sort_keys=False) + '\n')
    with open('hash_data_stats.json', 'w') as hash_file:
        hash_file.write(json.dumps(hash_counters, indent=4, sort_keys=False) + "\n")

    return


def main():

    """hash_data main module"""

    # Map starting index to 1 if a new run or one more than the last value as a continuing run
    # Init hash counters to zero

    hashfile = 'hash_list.txt'
    index_name = 'hash-data'

    # supported hashtypes are: md5, sha1, sha256
    if len(sys.argv) < 2:
        print('\nEnter the hash type after hash_data.py [md5, sha1, sha256]\n')
        sys.exit(1)
    elif sys.argv[1] == 'md5' or sys.argv[1] == 'sha1' or sys.argv[1] == 'sha256':
        hashtype = sys.argv[1]
    else:
        print('\nOnly hash types md5, sha1, or sha256 are supported\n')
        sys.exit(1)

    index = 1
    hash_counters = init_hash_counters()

    # read hash list from file
    hash_list = get_hash_list(hashfile)

    # iterate through the hash list getting sample and signature data

    for hashvalue in hash_list:

        hash_data_dict = {}

    # Used for Elasticsearch bulk import
    # Formatting requires index data per document record
        index_tag_full = elk_index(index_name)

    # query Autofocus to get sample and signature coverage data
        sample_data = get_sample_data(hashvalue, hashtype, hash_counters)

        if sample_data['verdict'] != 'No sample found':
            hash_data_dict, hash_counters = \
                get_sig_coverage(sample_data, hash_counters)

        # write output to file - per hash cycle to view updates during runtime
        write_to_file(index, index_tag_full, hash_data_dict, hash_counters)

        index += 1


if __name__ == '__main__':
    main()
