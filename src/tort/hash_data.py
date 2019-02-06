#!/usr/bin/env python
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import json
import time
import requests
import datetime

from project import app, es
from multiprocessing.dummy import Pool
from elasticsearch import helpers
from pan_cnc.lib import cnc_utils
from elasticsearch_dsl import connections
from elasticsearch_dsl import DocType, Search, Date, Integer, Keyword, Text, Object


def storeResults(results, outFile):
    '''
    Utility to store the results for the search based on user input either 
    into a file or into an ES DB. 
    
    Arguments:
        results {dict} -- if storing in the file it will be the json itself
                          if storing to DB, it will be the return status of the write
        outFile {string} -- if storing to a file, this the filename
    '''
    if "text" in app.config['OUTPUT_TYPE']:
        app.logger.debug(f"Writing results to {outFile}")
        with open(f"{outFile}", "a") as jsonFile:
            jsonFile.write(json.dumps(results, indent=4, sort_keys=False) + "\n")
        return {outFile:"NULL"}
    else:
        app.logger.info(f"Results stored in DB")
        app.logger.debug(f"Results are {results}") 
        return results

def loadJSON(hashJSON):
    '''
    Used with the ES bulkloader utility method to serialize the json to be 
    created as a do in the ES DB
    
    Arguments:
        hashJSON {dict} -- The JSON to be stored in the DB
    '''
    yield {
        "_index":"hash-data",
        "_type":"document",
        #"_id": f"{hashJSON['hashvalue']}",
        "_source": json.dumps(hashJSON)
    }

        
def init_hash_counters():

    """
    Use counters to create a simple output stats file in tandem with json details
    Initialize counters to zero
    """

    hash_counters = {}
    hash_count_values = ['total samples', 'malware', 'mal_inactive_sig', 'mal_active_sig',
                         'mal_no_sig', 'grayware', 'benign', 'phishing', 'No sample found']

    for value in hash_count_values:
        hash_counters[value] = 0

    return hash_counters


def elk_index(hashDict):

    """ Index setup for ELK Stack bulk install """

    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = "hash-data"
    index_tag_inner['_id'] = hashDict['hashvalue']
    index_tag_full['index'] = index_tag_inner

    return index_tag_full


def get_hash_list(filename):

    """ read the hash list from file and load into a list """

    hash_list = []

    with open(filename, 'r') as hash_file:
        hash_list = hash_file.read().splitlines()

    return hash_list


def init_query(af_ip, af_api_key, hashvalue):

    """
    initial API query post to Autofocus
    get_query_results used to check status and read query results
    """

    query = {"operator": "all",
             "children": [{"field":"alias.hash", "operator":"contains", "value":hashvalue}]
            }

    search_values = {"apiKey": af_api_key,
                     "query": query,
                     "size": 1,
                     "from": 0,
                     "sort": {"create_date": {"order": "desc"}},
                     "scope": "global",
                     "artifactSource": "af"
                    }

    headers = {"Content-Type": "application/json"}
    search_url = f'https://{af_ip}/api/v1.0/samples/search'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        print('Search query posted to Autofocus')
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    search_dict = {}
    search_dict = json.loads(search.text)
    app.logger.debug(f"Initial query for {hashvalue} returns {search_dict}")

    return search_dict


def get_query_results(af_ip, af_api_key, search_dict):

    """ check for a hit and then retrieve search results when hit = 1 """

    autofocus_results = {}

    cookie = search_dict['af_cookie']
    app.logger.debug(f'Tracking cookie is {cookie}')
    query_status = ''
    results_url = app.config['AUTOFOCUS_RESULTS_URL']
    cookie_url = results_url + cookie
    headers = {"Content-Type": "application/json"}
    results_values = {"apiKey": af_api_key}

    while query_status != 'FIN':

        time.sleep(5)
        try:    
            print(f"sending {cookie_url}")
            results = requests.post(url=cookie_url, headers=headers, data=json.dumps(results_values))
            results.raise_for_status()
        except requests.exceptions.HTTPError:
            print(results)
            print(results.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        autofocus_results = results.json()

        if 'total' in autofocus_results:
            if autofocus_results['total'] == 0:
                print('Now waiting for a hit...')
                print(autofocus_results)
            else:
                query_status = 'FIN'
        else:
            print('Autofocus still queuing up the search...')

    return autofocus_results


def get_sample_data(af_ip, af_api_key, hashvalue, af_hashtype, hash_counters):

    """ query each hash to gehashListString malware verdict and associated data """

    malware_values = {'0': 'bhashListStringnign', '1': 'malware', '2': 'grayware', '3': 'phishing'}


    hash_data_dict = {}
    app.logger.info(f'\nworking with hash {hashvalue}')

    search_dict = init_query(af_ip, af_api_key, hashvalue)
    autofocus_results = get_query_results(af_ip, af_api_key, search_dict)


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
        print('\n     No sample found in Autofocus for this hash')
        verdict_text = 'No sample found'

    app.logger.debug(f"get_sample_data() returns {hash_data_dict}")
    return hash_data_dict


def get_sig_coverage(af_ip, af_api_key, sample_data, hash_counters):

    """ for sample hits, second query to find signature coverage in sample analysis """

    print('Searching Autofocus for current signature coverage...')

    search_values = {"apiKey": af_api_key,
                     "coverage": 'true',
                     "sections": ["coverage"],
                    }

    headers = {"Content-Type": "application/json"}
    hashvalue = sample_data['sha256hash']
    search_url = f'https://{af_ip}/api/v1.0/sample/{hashvalue}/analysis'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()
    except Exception as e:
        app.logger.error(e)

    results_analysis = {}
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
    
    app.logger.debug(f"get_sig_coverage() returns {sample_data}")
    return sample_data, hash_counters


def write_to_file(index, index_tag_full, hash_data_dict, hash_counters):

    """
    write hash data to text file; for index = 1 create new file; for index > 1 append to file
    hash_data_estack uses the non-pretty format with index to bulk load into ElasticSearch
    hash_data_pretty has readable formatting to view the raw hash context data
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

        with open('hash_data_stats.json', 'w') as hash_file:
            hash_file.write(json.dumps(hash_counters, indent=4, sort_keys=False) + "\n")

    # print and write to file the current hash count stats
    hash_counters['total samples'] = index
    print('\nCurrent hash count stats:\n')
    print(json.dumps(hash_counters, indent=4, sort_keys=False) + '\n')
    with open('hash_data_stats.json', 'w') as hash_file:
        hash_file.write(json.dumps(hash_counters, indent=4, sort_keys=False) + "\n")


def processHashList(hashList,outputType,queryTag,hashType):

    """hash_data main module"""
    
    results = dict()
    outResults = dict()
    fileDate = datetime.datetime.now().strftime("%y-%m-%d-%H-%M")
    #outFile = f"{app.config['BASE_DIR']}/templates/output/{app.config['QUERY_TAG']}_{fileDate}.json"
    
    # Define the default Elasticsearch client
    connections.create_connection(hosts=cnc_utils.get_config_value('ELASTICSEARCH_HOST','localhost'))
    
    # Set the number of multi processes to use and cap it at 16 so
    # so we don't blow out the minute points on AutoFocus
    # multiProcNum = (app.config['TORT_POOL_COUNT'] 
    #                 if app.config['TORT_POOL_COUNT'] <= 2 else 2)

    # DEBUG_MODE means we only run 1 at a time, rather than multi-processing
    # if app.config['DEBUG_MODE'] != True:
    #     # Multiprocess the the hashes
    #     app.logger.debug(f"Running hashes through on {multiProcNum} processes")
    #     with Pool(multiProcNum) as pool:
    #         results = pool.map(getHashInfo, hashList)
    #     return storeResults(results,outFile)
    # else:
    for hashData in hashList:
        results = getHashInfo(hashData)
        outResults.update(storeResults(results,outFile))
    # if "text" in app.config['OUTPUT_TYPE']:
    #     return f"{outFile}"
    # else:
        return outResults
    

def getHashInfo(thisHash,outputType): 
    apiKey = cnc_utils.get_config_value("AUTOFOCUS_API_KEY","NOT-SET")
    hostname = "autofocus.paloaltonetworks.com"
    hashType = "MD5"
    now = datetime.datetime.now().replace(microsecond=0).isoformat('T')
    hashCounters = init_hash_counters()
    sampleData = {}
    hashDataDict = {}


    # query Autofocus to get sample and signature coverage data
    try:
        sampleData = get_sample_data(hostname, apiKey, thisHash, hashType, hashCounters)
    except Exception as e:
        logger.error(f"Unable to get sample data--ERROR: {e}")
 
    try:
        if sampleData['verdict'] != 'No sample found':
            hashDataDict, hashCounters = \
                get_sig_coverage(hostname, apiKey, sampleData, hashCounters)
    except Exception as e:
        logger.error(e)

    # Add some pertinent info to the data before saving
    hashDataDict['query_time'] = now
    hashDataDict['query_tag'] = app.config['QUERY_TAG']

    if 'text' in outputType:
        return hashDataDict
    else:
        try:
            result = helpers.bulk(es, loadJSON(hashDataDict))
            app.logger.debug(f"Result of indexing {thisHash} "
                            f"is {result}")
            if result[0] == 1:
                return {thisHash:"SUCCESS"}
            else:
                return {thisHash:"FAILURE"}
        except Exception as e:
            return {thisHash:f"Unknown error {e}"}

            
def save2Doc(dataDict):
    

    pass

if __name__ == '__main__':
    processHashes()
