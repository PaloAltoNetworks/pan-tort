# Hash Search as part of the Testing Output Response Toolkit


# Install & start the hash search application
### 1. Clone repo
```git clone https://www.github.com/PaloAltoNetworks/pan-tort.git```
<br/>
### 2. Change into repo directory
```cd pan-tort```
<br/>
### 3. Create python 3.6 virtualenv
```python3.6 -m venv env```
<br/>
### 4. Activate virtualenv
```source env/bin/activate```
<br/>
### 5. Download required libraries
```pip install -r requirements.txt```
<br/>
### 6. Create the panrc.py file for your installation to have Autofocus API access
[Create panrc.py](https://github.com/PaloAltoNetworks/pan-tort/wiki/panrc)
<br/>
### 7. Create the hash_list.txt file to read hashes for Autofocus contextual queries
[Create hash_list.txt](https://github.com/PaloAltoNetworks/pan-tort/wiki/hash_list)
<br/>
### 9. Run hash_data.py to begin queries and retrieving verdict, filetype, and coverage information
```python hash_data.py```
<br/>
### 10. Viewing output json files
*hash_data_stats.json:  quick stats for verdicts and signature coverage (active or inactive)
<br/>
*hash_data_pretty.json:  raw data view of per-hash Autofocus responses
<br/>
*hash_data_estack.json:  raw data output with index to bulk load into ElasticSearch/Kibana for visualization

[ElasticStack Visualization](https://github.com/PaloAltoNetworks/pan-tort/wiki/elasticStack)
<br/><br/>
## Best Practices and Optional Configuration
You should be all set.  For even more ideas on what you can do with the system and other things that you can download and install to get the most out of pan-tort, checkout the [Wiki](https://github.com/PaloAltoNetworks/pan-tort/wiki)!!