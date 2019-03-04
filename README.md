
# Test Output Results Toolkit

This utility is provided to enable Systems Engineers to load hashes from failed Ixia and/or Spirent security tests.  It will then process the hashes against the Palo Alto Networks Threat Intelligence Cloud to determine the reason why the hash was not found/blocked/inidcated in the passing results. 

It interfaces with both Autofocus (pull) and ELK (optional push) API interfaces.

## How to run TORT
The only *supported* way to run TORT is to run the docker container:
```
docker run -p 8088:80 paloaltonetworks/pan-tort:latest
```
Once the container is up and running - point your browser to http://localhost:8088

***Login is paloalto/tort***

NOTE:  This does not support pushing the results to ELK - yet


# Advanced TORT - pushing to ELK
To push the results to your ELK instance, you must have a .panrc in your home directory with the following entries (at minimum)
```
ELASTICSEARCH_HOST = "<ip of elasticsearch host>"
ELASTICSEARCH_PORT = "<port - default es install port is 9200>"
```
Optionally you can also add your API key to the .panrc as well:
```
AUTOFOCUS_API_KEY = "<api_key>"
```
Once you have that in place you can start the container by mounting the .panrc inside the container
```
docker run -p 8088:80 -v ~/.panrc:/.panrc paloaltonetworks/pan-tort:latest
```
If you added the AF API key, you don't have to type it in anymore. :)
