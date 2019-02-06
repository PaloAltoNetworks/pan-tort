# Application Elements

This contains details for the application and template builder roles

### pan-cnc.yaml

In the cnc app, this drives the menu generation and workflow. The yaml
file is annotated for each workflow and menu item.

Highlights:

* Builds UI 

* Defines workflow and branches based on selections


### views.py

The local views.py file adds a few workflow elements to the application

##### Class: tortView

* Used to validate the information from the form and make appropriate calls to methods for processing the hashes


### app/run_tort/.meta-cnc.yaml

* Defines the layout of the portal and shows only those parameters that we need