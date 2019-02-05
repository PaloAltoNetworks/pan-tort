# Application Elements

This contains details for the application and template builder roles

### pan-cnc.yaml

In the cnc app, this drives the menu generation and workflow. The yaml
file is annotated for each workflow and menu item.

Highlights:

* defaults to the 8.1 iron-skillet and mssp-template repo branches

* Creates a simple menu structure for G-S-B and GPCS service configuration


### views.py

The local views.py file adds a few workflow elements to the application

##### Class: gsbProvisionView

* only shows the fw name option if auto-configure values is True


##### Class: gsbWorkflow02

* only shows the fw name option if auto-configure values is True

* sets the Panorama template, stack, and device-group name same as the fw name


### app/ChooseSnippetViewConfigs

Optional first level workflow items to augment standard snippet choices.

These are referenced in pan-cnc.yaml as a snippet attribute.

##### cnc-conf-gpcs

For GPCS baseline and remote network configurations

* generate a menu list for snippets with type = gpcs

* customer name and service term as demo elements

* demo selection of bandwidth tier for the remote network service onboarding

##### cnc-conf-gpcs-cpe

Part of the configuration menu mapped for sample CPE GPCS configurations.

* Creates a list by vendor/product with type = gpcs-cpe


##### cnc-conf-gsb-panorama

Internet gateway Gold-Silver-Bronze configuration mapped to the Panorama
snippets and API.

* Demo elements for customer, term, and size

* Menu choices for Gold, Silver, Bronze where type = internet_gateway_panorama


##### cnc-conf-gsb-panos

Internet gateway Gold-Silver-Bronze configuration mapped to the PAN-OS
snippets and API.

* Demo elements for customer, term, and size

* Menu choices for Gold, Silver, Bronze where type = internet_gateway_panos





