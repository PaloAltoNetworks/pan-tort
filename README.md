
# MSSP Configuration Loader

This utility is provided to enable API-based configuration using the
[Palo Alto Networks MSSP templates](https://github.com/scotchoaf/mssp-templates/tree/81dev)

It interfaces with both Panorama and the firewall PAN-OS API interfaces.

### Internet Gateway service

This uses the Gold-Silver-Bronze template set to configure tiered
services based on MSSP offerings and device subscriptions.

Templates include:

    * internet gateway base config with interfaces, zones, routing

    * gold/silver/bronze tier tags and security rules


### GPCS

This is based on remote network access to the internet using GPCS

Template elements include:

    * baseline GPCS config for new service onboarding

    * remote network IPSEC onboarding

    * sample CPE IPSEC configs that text render only, no API configuration





