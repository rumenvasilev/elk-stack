FreeRadius add-ons
==================

perlauth-3.4.pm - perl auth module for freeradius /802.1x auth/
==================
* dynamic VLAN mapping
* auto-registration of WIFI users /with limits for devices count per username/
* mac filter check
* ipplan database backend check (postgre) -> user, mac, IP 
* ldap database backend check -> user, vlan
* works with Extreme Networks switches (VLAN attributes returned to the switch), but can be easily modified to support any vendor.
==================
I've developed this code w/o any previous perl background, which is why
the code might not be the best one.
But it worked well in the environment where it was deployed.
