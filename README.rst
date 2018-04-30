**************************
Suricata for Probe Manager
**************************


|Licence| |Version|


.. image:: https://api.codacy.com/project/badge/Grade/8ed3ca514eaa4aeb8941b082273444f3?branch=develop
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/treussart/ProbeManager_Suricata?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_Suricata&amp;utm_campaign=Badge_Grade

.. image:: https://api.codacy.com/project/badge/Coverage/8ed3ca514eaa4aeb8941b082273444f3?branch=develop
   :alt: Codacy Coverage
   :target: https://www.codacy.com/app/treussart/ProbeManager_Suricata?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_Suricata&amp;utm_campaign=Badge_Coverage

.. |Licence| image:: https://img.shields.io/github/license/treussart/ProbeManager_Suricata.svg
.. |Version| image:: https://img.shields.io/github/tag/treussart/ProbeManager_Suricata.svg


Presentation
============

Module for `Suricata IDS <https://suricata-ids.org/>`_


Compatible version
------------------

 * Suricata version 4.0.4 RELEASE


Features
--------

 * Install and update Suricata NIDS on a remote server.
 * Configure the settings and test the configuration.
 * Add, Delete, Update scripts and signatures.
 * Tests signatures compliance.
 * Tests signatures if generates alert via Pcap.
 * Adding rules via HTTP or via upload file.
 * Scheduling rules update via HTTP (EmergingThreat ...)
 * Grouping rules into groups and assign this to probes.
 * Possibility to add into blacklist an IP, Domain or MD5.
 * Implements IP reputation.

Installation
============

Install with `ProbeManager <https://github.com/treussart/ProbeManager/>`_

Usage
=====

.. |Admin page| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/develop/data/admin-index.png
.. |Admin page for add a suricata instance| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/develop/data/admin-suricata-add.png
.. |Admin page for add a conf| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/develop/data/admin-conf-add.png
.. |Admin page for add a blacklist| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/develop/data/admin-blacklist-add.png
.. |Admin page for add a ipreputation| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/develop/data/admin-ipreputation-add.png
.. |Instance page| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/develop/data/instance-index.png


Administration Page of the module :
-----------------------------------

|Admin page|


Page to add a Suricata IDS instance :
-------------------------------------

|Admin page for add a suricata instance|

 * Give a unique name for this instance, example: server-tap1_suricata.


Page to add a configuration :
-----------------------------

|Admin page for add a conf|


Page to add a value in Blacklist :
----------------------------------

|Admin page for add a blacklist|


Page to add a reputation on an IP :
-----------------------------------

|Admin page for add a ipreputation|


Page of an instance :
---------------------

|Instance page|

 * Uptime indicate the time elapsed since the last time the application was started.
 * 'Refresh Instance Status' is a button to know the status of the application. (running or not)
 * Update instance, you need to edit the conf file to change the version number you want.
 * Deploy configuration, copy configuration files to the remote server, and reload the Bro instance.
 * Deploy rules, copy rules (signatures and scripts) files to the remote server, and reload the Bro instance.
 * Deploy reputation list, copy the IP and Category reputation files to the remote server.
