**************************
Suricata for Probe Manager
**************************


|Licence| |Version|


.. image:: https://api.codacy.com/project/badge/Grade/8ed3ca514eaa4aeb8941b082273444f3?branch=master
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/treussart/ProbeManager_Suricata?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_Suricata&amp;utm_campaign=Badge_Grade

.. image:: https://api.codacy.com/project/badge/Coverage/8ed3ca514eaa4aeb8941b082273444f3?branch=master
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
* Add rules via HTTP or via upload file.
* Schedule rules update via HTTP (EmergingThreat ...)
* Group rules into groups and assign this to probes.
* Possibility to add into blacklist an IP, Domain or MD5.
* Implements IP reputation.
* Ability to have scripts called via rules as a filter condition in signatures and to write arbitrary output.


Installation
============

Install with `ProbeManager <https://github.com/treussart/ProbeManager/>`_

Usage
=====

Administration Page of the module :
-----------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/admin-index.png
  :align: center
  :width: 80%


Page to add a Suricata IDS instance :
-------------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/admin-suricata-add.png
    :align: center
    :width: 80%

* Name: Give a unique name for this instance, example: server-tap1_suricata.
* Secure deployment: Specify if you want rules to be verified at each deployment.
* Scheduled rules deployment enabled: Enable scheduled deployment of rules.
* Scheduled check enabled: Enable instance monitoring. (Check if the probe is active)
* Server: Specify the server for the probe.
* Probe already installed: Specify if the probe is already installed.
* Rulesets: Choose the sets of rules that will be deployed on this probe.
* Configuration: Give the configuration of the probe.


Page to add a configuration :
-----------------------------

Allows you to modify the `Suricata configuration <http://suricata.readthedocs.io/en/latest/configuration/index.html>`_.

Simple
^^^^^^

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/admin-conf-add.png
  :align: center
  :width: 70%

* Under 'Conf advanced': there are the most important settings of Suricata to simplify the configuration. This application will generate the YAML file.

Advanced
^^^^^^^^

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/admin-conf-add-advanced.png
  :align: center
  :width: 90%

* 'Conf advanced': Allows to edit directly the YAML file.

Page to add a value in Blacklist :
----------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/admin-blacklist-add.png
  :align: center
  :width: 80%

* Type: (IP, MD5, HOST). For IP and HOST, a signature is created automatically. For `MD5 <http://suricata.readthedocs.io/en/latest/rules/file-keywords.html?highlight=MD5#filemd5>`_, a text file is stored with a single md5 per line.
* Value: The value for this type.
* Comment: To keep track of information.
* Rulesets: Choose the sets of rules that will contain this blacklist.

Page to add a reputation on an IP :
-----------------------------------

Allows you to use the `IP Reputation of Suricata <http://suricata.readthedocs.io/en/latest/reputation/index.html>`_.

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/admin-ipreputation-add.png
  :align: center
  :width: 55%

* Ip: Specify an IP address.
* Category: Specify a Category (short name and long description).
* Reputation score: The reputation score is the confidence that this IP is in the specified category, represented by a number between 1 and 127 (0 means no data).

Page to add a value in Classtype :
----------------------------------

Allows to modify and create new `Classtype <http://suricata.readthedocs.io/en/latest/rules/meta.html?#classtype>`_

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/admin-classtype-add.png
  :align: center
  :width: 60%

* Name: (IP, MD5, HOST). For IP and HOST, a signature is created automatically, for `MD5 <http://suricata.readthedocs.io/en/latest/rules/file-keywords.html?highlight=MD5#filemd5>`_, it store a text file with a single md5 per line.
* Description: A description for this classtype.
* Security Level: A priority of 1 (high) is the most severe and 4 (very low) is the least severe.

Page of an instance :
---------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Suricata/master/data/instance-index.png
  :align: center
  :width: 80%

* 'Uptime': indicate the time elapsed since the last time the application was started.
* 'Refresh Instance Status': is a button to know the status of the application (running or not).
* 'Update instance': you need to edit the configuration file to change the version number you want.
* 'Deploy configuration': copy configuration files to the remote server, and reload the Suricata instance.
* 'Deploy rules': copy rule (signatures and scripts) files to the remote server, and reload the Suricata instance.
* 'Deploy reputation list': copy the `IP and Category reputation <http://suricata.readthedocs.io/en/latest/reputation/index.html>`_ files to the remote server. The probe is not reloaded because if categories change, Suricata should be restarted. And Restarting can result in packet loss, which is why it is up to the user to intentionally restart.
