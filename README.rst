==========================
Suricata for Probe Manager
==========================


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
~~~~~~~~~~~~

Module for `Suricata IDS <https://suricata-ids.org/>`_


Compatible version
==================

 * Suricata version 4.0.4 RELEASE


Features
========

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
~~~~~~~~~~~~

Install with `ProbeManager <https://github.com/treussart/ProbeManager/>`_
