===========================
Suricata for  Probe Manager
===========================

Presentation
~~~~~~~~~~~~

|Licence| |Version|

Module for Suricata IDS


.. |Licence| image:: https://img.shields.io/github/license/matleses/ProbeManager_Suricata.svg
.. |Version| image:: https://img.shields.io/github/tag/matleses/ProbeManager_Suricata.svg

Features
========

 * Install and update Suricata NIDS on a remote server.
 * Configure the settings.
 * Add, Delete, Update scripts and signatures.
 * Tests signatures compliance.
 * Tests signatures if generates alert via Pcap.
 * Adding rules via HTTP or via upload file.
 * Scheduling rules update via HTTP (EmergingThreat ...)
 * Grouping rules into groups and assign this to probes.


TODO
====

 * increase tests


Source
~~~~~~

Models
======

.. automodule:: suricata.models
   :members:

Views
=====

.. automodule:: suricata.views
    :members:
    :undoc-members:
    :special-members:
    :inherited-members:
    :show-inheritance:
