=================
Botan Test Report
=================

Preface
=======

**Summary**

The objective of this project is the secure implementation of a universal crypto
library which contains all common cryptographic primitives that are necessary for
the wide use of cryptographic operations. These include symmetric and asymmetric
encryption and signature methods, PRFs, hash functions and RNGs. Additionally,
security standards such as X.509 and SSL/TLS have to be supported. The library will
be provided to manufacturers of VS-NfD products which will help the Federal Office
for Information Security (BSI) to evaluate these products.

This document reports the test results of the Botan test suite.

**Authors**

| Daniel Neus (DN)
| René Fischer (RK)
| René Meusel (RM)

**Copyright**

This work is protected by copyright law. Every application outside of
copyright law without explicit permission by the
Federal Office for Information Security (BSI) is forbidden and will be prosecuted.
This holds especially for the reproduction, translation, microfilming and
storing and processing in electronic systems.

.. raw:: latex

   \pagebreak

Changelog
=========

.. table::
   :class: longtable

   +---------+----------+---------------------------------------------+------------+
   | Version | Authors  | Comment                                     | Date       |
   +=========+==========+=============================================+============+
   | 1.0.0   | DN, RK   | Initial version                             | 2016-11-11 |
   +---------+----------+---------------------------------------------+------------+
   | 1.1.0   | RK       | Update to Botan 2.0.0                       | 2017-01-09 |
   +---------+----------+---------------------------------------------+------------+
   | 1.2.0   | DN       | Update to Botan 2.0.1-RSCS1                 | 2017-03-06 |
   +---------+----------+---------------------------------------------+------------+
   | 1.3.0   | RK       | Update to Botan 2.4.0                       | 2018-05-07 |
   +---------+----------+---------------------------------------------+------------+
   | 1.3.1   | RK       | Update to latest Botan 2.4.0-RSCS1          | 2018-05-07 |
   +---------+----------+---------------------------------------------+------------+
   | 1.4.0   | RK       | Update to Botan 2.14.0-RSCS1                | 2020-06-24 |
   +---------+----------+---------------------------------------------+------------+
   | 1.5.0   | RM       | Update to Botan 3.0.0-alpha1-BSI1           | 2022-11-21 |
   +---------+----------+---------------------------------------------+------------+
   | 2.0.0   | RM       | | Switch to automatically generated test    | -          |
   |         |          | | report. End of the changelog.             |            |
   +---------+----------+---------------------------------------------+------------+

.. raw:: latex

   \pagebreak

Test Report
===========

The following report lists the test results for the Botan test suite.
The following information is given for each test run:

 * Information about the test environment
    * Botan configuration
    * Date and time of execution
    * Operating system
    * Compiler and compiler version
    * Target architecture
 * Number of tests executed
    * Of these, the number of tests executed successfully
    * Of these, the number of failed tests
 * A list of failed tests and the reason for each test failure

.. raw:: latex

   \pagebreak