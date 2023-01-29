Botan: Crypto and TLS for C++11
========================================

The `German Federal Office for Information Security (BSI) <https://www.bsi.bund.de/EN/>`_
carried out a project "Secure Implementation of a Universal Crypto Library"
in which it analyzed open source cryptographic libraries and developed a secure
cryptographic library based on the `Botan <https://botan.randombit.net>`_ cryptographic library.
Botan 2.0 satisfies the basic requirements of the BSI and
its use is recommended in security products. The library includes all algorithms 
recommended by BSI technical guidelines `02102-1 <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html>`_,
`02102-2 <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html>`_ and `03111 <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03111/TR-03111_node.html>`_.
Botan is licensed under the Simplified BSD license and can therefore be freely 
used in open source as well as commercial software.

This repository contains versions of Botan that are approved by the BSI. All changes made
to Botan during the project were contributed to the original project. Our goal is to keep 
this fork in sync with the official repository, but we cannot assure this. In case an approved
version differs from an official Botan version, the changes are listed in the `release notes <news.rst>`_.

Versioning
----------------------------------------

The versioning scheme used here is based on that of the
`original project <https://botan.randombit.net/news.html>`_. In case
there are differences between an official release version and an approved version,
the approved version number will contain the original version it is based on followed by
a `RSCSN` suffix. For example, the version 2.4.0-RSCS1 is based on the official
Botan version 2.4.0, but contains additional changes that are not part of 2.4.0
(but may be part of a future Botan version).
New Botan releases will be audited on a regular basis and cryptographically relevant
changes will be checked and documented. These releases will eventually be
released here when approved by the BSI.

Release Downloads
----------------------------------------

The latest version is `2.4.0-RSCS1 <https://cdn.rohde-schwarz.com/pws/dl_downloads/dl_software/zip/Cybersecurity-software-Botan-2.4.0-RSCS1.zip>`_ (`sig <https://cdn.rohde-schwarz.com/pws/dl_downloads/dl_software/sig/Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sig>`_) released on 2018-09-28.

`SHA-256 <https://cdn.rohde-schwarz.com/pws/dl_downloads/dl_software/sha256/Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sha256>`_: EADC9A20FBE6AF4725CBA26B0636C1244083BAF4F936A129AF498D056EACBF75

All approved releases are signed with the following key::
  
  -----BEGIN PUBLIC KEY-----
  MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyGKrzmfZhGuIaMXGZ56x
  yKtzTuvDrK50edCd1/EccVtS1V/52bmM/mfWaTCvUKUd+BlKw544L+hEaMdoGMvj
  rkJL70DxU+fqV3NHBJKDqV+fJi4X8iWPIq3B/Tu08jFYjeHoRDN3BcaGFSQnR9lC
  1p3PXbga8Mpk5Qe93ca3tGawr2AKt0ImdVwWvcPlL2JHr63jB0YARYzf1M8DtDzk
  RQewoyrxbyQbup4Qgd2IbJsfTbNxgeWFMSeiBEZVnqVosKvzLybXZpmbmZSxQr64
  qT8JRzlJbIh3RrJlfGPu2YFojg9x+uL0KqGGPhqDFIR/UQdW1Ve+kjh7MaSQJsnZ
  u/+HoGJVSDfkiW1ZLPfYHDye85e4c5z4JCxbOMn2IVSlFWxfrNjaIU6jEjxyS09E
  6W9Yr2r5iC/ef5BFc38JgVuvfMa3RJHSqY4AfIl+GnozwtKzYsedfKAZkZUx+kiu
  65FdQqHR1iMrM4kxmRIeYxttdF7h0NzU7CGGXoVV14qRMQ9ZMTHPyasqmt5JihK6
  cyn9e8DPzgndm2HhBJeQdSMCWraZoZqO8GjzuTuSVtt4a3C/G++rpLA9RXHRwK1P
  UjeWn1B9Pd6fX4oZ1/eQF+Y5oZnl80IsILOE2CdxEKN2TNQftESdKNNWe+nCEY1c
  sSPNDnqFuHxJaS2oS5A3BBUCAwEAAQ==
  -----END PUBLIC KEY-----

The SHA-256 public key fingerprint is B1B688ED5FD24ACD53E73BE74A5279916471B2A9C80BC33AA9A7EDC58A715CF0.

Verify the release signature using Botan (where the public key listed above is referred to as *Botan-Signing-Key.pem*)::

  $ botan verify --hash=SHA-512 --emsa=EMSA4 Botan-Signing-Key.pem Cybersecurity-software-Botan-2.4.0-RSCS1.zip Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sig
  Signature is valid

Verify the release signature using OpenSSL (you need to base64 decode the signature first)::

  $ type Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sig | openssl base64 -d -out Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sig.dec

or alternatively using python::

  $ python -m base64 -d Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sig > Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sig.dec

  $ openssl dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 -verify Botan-Signing-Key.pem -signature Cybersecurity-software-Botan-2.4.0-RSCS1.zip.sig.dec Cybersecurity-software-Botan-2.4.0-RSCS1.zip
  Verified OK

Documentation
----------------------------------------

Botan provides a comprehensive `API documentation <https://botan.randombit.net/doxygen/>`_ as well as
a users `handbook <https://botan.randombit.net/handbook/>`_.

API documentation and the handbook for the latest version approved by the BSI can be found here:

* `API documentation <doc/bsi/doxygen.zip>`_
* `Handbook <doc/bsi/handbook.pdf>`_

In addition to the official documentation, we provide the following documents,
which were created during the BSI project:

* `Software architecture <doc/bsi/architecture.pdf>`_
* `Implementation of cryptographic algorithms and protocols <doc/bsi/crypto.pdf>`_
* `Specification of tests <doc/bsi/testspecification.pdf>`_
* `Test report <doc/bsi/testreport.pdf>`_

Support & Maintenance
----------------------------------------

If you need help with a problem, please `open an issue <https://github.com/randombit/botan/issues/new>`_
at the offical GitHub repository. In case you want to contribute some changes, please also
`contribute <https://github.com/randombit/botan/compare>`_ them to the official Botan repository.

BSI Compliant Usage of Botan
----------------------------------------

Botan contains a `BSI module policy <src/build-data/policy/bsi.txt>`_ which includes all algorithms recommended by BSI
technical guidelines and prohibits alternative algorithms.
To configure Botan with the BSI policy::

  $ ./configure.py --module-policy=bsi

Additional modules which are not automatically enabled by the BSI policy
can be enabled manually using `--enable-modules`, for example::

  $ ./configure.py --module-policy=bsi --enable-modules=tls,ffi,x509,xts

TLS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Botan contains a TLS Policy class `BSI_TR_02102_2 <src/lib/tls/tls_policy.h>`_ that only allows the algorithms recommended in
BSI technical guideline `02102-2 <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html>`_.
This policy can be passed whereever a ``TLS_Policy`` reference is accepted by the API.
For more information, see the `handbook <https://botan.randombit.net/handbook/api_ref/tls.html>`_.


Random Number Generation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Botan contains an implementation of `NIST SP 800-90A <https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final>`_'s `HMAC_DRBG <src/lib/rng/hmac_drbg/hmac_drbg.h>`_.
The parameters reseed interval, maximum number of bytes per request and the entropy source(s) for
seeding and reseeding can be configured per ``HMAC_DRBG`` instance. For example,
a ``PKCS11_RNG`` can be used as an entropy source::

  Botan::PKCS11::PKCS11_RNG p11_rng(session);
  Botan::HMAC_DRBG drbg(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"), p11_rng);

``HMAC_DRBG`` will automatically reseed whenever the reseed interval or maximum number
of bytes per request are exceeded. On platforms which support ``fork()``, it will also
automatically reseed after a fork. For more information, see the `handbook <https://botan.randombit.net/handbook/api_ref/rng.html>`_.


