Botan: Crypto and TLS for C++20
========================================

The `German Federal Office for Information Security (BSI) <https://www.bsi.bund.de/EN/>`_
carried out projects for the developement of a secure cryptographic library based on the
`Botan <https://botan.randombit.net>`_ cryptographic library. It satisfies the basic requirements
of the BSI and its use is recommended in security products. More information can be found `here <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Kryptografie/Kryptobibliothek-Botan/kryptobibliothek-botan_node.html>`_.
The library includes all algorithms  recommended by BSI technical guidelines `02102-1 <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html>`_,
`02102-2 <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html>`_ and `03111 <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03111/TR-03111_node.html>`_.
Botan is licensed under the Simplified BSD license and can therefore be freely
used in open source as well as commercial software.

All changes are provided `upstream <https://github.com/randombit/botan>`_ via the `Botan releases <https://botan.randombit.net/#releases>`_.
You can find the approved upstream releases on the `BSI webiste <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Kryptografie/Kryptobibliothek-Botan/kryptobibliothek-botan_node.html>`_.

In case an approved version differs from an official Botan version, a special `*-RSCS` version is released
in this repository. The changes are listed in the `release notes <news.rst>`_ and will be included in the next
Botan release.

Release Downloads
----------------------------------------

The latest RSCS version is `3.7.1-RSCS1 <https://github.com/Rohde-Schwarz/botan/releases/download/3.7.1-RSCS1/botan-3.7.1-RSCS1.zip>`_ (`sig <https://github.com/Rohde-Schwarz/botan/releases/download/3.7.1-RSCS1/botan-3.7.1-RSCS1.zip.sig>`_) released on 2025-03-28.

`SHA-256 <https://github.com/Rohde-Schwarz/botan/releases/download/3.7.1-RSCS1/botan-3.7.1-RSCS1.zip.hash>`_: F55EE971BC538E91A64174D9F576753A866C2C53AC6EC64F7DAB77076023AE65

All approved *-RSCS releases are signed with the following key::

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

Verify the release signature using Botan (where the public key listed above is referred to as *Botan-Signing-Key.pem*)::

  $ botan verify --hash=SHA-512 Botan-Signing-Key.pem botan-3.7.1-RSCS1.zip botan-3.7.1-RSCS1.zip.sig
  Signature is valid

Verify the release signature using OpenSSL and Python::

  $ python -m base64 -d botan-3.7.1-RSCS1.zip.sig | openssl dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 -verify Botan-Signing-Key.pem -signature /dev/stdin botan-3.7.1-RSCS1.zip
  Verified OK

Documentation
----------------------------------------

Botan provides a comprehensive `API documentation <https://botan.randombit.net/doxygen/>`_ as well as
a users `handbook <https://botan.randombit.net/handbook/>`_.

In addition to the official documentation, documents created during the BSI project such as
Crypto Specification and Audit Reports are found in the `botan-docs <https://github.com/sehlen-bsi/botan-docs>`_
repository.

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
