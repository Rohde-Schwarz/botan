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
You can find the approved upstream releases on the `BSI website <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Kryptografie/Kryptobibliothek-Botan/kryptobibliothek-botan_node.html>`_.

In case an approved version differs from an official Botan version, a special `*-RSCS` version is released
in this repository. The changes are listed in the `release notes <news.rst>`_ and will be included in the next
Botan release.

Release Downloads
----------------------------------------

The latest RSCS version is `3.7.1-RSCS1 <https://github.com/Rohde-Schwarz/botan/releases/download/3.7.1-RSCS1/botan-3.7.1-RSCS1.zip>`_ (`sig <https://github.com/Rohde-Schwarz/botan/releases/download/3.7.1-RSCS1/botan-3.7.1-RSCS1.zip.sig>`_) released on 2025-03-28.

`SHA-256 <https://github.com/Rohde-Schwarz/botan/releases/download/3.7.1-RSCS1/botan-3.7.1-RSCS1.zip.hash>`_: F55EE971BC538E91A64174D9F576753A866C2C53AC6EC64F7DAB77076023AE65

The release can be verified with the following certificate ``certBotan.pem``::

  -----BEGIN CERTIFICATE-----
  MIIHCjCCBPKgAwIBAgITWQABJxyBe2TeKW/9ywADAAEnHDANBgkqhkiG9w0BAQsF
  ADBoMQswCQYDVQQGEwJERTEQMA4GA1UECAwHQmF2YXJpYTEPMA0GA1UEBwwGTXVu
  aWNoMRYwFAYDVQQKDA1Sb2hkZS1TY2h3YXJ6MR4wHAYDVQQDDBVSb2hkZS1TY2h3
  YXJ6LVVzZXItQ0EwHhcNMjUwNDI0MTEyMDUxWhcNMjcwNDI0MTEyMDUxWjATMREw
  DwYDVQQDDAhTQV9CT1RBTjB2MBAGByqGSM49AgEGBSuBBAAiA2IABEyUT731zCmx
  zY8NJA4T2+5gIMmLJnsuwkbhJbO26dOb4h/xNL5a0wcvTDWqkUlJ8Tsr2hrpJOc1
  N5BpvYoSa1quTQHzBXS4Dm+YPIULPnDe8X9ZXkZQGvbqKGq9br0fc6OCA64wggOq
  MB0GA1UdDgQWBBT84ZPVOLOFtJSWxXz5SbcencFg1DALBgNVHQ8EBAMCB4AwHwYD
  VR0jBBgwFoAUXgYDIHF8OB7lAKIfi3TUY5IvbiMwggEVBgNVHR8EggEMMIIBCDCC
  AQSgggEAoIH9hoG7bGRhcDovLy9DTj1Sb2hkZS1TY2h3YXJ6LVVzZXItQ0EoMyks
  Q049Q01VMDMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
  cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cnNpbnQsREM9bmV0P2NlcnRpZmlj
  YXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRp
  b25Qb2ludIY9aHR0cDovL3BraS5yb2hkZS1zY2h3YXJ6LmNvbS9jcmwvUm9oZGUt
  U2Nod2Fyei1Vc2VyLUNBKDMpLmNybDCBhwYIKwYBBQUHAQEEezB5MC0GCCsGAQUF
  BzABhiFodHRwOi8vcGtpLnJvaGRlLXNjaHdhcnouY29tL29jc3AwSAYIKwYBBQUH
  MAKGPGh0dHA6Ly9wa2kucm9oZGUtc2Nod2Fyei5jb20vY2EvUm9oZGUtU2Nod2Fy
  ei1Vc2VyLUNBKDMpLmNydDAMBgNVHRMBAf8EAjAAMD0GCSsGAQQBgjcVBwQwMC4G
  JisGAQQBgjcVCIT/01qHwLAlhM2JPIP20QqGv81+Z4L64F+CtfVHAgFkAgEkMB8G
  A1UdJQQYMBYGCisGAQQBgjcKAwwGCCsGAQUFBwMEMCkGCSsGAQQBgjcVCgQcMBow
  DAYKKwYBBAGCNwoDDDAKBggrBgEFBQcDBDA4BgNVHREEMTAvoC0GCisGAQQBgjcU
  AgOgHwwdc2FfYm90YW4uc2FAcm9oZGUtc2Nod2Fyei5jb20wUQYJKwYBBAGCNxkC
  BEQwQqBABgorBgEEAYI3GQIBoDIEMFMtMS01LTIxLTIxOTIyNjcyODMtMzUwMzk4
  Nzg3Ny0yNzA2NDYyNTc1LTcwNDU2NjCBkQYDVR0gBIGJMIGGMEUGCisGAQQBlAZn
  ZAMwNzA1BggrBgEFBQcCARYpaHR0cDovL3BraS5yb2hkZS1zY2h3YXJ6LmNvbS9D
  ZXJ0Y2xhc3Nlcy8wPQYKKwYBBAGUBmcAADAvMC0GCCsGAQUFBwIBFiFodHRwOi8v
  cGtpLnJvaGRlLXNjaHdhcnouY29tL0NQUy8wDQYJKoZIhvcNAQELBQADggIBAIPy
  Tw8bYszGJvJueGJq4O2Pyg9Qb99JtOFi3jtWwWY6REbF11LTiEJhlgQ920u5JlSL
  4mfJvFRykXvSX+j5Gi8UBwoyEXcJjE7HJCG2SFXGSSX6ZYtsqqYkUadzUKCe/34K
  A2djoU60bwJPZ6bPmjKVjH8R1WNOvRh+w6TwIuiNm7zFS0yKUEnJtKHKGNev593u
  rw5t/3GRJLvcuRd/XL4QbO7/19pNnnCSrX7At0bbHBDlNt5u7cVunKdZNDPW5fsS
  IviShSchvUbBMkHLslGpDfxmBiw1gBBaRvcowBywTr9vQ/mxYyi+uGTykamAehm2
  zd5u1EBTQs2Dem9d9pXUDdsU+/+RAr95rN55IbW8FwYSufl6k5ubmamjwmayKo+X
  glnoBSaPdXblabHSnwvZ9Rpsr4UxuHO7yTHCQVNknvoXT+EIUtUEmGK8umwjDUnY
  FsGDJYj3qP2UrYtqgx3KX/33B0dQNojzPrKuzxlVtDYhmLWg3Dbawd7E7pP/58Tc
  DsK/rhTAt19VPX5USNlIGQSk4XPjN+vW6hWqTpEzuPe5NvjVzWn6sPLaY2C3JP4T
  HWxiQfpnZE+f+LJWfJ8mhLFYckozMM55mvTTrU8rCjIK05fiyNV+o8sf18gxd5mO
  tUrRBCAhqojI7PFlrP50Ra7xsOZ/WuF5883UuD4x
  -----END CERTIFICATE-----

To verify the signature, do the following steps:

1. Verify ``certBotan.pem`` with the `Rohde & Schwarz PKI <https://pki.rohde-schwarz.com/RS-Certificates.html>`_

::

  $ wget "https://pki.rohde-schwarz.com/CA/Rohde-Schwarz-User-CA(3).pem" && wget "https://pki.rohde-schwarz.com/CA/Rohde-Schwarz-Root-CA(2).pem"

::

  $ openssl verify -CAfile "Rohde-Schwarz-Root-CA(2).pem" -untrusted "Rohde-Schwarz-User-CA(3).pem" certBotan.pem

2. Extract public key from ``certBotan.pem``

::

  $ openssl x509 -in certBotan.pem -pubkey -noout > pubkeyBotan.pem

3. Verify signature

::

  $ openssl dgst -sha384 -verify pubkeyBotan.pem -signature botan-3.7.1-RSCS1.zip.sig botan-3.7.1-RSCS1.zip

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
