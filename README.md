#!/usr/bin/env python
# Exploit Title: Paid Memberships Pro  v2.9.8 (WordPress Plugin) - Unauthenticated SQL Injection
# Exploit Author: r3nt0n
# CVE: CVE-2023-23488
# Date: 2023/01/24
# Vulnerability discovered by Joshua Martinelle
# Vendor Homepage: https://www.paidmembershipspro.com
# Software Link: https://downloads.wordpress.org/plugin/paid-memberships-pro.2.9.7.zip
# Advisory: https://github.com/advisories/GHSA-pppw-hpjp-v2p9
# Version: < 2.9.8
# Tested on: Debian 11 - WordPress 6.1.1 - Paid Memberships Pro 2.9.7
#
# Running this script against a WordPress instance with Paid Membership Pro plugin
# tells you if the target is vulnerable.
# As the SQL injection technique required to exploit it is Time-based blind, instead of
# trying to directly exploit the vuln, it will generate the appropriate sqlmap command
# to dump the whole database (probably very time-consuming) or specific chose data like
# usernames and passwords.
#
# Usage example: python3 CVE-2023-23488.py http://127.0.0.1/wordpress
