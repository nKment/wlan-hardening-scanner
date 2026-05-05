# WLAN Hardening Scanner

Prototype scanner for the structured assessment of WLAN hardening measures in small enterprise environments.

This project was developed as part of a bachelor thesis on the hardening of WLAN access points in small enterprises. The scanner evaluates baseline and hardened WLAN configurations by combining automated client-side network observations with manually documented configuration values.

## Overview

The scanner is designed to support a structured and partially automated assessment of WLAN security configurations. It does not replace manual analysis or device-level auditing, but operationalizes selected criteria of a custom evaluation model.

The prototype focuses on the following security categories:

- Authentication and Encryption
- Management Access Control
- Network Segmentation
- Network Exposure
- Known Insecure Features / Vulnerabilities

Each category is scored from 0 to 3 and weighted to produce a final security score.

## Purpose

The goal of this project is to demonstrate how selected WLAN hardening criteria can be translated into a reproducible and partially automated assessment workflow.

The scanner compares a baseline WLAN configuration with hardened configurations and helps answer questions such as:

- Is the client in the expected subnet?
- Is the gateway correct and reachable?
- Are management hosts reachable from ordinary client networks?
- Are management-related ports exposed or filtered?
- How many hosts are visible in the client subnet?
- Do the observed results match the intended hardened design?

## How the scanner works

The scanner combines two input sources.

### 1. Automated client-side checks

The scanner runs standard macOS command-line tools to collect observable network properties, including:

- current IP configuration
- local gateway reachability
- external reachability
- management host reachability
- management port exposure
- visible hosts in the local subnet
- ARP entries

### 2. Manually recorded configuration values

Some security-relevant properties cannot be derived reliably from the client perspective alone. These are therefore documented manually in YAML files, including:

- authentication mode
- WPS status
- VLAN presence
- management network configuration
- SSID-to-VLAN mapping

The scanner combines both sources and maps them to explicit scoring rules.

## Scoring model

The scanner implements a weighted multi-level evaluation model.

### Categories and weights

| Category | Weight |
|---|---:|
| Authentication and Encryption | 3 |
| Management Access Control | 3 |
| Network Segmentation | 2 |
| Network Exposure | 2 |
| Known Insecure Features / Vulnerabilities | 3 |

### Score scale

Each category is scored from 0 to 3:

- **0** = absent / ineffective / clearly insufficient
- **1** = basic protection
- **2** = improved / partially hardened
- **3** = strong and appropriately implemented measure

### Maximum score

The maximum possible score is:

```text
39 points
Example interpretation

A hardened WLAN that uses WPA3-Personal, disables WPS, separates internal, guest, and management traffic, and restricts management exposure should achieve a significantly higher score than a flat baseline WLAN with WPA2-PSK and exposed management services.

Project structure
wlan-hardening-scanner/
├── scanner.py
├── config.yaml
├── observed_baseline.yaml
├── observed_hardened.yaml
├── reports/
└── README.md
File descriptions
scanner.py

Main scanner implementation. Runs automated checks, applies scoring logic, and prints or exports results.

config.yaml

Contains:

scan profiles
expected subnets
expected gateways
management hosts
discovery subnets
category weights
observed_baseline.yaml

Manually documented configuration values for the baseline WLAN setup.

observed_hardened.yaml

Manually documented configuration values for the hardened WLAN setup.

reports/

Optional output directory for generated JSON reports.

Requirements

This prototype was developed and tested on macOS.

Required software
Python 3
PyYAML
Nmap
Why macOS?

The scanner currently uses the macOS utility:

networksetup

This means the current implementation is intended for macOS and will not run unchanged on Windows or Linux.

Setup
1. Clone the repository
git clone https://github.com/nKment/wlan-hardening-scanner.git
cd wlan-hardening-scanner
2. Create a virtual environment
python3 -m venv .venv
3. Activate the virtual environment
source .venv/bin/activate
4. Install Python dependency
pip install pyyaml
5. Install Nmap

If you use Homebrew:

brew install nmap
6. Verify installation
python3 --version
python3 -m pip --version
nmap --version
Configuration files

Before running the scanner, review the YAML files carefully.

config.yaml

This file defines the scan profiles and scoring weights.

Typical content includes:

expected client subnet
expected gateway
external test IP
discovery subnet
management gateway
management hosts
category weights
Example structure
weights:
  authentication_and_encryption: 3
  management_access_control: 3
  network_segmentation: 2
  network_exposure: 2
  known_insecure_features_or_vulnerabilities: 3

profiles:
  baseline:
    expected_subnet: 192.168.1.0/24
    expected_gateway: 192.168.1.1
    external_test_ip: 8.8.8.8
    discovery_subnet: 192.168.1.0/24
    management_gateway: null
    management_hosts:
      - 192.168.1.2

  hardened_internal:
    expected_subnet: 192.168.20.0/24
    expected_gateway: 192.168.20.1
    external_test_ip: 8.8.8.8
    discovery_subnet: 192.168.20.0/24
    management_gateway: 192.168.99.1
    management_hosts:
      - 192.168.99.2
      - 192.168.99.3

  hardened_guest:
    expected_subnet: 192.168.30.0/24
    expected_gateway: 192.168.30.1
    external_test_ip: 8.8.8.8
    discovery_subnet: 192.168.30.0/24
    management_gateway: 192.168.99.1
    management_hosts:
      - 192.168.99.2
      - 192.168.99.3
observed_baseline.yaml

This file contains manually recorded values for the baseline WLAN.

Example:

auth_mode: "wpa2_psk"
wps_disabled: false
vlans_present: []
management_network_configured: false
ssid_to_vlan_mapping: {}
observed_hardened.yaml

This file contains manually recorded values for the hardened WLAN.

Example:

auth_mode: "wpa3_personal"
wps_disabled: true
vlans_present:
  - 20
  - 30
  - 99
management_network_configured: true
ssid_to_vlan_mapping:
  SME-Internal: 20
  SME-Guest: 30
Running the scanner

The scanner supports three profiles:

baseline
hardened_internal
hardened_guest
Run baseline scan
python3 scanner.py --profile baseline --observed observed_baseline.yaml --json-out reports/baseline.json
Run hardened internal scan
python3 scanner.py --profile hardened_internal --observed observed_hardened.yaml --json-out reports/hardened_internal.json
Run hardened guest scan
python3 scanner.py --profile hardened_guest --observed observed_hardened.yaml --json-out reports/hardened_guest.json
Example terminal output
========================================================================
WLAN Hardening Assessment: hardened_internal
========================================================================
Client IP: 192.168.20.101
Gateway:   192.168.20.1
IP in expected subnet: True
Gateway matches expected: True
Gateway reachable: True
External reachable: True
Hosts up in discovery scan: 1

Management hosts:
  - 192.168.99.2: ping=False, ports={80: 'filtered', 443: 'filtered'}
  - 192.168.99.3: ping=False, ports={80: 'filtered', 443: 'filtered'}
Management gateway reachable: True

Category scores:
  - Authentication and Encryption: 3/3, weight=3, weighted=9
  - Management Access Control: 2/3, weight=3, weighted=6
  - Network Segmentation: 3/3, weight=2, weighted=6
  - Network Exposure: 2/3, weight=2, weighted=4
  - Known Insecure Features / Vulnerabilities: 3/3, weight=3, weighted=9

Weighted total: 34 / 39
Security level: 87.2%
========================================================================
JSON report output

If --json-out is used, the scanner writes a JSON report that includes:

selected profile
raw and parsed network observations
manually documented values
category scores
weighted scores

This makes it possible to keep structured scan results for later analysis or documentation.

Implemented checks

The prototype currently performs the following automated checks:

Wi-Fi client IP and gateway extraction
subnet validation
gateway validation
gateway ping
external ping
management gateway ping
management host ping
management host web port scan
ARP table inspection
host discovery scan
category scoring
weighted score calculation
terminal report generation
JSON report generation
Scoring logic overview

The scanner translates observations into category scores.

Authentication and Encryption

Derived from the manually recorded auth_mode.

Examples:

wpa2_psk → lower score
wpa3_personal → higher score
Management Access Control

Derived from:

reachability of management hosts
reachability of management gateway
observed state of management ports such as 80/tcp and 443/tcp
Network Segmentation

Derived from:

documented VLAN presence
management network configuration
observed client subnet
expected gateway match
Network Exposure

Derived from:

host discovery results in the client subnet
exposure of management-related services
Known Insecure Features / Vulnerabilities

Derived primarily from:

WPS status
macOS notes

Because the scanner uses networksetup, it should be run on a Mac that is actively connected to the WLAN that is being assessed.

The scanner assumes that:

the active Wi-Fi interface is available as Wi-Fi
ping, arp, and nmap are available
the client has permission to run these commands

If your Wi-Fi service has a different name on macOS, you may need to adapt the code accordingly.

Limitations

This scanner is a proof of concept and has several limitations:

It is designed for macOS
It uses a client-side perspective
It does not retrieve all configuration values directly from the infrastructure devices
It depends partly on manually documented configuration values
It is not a full penetration testing tool
It is not intended to replace enterprise-grade auditing platforms
Future improvements

Possible future extensions include:

API-based device integration
SSH-based configuration retrieval
SNMP support
automated comparison reports
graphical result visualization
support for additional platforms and vendors
Thesis context

This prototype was developed as part of a bachelor thesis on WLAN hardening in small enterprise environments. Its purpose is to demonstrate how selected WLAN hardening criteria can be translated into a structured and partially automated assessment workflow.

License
