# Bug Bounty Tools
[![username - bugbounty](https://img.shields.io/static/v1?label=username&message=bugbounty&color=blue&logo=github)](https://github.com/username/bugbounty)
[![stars - bugbounty](https://img.shields.io/github/stars/username/bugbounty?style=social)](https://github.com/username/bugbounty)
[![forks - bugbounty](https://img.shields.io/github/forks/username/bugbounty?style=social)](https://github.com/username/bugbounty)
[![GitHub release](https://img.shields.io/github/release/username/bugbounty?include_prereleases=&sort=semver)](https://github.com/username/bugbounty/releases/)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
[![issues - bugbounty](https://img.shields.io/github/issues/username/bugbounty)](https://github.com/username/bugbounty/issues)

<strong>A set of tools for bug bounty hunting.</strong><br>
<a href="#license"><img align="right"  src="resources/images/logo.png"></a>

<i>In the following tables, you can find the tools you need according to the heading.</i>
* [Bug Bounty Tools](https://github.com/username/bugbounty)
  * [Pwn Windows](#-Pwn-windows)
  * [Web](#-web)
  * [Mobile](#-mobile)
  * [📔 Bug Bounty Books](#-bug-bounty-books)
  * [📎 Target and Practice](#-target-and-practice)

## 🖥️ Pwn-Windows
<i>Pwn Windows Tools</i>

| Name                  | Descriptions                                                                                 | Download Link                                                   |
| --------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Empire**            | A post-exploitation framework that includes a pure-PowerShell Windows agent.                 | [Download](https://github.com/EmpireProject/Empire)             |
| **BloodHound**        | A single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a C# ingestor. | [Download](https://github.com/BloodHoundAD/BloodHound)          |
| **CrackMapExec**      | A swiss army knife for pentesting networks.                                                  | [Download](https://github.com/byt3bl33d3r/CrackMapExec)         |
| **Evil-WinRM**        | The ultimate WinRM shell for hacking/pentesting.                                             | [Download](https://github.com/Hackplayers/evil-winrm)           |
| **Unicorn**           | A simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. | [Download](https://github.com/trustedsec/unicorn)              |
| **Certipy**           | A tool for abusing Active Directory Certificate Services (AD CS).                            | [Download](https://github.com/ly4k/Certipy)                     |
| **Responder**         | An LLMNR, NBT-NS, and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server. | [Download](https://github.com/lgandx/Responder)               |
| **PowerSploit**       | A collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. | [Download](https://github.com/PowerShellMafia/PowerSploit) |
| **Covenant**          | A collaborative .NET C2 framework for red teamers.                                           | [Download](https://github.com/cobbr/Covenant)                   |
| **LDAPDomainDump**    | A Python script to enumerate users, groups, computers, and trusts in an Active Directory domain. | [Download](https://github.com/CrowdStrike/ldapdomaindump)      |
| **SharpCollection**   | A collection of .NET tools for red teaming and post-exploitation.                            | [Download](https://github.com/Flangvik/SharpCollection)         |
| **ADRecon**           | A tool for gathering detailed information about an Active Directory environment.             | [Download](https://github.com/adrecon/ADRecon)                  |
| **Spraykatz**         | A tool to spray and dump credentials from a number of different data sources on a Windows machine. | [Download](https://github.com/aas-n/spraykatz)                 |
| **nishang**           | Offensive PowerShell for red team, penetration testing and offensive security.               | [Download](https://github.com/samratashok/nishang)              |
| **pyGPOAbuse**        | A Python tool to abuse Group Policy Objects in Active Directory.                             | [Download](https://github.com/GoSecure/pyGPOAbuse)              |
| **Ghostpack**         | A collection of C# tools for red teaming and offensive security.                            | [Download](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) |
| **Invoke-Obfuscation**| A PowerShell v3+ cmdlet that obfuscates existing PowerShell scripts to evade antivirus.    | [Download](https://github.com/danielbohannon/Invoke-Obfuscation) |
| **PowerSharpPack**    | Many useful offensive C# tools wrapped into one project.                                     | [Download](https://github.com/S3cur3Th1sSh1t/PowerSharpPack)    |
| **PSAmsi**            | A module to bypass AMSI (Antimalware Scan Interface) in PowerShell.                          | [Download](https://github.com/cobbr/PSAmsi)                     |
| **PoshC2**            | A proxy aware C2 framework used to aid red team operations, post-exploitation, and lateral movement. | [Download](https://github.com/nettitude/PoshC2)             |
| **kerbrute**          | A tool to quickly brute force and enumerate valid Active Directory accounts through Kerberos Pre-Authentication. | [Download](https://github.com/ropnop/kerbrute)             |
| **ASREPRoast**        | A tool for performing AS-REP roasting attacks on Active Directory.                           | [Download](https://github.com/HarmJ0y/ASREPRoast)               |
| **Rubeus**            | A tool to interact with Kerberos tickets in various ways to assist with attacks such as pass-the-ticket. | [Download](https://github.com/GhostPack/Rubeus)            |
| **SharpHound**        | A C# ingestor for BloodHound used to collect data from Active Directory environments.         | [Download](https://github.com/BloodHoundAD/SharpHound)          |
| **SharpGPOAbuse**     | A tool to automate the exploitation of insecure Group Policy Objects in Active Directory.     | [Download](https://github.com/byronkg/SharpGPOAbuse)            |
| **SharpLAPS**         | A tool to interact with LAPS (Local Administrator Password Solution) for enumeration and exploitation. | [Download](https://github.com/swisskyrepo/SharpLAPS)         |
| **PowerView**         | A PowerShell tool to gain network situational awareness on Windows domains.                  | [Download](https://github.com/PowerShellEmpire/PowerTools)      |
| **Inveigh**           | A PowerShell LLMNR/NBNS/mDNS spoofer/man-in-the-middle tool.                                 | [Download](https://github.com/Kevin-Robertson/Inveigh)          |
| **PowerUp**           | A PowerShell tool to assist with local privilege escalation on Windows systems.              | [Download](https://github.com/PowerShellMafia/PowerSploit)      |
| **SharpUp**           | A C# tool for privilege escalation on Windows.                                               | [Download](https://github.com/GhostPack/SharpUp)                |
| **SharpDump**         | A C# tool to dump the memory of processes for credential extraction.                         | [Download](https://github.com/GhostPack/SharpDump)              |
| **SharpWMI**          | A C# tool to execute WMI queries and methods for enumeration and remote code execution.       | [Download](https://github.com/GhostPack/SharpWMI)               |
| **SharpRoast**        | A C# tool to perform Kerberoasting attacks on Active Directory.                              | [Download](https://github.com/GhostPack/SharpRoast)             |
| **SharpDPAPI**        | A C# tool to interact with the Data Protection API (DPAPI) to decrypt secrets.                | [Download](https://github.com/GhostPack/SharpDPAPI)             |
| **Lockless**          | A C# tool to bypass the Windows lock screen.                                                 | [Download](https://github.com/GhostPack/Lockless)               |
| **SafetyKatz**        | A C# tool to safely run Mimikatz in memory.                                                  | [Download](https://github.com/GhostPack/SafetyKatz)             |
| **KeeThief**          | A C# tool to interact with KeePass databases.                                                | [Download](https://github.com/GhostPack/KeeThief)               |
| **Seatbelt**          | A C# tool to perform security audits on Windows systems.                                     | [Download](https://github.com/GhostPack/Seatbelt)               |
| **Limelighter**       | A C# tool for lateral movement by injecting code into existing processes.                    | [Download](https://github.com/Tylous/Limelighter)               |
| **SharpGen**          | A C# tool to generate and obfuscate shellcode.                                               | [Download](https://github.com/GhostPack/SharpGen)               |
| **Invoke-Mimikatz**   | A PowerShell tool to run Mimikatz in memory.                                                 | [Download](https://github.com/PowerShellMafia/PowerSploit)      |
| **LaZagne**           | A tool to retrieve stored passwords on Windows.                                              | [Download](https://github.com/AlessandroZ/LaZagne)              |
| **QuarksPwDump**      | A C++ tool to dump passwords from Windows systems.                                           | [Download](https://github.com/QuarksLab/QuarksPwDump)           |
| **Invoke-TheHash**    | A PowerShell tool for performing various NTLM hash attacks.                                  | [Download](https://github.com/EmpireProject/Empire)             |
| **Invoke-DCSync**     | A PowerShell tool to replicate data from Domain Controllers using the DCSync technique.       | [Download](https://github.com/EmpireProject/Empire)             |
| **NetRipper**         | A post-exploitation tool for packet sniffing on Windows.                                     | [Download](https://github.com/NytroRST/NetRipper)               |
| **WMIExec**           | A Python tool for remote command execution via WMI.                                          | [Download](https://github.com/BC-SECURITY/WMIExec)              |
| **Sysinternals Suite**           | A comprehensive collection of advanced system utilities for monitoring, managing, and troubleshooting Windows operating systems.                                          | [Download](https://download.sysinternals.com/files/SysinternalsSuite.zip)              |
| **Mimikatz**           |  A versatile post-exploitation tool for extracting credentials and performing lateral movement within Windows networks.                                         | [Download](https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810-2/mimikatz_trunk.zip)              |
| **Merlin Server (Linux x64)**           | A robust red teaming toolset for simulating adversarial infrastructure to test and enhance detection and response capabilities in Windows environments.                                         | [Download](https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810-2/mimikatz_trunk.zip)              |



## 📱 Mobile Tools
<i>Mobile Security Tools</i>

| Name             | Descriptions                                                                 | Download |
| ---------------- | --------------------------------------------------------------------------- | -------- |
| **`apkleaks`**   | Scans APK files for secrets, such as hardcoded credentials and API keys.    | [Download](https://github.com/dwisiswant0/apkleaks) |
| **`aeroot`**     | Android rooting tool that exploits vulnerabilities in older Android versions. | [Download](https://github.com/AeonDave/aeroot) |
| **`frida-tools`**| Dynamic instrumentation toolkit for developers, reverse engineers, and security researchers. | [Download](https://github.com/frida/frida) |
| **`objection`**  | Runtime mobile exploration toolkit, powered by Frida.                        | [Download](https://github.com/sensepost/objection) |
| **`radare2`**    | A portable reversing framework that supports various architectures.          | [Download](https://github.com/radareorg/radare2) |
| **`dnspy`**      | .NET debugger and assembly editor.                                           | [Download](https://github.com/dnSpy/dnSpy) |
| **`Drozer`**     | Comprehensive security testing framework for Android applications.           | [Download](https://github.com/FSecureLABS/drozer) |
| **`MobSF`**      | Mobile Security Framework - automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis, and security assessment tool. | [Download](https://github.com/MobSF/Mobile-Security-Framework-MobSF) |
| **`apksigner`**  | Command-line tool to sign and verify Android APKs.                           | [Included in Android SDK](https://developer.android.com/studio/command-line/apksigner) |
| **`apktool`**    | A tool for reverse engineering Android APK files.                             | [Download](https://ibotpeaches.github.io/Apktool/) |
| **`zipalign`**   | Optimizes Android APK files.                                                 | [Included in Android SDK](https://developer.android.com/studio/command-line/zipalign) |
| **`adb`**        | Android Debug Bridge, a versatile command-line tool for managing Android devices. | [Download](https://developer.android.com/studio/releases/platform-tools) |
| **`aapt`**       | Android Asset Packaging Tool, part of the Android SDK build tools.           | [Included in Android SDK](https://developer.android.com/studio/command-line/aapt2) |
| **`jadx`**       | DEX to Java decompiler.                                                      | [Download](https://github.com/skylot/jadx) |
| **`jadx-gui`**   | GUI for jadx, a DEX to Java decompiler.                                      | [Download](https://github.com/skylot/jadx) |
| **`jadx-cli`**   | Command-line interface for jadx, a DEX to Java decompiler.                   | [Download](https://github.com/skylot/jadx) |
| **`jadx-dex2jar`** | Converts Android DEX files to Java JAR files.                               | [Download](https://github.com/pxb1988/dex2jar) |
| **`jarsigner`**  | Signs and verifies Java Archive (JAR) files.                                  | [Included in JDK](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html) |




## 🌐 Web

#### API TOOLS:

| Name          | Descriptions                                                               | Download                                                          |
| ------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **Kiterunner** | Security testing tool for APIs, focusing on GraphQL and REST endpoints.     | [Download](https://github.com/assetnote/kiterunner/releases/latest) |

## 🌐 Web

#### CMS SCANNERS:

| Name          | Descriptions                                 | Download |
| ------------- | -------------------------------------------- | -------- |
| **Droopescan** | CMS vulnerability scanner.                    | [Install via pip](https://pypi.org/project/droopescan/) |
| **Nrich**      | Networked reconnaissance framework for CMS.   | [Download](https://gitlab.com/api/v4/projects/33695681/releases) |
| **AEM-Hacking**| Adobe Experience Manager security toolkit.    | [GitHub Repo](https://github.com/0ang3el/aem-hacker) |
| **WhatWaf**    | Web application firewall identification tool. | [GitHub Repo](https://github.com/Ekultek/WhatWaf) |


#### Directory fuzzers:

| Name          | Descriptions                                     | Download |
| ------------- | ------------------------------------------------ | -------- |
| **Dirbuster** | Web directory brute-forcing tool.                | [Install via apt](https://packages.ubuntu.com/dirbuster) |
| **ffuf**      | Fast web fuzzer for directory and file bruteforcing. | [GitHub Repo](https://github.com/ffuf/ffuf) |
| **gobuster**  | Directory and file brute-forcing tool.            | [GitHub Repo](https://github.com/OJ/gobuster) |
| **feroxbuster**| Fast, simple web directory and file bruteforcer. | [GitHub Repo](https://github.com/epi052/feroxbuster) |


#### Dns resolver:

| Name         | Descriptions                                       | Download |
| ------------ | -------------------------------------------------- | -------- |
| **dnsx**     | Fast and versatile DNS toolkit.                    | [GitHub Repo](https://github.com/projectdiscovery/dnsx) |
| **puredns**  | DNS resolver and cache written in Go.              | [GitHub Repo](https://github.com/d3mondev/puredns) |
| **shuffledns**| Fast, flexible DNS discovery tool.                 | [GitHub Repo](https://github.com/projectdiscovery/shuffledns) |
| **MassDNS**   | High-performance DNS stub resolver.               | [GitHub Repo](https://github.com/blechschmidt/massdns) |
| **dnsvalidator**| DNS validation and resolution tool.              | [GitHub Repo](https://github.com/vortexau/dnsvalidator) |


#### Frameworks:

| Name         | Descriptions                                       | Download |
| ------------ | -------------------------------------------------- | -------- |
| **w3af**     | Web application attack and audit framework.        | [GitHub Repo](https://github.com/andresriancho/w3af) |
| **Arachni**  | Web application security scanner.                  | [Website](http://www.arachni-scanner.com/) |



#### Git Hunting:

| Name         | Descriptions                                       | Download |
| ------------ | -------------------------------------------------- | -------- |
| **GitDorker**| Tool to scan GitHub for sensitive information.     | [GitHub Repo](https://github.com/obheda12/GitDorker) |
| **gitGraber**| Tool to find sensitive information in GitHub pages. | [GitHub Repo](https://github.com/hisxo/gitGraber) |
| **GitTools** | Collection of tools for reconnaissance of Git repositories. | [GitHub Repo](https://github.com/internetwache/GitTools) |
| **GitHacker**| Tool for finding exposed `.git` directories.      | [PyPI](https://pypi.org/project/GitHacker/) |



<i>Recommended Books</i>

| Name  | Author | Purchase | 
| ----- | ------ | -------- |
| **`Book1`** | Author1 | [Buy](https://example.com/book1) |
| **`Book2`** | Author2 | [Buy](https://example.com/book2) |
| **`Book3`** | Author3 | [Buy](https://example.com/book3) |

## 📎 Target and Practice
<i>Places to practice and find bug bounty targets</i>

| Name  | Description | Visit | 
| ----- | ----------- | ----- |
| **`Platform1`** | Description for Platform1. | [Visit](https://example.com/platform1) |
| **`Platform2`** | Description for Platform2. | [Visit](https://example.com/platform2) |
| **`Platform3`** | Description for Platform3. | [Visit](https://example.com/platform3) |