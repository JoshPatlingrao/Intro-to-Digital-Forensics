# Intro-to-Digital-Forensics

## Intro
Digital Forensics
- A.K.A computer forensics or cyber forensics
- Involves collection, preservation, analysis, and presentation of digital evidence to investigate cyber incidents, criminal activities, and security breaches.
- Applies forensic techniques to digital artifacts in computers, servers, mobile devices, networks, and storage media
- Aims to reconstruct timelines, identify malicious activities, assess the impact of incidents, and provide evidence for legal or regulatory proceedings.
- Important to incident response process, contributing crucial insights and support at various stages.

Key Concepts
- Electronic Evidence: Includes files, emails, logs, databases, and network traffic from sources like computers, mobile devices, and cloud services.
- Preservation of Evidence: Evidence must be preserved with integrity, following strict procedures to maintain authenticity and a proper chain of custody.
- Forensic Process Stages:
  - Identification: Locate potential evidence.
  - Collection: Acquire data using secure, forensic methods.
  - Examination: Inspect data for relevant details.
  - Analysis: Interpret findings to understand events.
  - Presentation: Clearly report results for legal or organizational use.
- Types of Cases:
  - Cybercrime (e.g., hacking, data theft)
  - Intellectual property theft
  - Internal investigations (e.g., employee misconduct)
  - Incident response and data breaches
  - Legal proceedings and litigation support

Basic Steps
- Create a Forensic Image
- Document the System's State
- Identify and Preserve Evidence
- Analyze the Evidence
- Timeline Analysis
- Identify Indicators of Compromise (IOCs)
- Report and Documentation

Digital Forensics for SOC Analysts
- Post-Incident Analysis: Digital forensics offers a detailed retrospective view of security incidents, helping trace attacker behavior, techniques, and possibly their identity.
- Rapid Threat Identification: Forensic tools quickly analyze large datasets to identify the time of compromise, affected systems, and attack vectors—enabling swift containment.
- Legal Evidence Collection: Forensics ensures evidence is preserved in a legally admissible way (hashed, timestamped, and logged), supporting legal action post-breach.
- Threat Hunting Enablement: Insights from past attacks (IoCs and TTPs) help SOC teams proactively search for signs of compromise across systems.
- Improved Incident Response: Understanding the full scope of an attack allows for more targeted and thorough responses, reducing risks of lingering threats or repeated breaches.
- Continuous Learning & Defense Improvement: Each incident provides valuable lessons, enabling SOC analysts to anticipate new threats and strengthen defenses over time.
- Proactive Security Posture: Digital forensics transforms from a reactive function into a proactive capability that enhances overall SOC effectiveness and organizational resilience.

## Windows Forensic Overview
NTFS (New Technology File System)
- Introduced with Windows NT 3.1 in 1993 as a proprietary file system and is now the default for modern Windows OS versions
- Replaced the older FAT (File Allocation Table) system, overcoming many of its limitations
- Includes features like journaling and error recovery to enhance data integrity.
- Designed to manage large volumes efficiently with faster access and better disk space utilization.
- Supports file-level permissions and encryption to control access and protect data.
- Capable of handling large files and partitions, making it suitable for both desktop and enterprise environments.

NTFS Forensic Artifacts
- File Metadata
  - Stores creation, modification, access times, and file attributes (e.g., read-only, hidden).
  - Helps establish user activity timelines.
- Master File Table (MFT)
  - Central structure storing metadata for all files and folders.
  - Deleted files’ MFT entries may still contain recoverable data.
- File Slack & Unallocated Space
  - May hold remnants of deleted files or leftover data fragments.
  - Useful for data recovery during forensic analysis.
- File Signatures
  - Identifies file types via headers, even if extensions are altered.
  - Aids in reconstructing hidden or renamed files.
- USN Journal
  - Logs changes to files and directories (creations, deletions, modifications).
  - Supports timeline reconstruction and change tracking.
- LNK Files (Shortcuts)
  - Contain paths and metadata of linked files.
  - Reveal accessed or executed programs/files.
- Prefetch Files
  - Log information about program executions for performance optimization.
  - Help identify what apps ran and when.
- Registry Hives
  - Hold critical system and user configuration data.
  - Forensic clues often left by malware or unauthorized changes.
- Shellbags
  - Record folder view settings and accessed directory paths.
  - Show which folders were browsed by users.
- Thumbnail Cache
  - Stores previews of image/doc files.
  - Reveal recently viewed content even if originals are deleted.
- Recycle Bin
  - Temporarily stores deleted files.
  - Useful for recovering user-deleted content and tracking deletions.
- Alternate Data Streams (ADS)
  - Hidden data streams attached to files.
  - Often abused by attackers to hide malicious data.
- Volume Shadow Copies
  - Backup snapshots of the file system.
  - Aid in historical analysis and recovery of changed/deleted files.
- Security Descriptors and ACLs
  - Define user permissions on files/folders.
  - Help identify unauthorized access or privilege misuse.

Windows Event Logs
- Core component of Windows OS used to log events from the system, applications, services, and ETW (Event Tracing for Windows) providers
- Essential for tracking system activity and errors.
- Logs application errors, security incidents, system diagnostics, and more. Useful for real-time monitoring and historical analysis.
  - Also capture a wide range of adversarial tactics such as: initial compromise (e.g., malware, exploits), credential access, privilege escalation and lateral movement (often using built-in Windows tools)
  - Specific logs provide valuable insight into system behavior and attacker actions.
  - Logs can be accessed directly for offline or forensic analysis.

Windows Execution Artifacts
- Traces left behind when programs run on a Windows system
- Helps reconstruct timelines of program execution.
- Allows identification of malicious activity and unauthorized software.
- Aids in understanding user behavior and system interactions.

Common Windows Execution Artifacts
- Prefetch Files
  - Store metadata on executed applications (file paths, execution count, timestamps).
  - Reveal which programs ran and in what order.
- Shimcache (AppCompatCache)
  - Logs executed programs for compatibility.
  - Includes file paths, timestamps, and execution flags.
- Amcache
  - Database of executables and installed apps (since Windows 8).
  - Records file metadata, digital signatures, and execution timestamps.
- UserAssist
  - Registry key tracking user-executed programs.
  - Records app names, execution counts, and timestamps.
- RunMRU Lists
  - Registry-based list of most recently run programs (e.g., from Run dialog).
  - Indicates what was executed and when.
- Jump Lists
  - Store recently accessed files/tasks for specific apps.
  - Reveal user activity and frequently used files.
- Shortcut (LNK) Files
  - Contain paths, timestamps, and user interaction metadata.
  - Show context of program or file execution.
- Recent Items
  - Folder storing shortcuts to recently opened files.
  - Useful for tracking recent user activity.
- Windows Event Logs
  - Include Security, System, and Application logs.
  - Record process creation, termination, crashes, and other events.

Windows Persistence Artifacts
- Windows persistence uses techniques to maintain long-term access to a compromised system after the initial intrusion.
  - Allows attackers to survive reboots and avoid detection.
  - Ensures they can continue malicious activities over time.
  - Helps sustain remote control or ongoing data access/exfiltration.

Windows Registry
- A centralized database in Windows that stores critical system and user configuration settings.
  - Stores user account security configurations via the Security Accounts Manager (SAM).
  - Controls startup behavior and system services.
  - Modifies system behavior based on registry keys and values.
- Covers settings for: Devices, Services, Security policies, Installed applications, User profiles
- Why?
  - High-value target for persistence and privilege escalation.
  - Adversaries modify autorun keys to launch malware at system startup.
  - Registry changes can be stealthy and difficult to detect.
- Defense
  - Regularly inspect Autorun Keys
    - Run/RunOnce Keys
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      - HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\
    - Keys used by WinLogon Process
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
    - Startup Keys
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
      - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User
  - Monitor unauthorized modifications or suspicious entries.
  - Use tools like Sysinternals Autoruns or registry auditing for analysis.

Schtasks
- Built-in Windows feature that allows automation of programs or commands.
- Used for:
  - Running scripts or updates at specific times
  - Performing system maintenance
  - Automating repetitive processes
- Where?
  - Scheduled tasks are located in: C:\Windows\System32\Tasks
  - Each task is saved as an XML file that contains:
    - Creator/user
    - Trigger details (when the task runs)
    - Path to the executable/command
- Why it Matters?
  - Scheduled tasks can be used to:
    - Maintain persistence
    - Re-execute malware on reboot or at intervals
    - Evade detection using legitimate system features
- How to Investigate?
  - Examine XML content to check for:
    - Unusual or unknown creators
    - Suspicious paths or commands
    - Irregular or high-frequency triggers

Windows Services
- What is it?
  - Background processes that run without user interaction.
  - Critical for system functionality (e.g., networking, updates, security).
  - Automatically start on boot, triggered, or manual.
- Why it Matters?
  - Allows attackers to:
    - Maintain persistence
    - Automatically launch malware or backdoors
    - Operate stealthily under trusted system behavior
- Location
  - Malicious services are often configured in: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
  - This registry path stores: service names, start type (auto/manual), executable paths and configs
- Look For
  - Unexpected or suspicious service names
  - Executables pointing to non-standard directories
  - Services configured to auto-start with unknown binaries

Web Browser Forensics
- A forensic discipline focused on analyzing browser artifacts to understand user activity, online behavior, and potential malicious interactions.
- Look For:
  - Browsing History: URLs, page titles, timestamps, and visit frequency.
  - Cookies: Session data, preferences, and authentication tokens.
  - Cache: Stored web content (pages, images) that may persist even after history is cleared.
  - Bookmarks/Favorites: Saved links showing user interests or frequently accessed sites.
  - Download History: File names, timestamps, and source URLs.
  - Autofill Data: Auto-entered form data: names, addresses, emails, passwords.
  - Search History: Search engine queries and associated timestamps.
  - Session Data: Information about current and recent browsing sessions, tabs, and windows.
  - Typed URLs: Manually entered web addresses.
  - Form Data: User-entered data in web forms (credentials, queries).
  - Saved Passwords: Stored login credentials for websites.
  - Web Storage: Data stored locally by websites (e.g., HTML5 local storage).
  - Favicons: Website icons that indicate visited domains.
  - Tab Recovery Data: Restorable session/tab data after a crash.
  - Extensions and Add-ons: Installed browser tools and their configurations, which may be legitimate or malicious.

SRUM (System Resource Usage Monitor)
- What is it?
  - Introduced in Windows 8+.
  - Logs application and resource usage over time.
  - Stores data in a SQLite database file: sru.db located at: C:\Windows\System32\sru
- Look For
  - Application Profiling
    - Logs executed applications and processes.
    - Includes executable names, paths, timestamps, and usage data.
    - Useful for identifying malicious or unauthorized software.
  - Resource Consumption
    - Tracks CPU, memory, and network usage per process.
    - Helps detect unusual resource spikes or performance anomalies.
  - Timeline Reconstruction
    - Allows creation of detailed timelines based on app usage and system activity.
    - Critical for tracing events, behaviors, and attack sequences.
  - User & System Context
    - Includes user identifiers, linking activities to specific accounts.
    - Helps attribute actions to legitimate users or intruders.
  - Malware Detection
    - Detects signs of malicious behavior:
      - Unusual app usage
      - High resource consumption
      - Suspicious install patterns
  - Incident Response
    - Offers rapid access to recent activity logs during an investigation.
    - Supports quick threat identification and containment decisions.

## Evidence Acquisition Techniques & Tools
Evidence Acquisition
- The process of collecting digital artifacts from systems to preserve them for forensic analysis
- Integrity, authenticity, and admissibility of the data are ensured with specialized tools and methods
- Common Techniques
  - Forensic Imaging
  - Extracting Host-based Evidence & Rapid Triage
  - Extracting Network Evidence

### Forensic Imaging
Forensic Imaging
- Creation of bit-by-bit copies of storage devices.
- Preserves all data, including deleted or hidden files.
  - Allows investigation of evidence and atat in its original state
- Maintains original evidence integrity using hashes (e.g., MD5, SHA-1).
  - Ensures evidence admissibility

Common Forensic Imaging Tools
- FTK Imager
  - Developed by AccessData (now Exterro)
  - Widely used for disk imaging and analysis
  - Preserves evidence integrity and allows data viewing without modification
- AFF4 Imager
  - Free, open-source imaging tool
  - Supports compression, volume segmentation, and file extraction by timestamp
  - Compatible with multiple file systems
- DD & DCFLDD
  - Command-line tools on Unix-based systems
  - DD is default on most Unix systems
  - DCFLDD extends DD with forensic-specific features (e.g., hashing)
- Virtualization Tools
  - Used for evidence collection in virtualized environments
  - Methods include:
    - Pausing VMs and copying storage directories
    - Using VM snapshot features for consistent state capture

### Extracting Host-based Evidence & Rapid Triage
Host-based Evidence
- Digital artifacts generated by OSs and applications during regular operation
  - Such as: file edits, user account creation, application execution
 
Data Volatility
- Volatile data disappears after power-off or logoff
  - Stored in RAM
- Active memory (RAM) is especially valuable in malware investigations.
- Memory analysis can reveal live malware, processes, network activity, and more.
  - Can find many RAM or memory-based attacks

Non-Volatile Data
- Stored on HDD/SSD, and presists through shutdowns
- Includes
  - Registry
  - Windows Event Log
  - System-related artifacts (e.g., Prefetch, Amcache)
  - Application-specific artifacts (e.g., IIS logs, Browser history)

Memory Acquisition Tools
- FTK Imager (https://www.exterro.com/ftk-imager)
  - Commonly used for memory and disk imaging
  - Preserves data integrity for analysis
- WinPmem (https://github.com/Velocidex/WinPmem)
  - Open-source memory acquisition tool
  - Originally part of the Rekall project
- DumpIt (https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/)
  - Simple utility for dumping memory on Windows and Linux
  - Combines 32- and 64-bit memory spaces into a single output file
- MemDump (http://www.nirsoft.net/utils/nircmd.html)
  - Command-line tool for capturing RAM
  - Lightweight and ideal for malware or forensic investigations
- Belkasoft RAM Capturer (https://belkasoft.com/ram-capturer)
  - Effective even against anti-debugging techniques
  - Captures full RAM from live Windows systems
- Magnet RAM Capture (https://www.magnetforensics.com/resources/magnet-ram-capture/)
  - Free tool by Magnet Forensics
  - Simple interface for volatile memory capture
- LiME - Linux Memory Extractor (https://github.com/504ensicsLabs/LiME)
  - Designed for Linux systems
  - Transparent and stealthy, useful for avoiding anti-forensics detection

Rapid Triage
- A targeted forensic approach focused on quickly collecting high-value data from potentially compromised systems.
  - Prioritizes systems likely affected by an incident, as attackers may implement anti-forensic measures and erase data and evidence
- The goal is to centralize and streamline analysis to identify systems with the most evidentiary value, enabling faster and deeper forensic investigation.
  - Centralizes key forensic artifacts for efficient indexing and searching.

Rapid Triage Tool - KAPE (Kroll Artifact Parser and Extractor)
- Developed by Kroll (formerly Magnet Forensics).
- Parses and extracts forensic artifacts rapidly from Windows systems.
  - Speeds up evidence collection from large data sets.
- Works well with mounted images (e.g., using Arsenal Image Mounter).
- Supports both collection (Targets) and processing (Modules) phases.
- Highly customizable and effective in incident response and deep forensics.
  - Extracts critical forensic artifacts (e.g., event logs, browser data, registry keys).
  - Offers automation, efficiency, and broad artifact coverage.

<img width="1579" height="419" alt="image" src="https://github.com/user-attachments/assets/39ced873-2729-4ce9-b074-ff4303b390ed" />

KAPE Operation
- Operates based on the principles of Targets and Modules
  - Targets: specific artifacts KAPE aims to extract from an image or system and duplicated in an output directory
    - Has the '.tkape' extension on output files
  - Compound Targets: amalgamations of multiple targets, gathering multiple files defined across various targets in a single run
- It duplicates specific forensic-related files to a designated output directory, all while maintaining the metadata of each file

EDR (Endpoint Detection and Response)
- Powerful tools used by incident response analysts to remotely detect, investigate, and collect digital evidence from endpoints across a network
- Significantly accelerates investigation and response efforts in large environments.

Rapid Triage Tool - Velociraptor
- Open-source endpoint visibility and response tool.
- Uses Velociraptor Query Language (VQL) to query and collect host data.
- Supports running Hunts across endpoints to gather targeted artifacts.
- Often uses Windows.KapeFiles.Targets artifact to mimic KAPE logic.
- KAPE is not open-source, but its collection logic is available via the KapeFiles project (YAML-based).
  - Velociraptor leverages this logic to efficiently gather high-value forensic artifacts.
- Enables rapid triage and large-scale evidence gathering.
- Improves visibility across all systems.
- Reduces time and resource cost during incident response.
- Velociraptor adds flexibility and customization via open-source tooling.

### Extracting Network Evidence
- Foundational task for SOC analysts
- Involves collecting and analyzing data from network traffic to identify malicious behavior, track threats, and support incident response.
  - Packet Capture & Analysis
    - Traffic capture offers a detailed snapshot of all data transmissions within a network.
    - Tools: Wireshark, tcpdump
    - Enables deep inspection of network conversations and protocol behavior.
  - IDS/IPS Data
    - IDS detects suspicious or known-malicious traffic patterns and generate alerts.
    - IPS goes further by automatically blocking malicious activity.
    - This data is crucial for real-time threat detection and validation.
  - Flow Data (NetFlow/sFlow)
    - Offers a high-level overview of traffic behavior and communication patterns between systems.
    - Lacks payload detail but is excellent for:
      - Identifying large data transfers
      - Spotting unusual communication flows
      - Detecting lateral movement
  - Firewall Logs
    - Modern firewalls do more than block/allow traffic:
      - Identify applications
      - Attribute traffic to specific users
      - Detect and block advanced threats
    - Firewall log analysis helps detect:
      - Exploitation attempts
      - Unauthorized access
      - Malicious communications
