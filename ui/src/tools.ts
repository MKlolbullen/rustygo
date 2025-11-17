import { Tool } from './types';

export const TOOL_CATEGORIES: { id: Tool['category']; label: string }[] = [
  { id: 'recon', label: 'Recon / Auxiliary' },
  { id: 'enumeration', label: 'Enumeration' },
  { id: 'crawling', label: 'Crawling' },
  { id: 'fuzzing', label: 'Fuzzing' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'privilege-escalation', label: 'Privilege Escalation' },
  { id: 'exploitation', label: 'Exploitation' },
  { id: 'post-exploitation', label: 'Post-Exploitation' },
  { id: 'persistence', label: 'Persistence' },
  { id: 'scanning', label: 'Scanning' },
  { id: 'auxiliary', label: 'Misc / Auxiliary' }
];

export const TOOLS: Tool[] = [
  //
  // RECON / AUX
  //
  {
    id: 'subfinder_recon',
    label: 'Subfinder',
    category: 'recon',
    description: 'Passive subdomain enumeration via ProjectDiscovery subfinder.'
  },
  {
    id: 'assetfinder_recon',
    label: 'Assetfinder',
    category: 'recon',
    description: 'Subdomain discovery using assetfinder-style sources.'
  },
  {
    id: 'dnsx_resolve',
    label: 'dnsx (DNS resolve)',
    category: 'recon',
    description: 'Resolve DNS records (A/AAAA/CNAME/SRV/TXT/etc) for discovered subdomains.'
  },
  {
    id: 'httpx_probe',
    label: 'httpx (HTTP probe)',
    category: 'recon',
    description: 'Probe HTTP/HTTPS services, detect status codes, titles and technologies.'
  },
  {
    id: 'naabu_scan',
    label: 'naabu (fast port scan)',
    category: 'recon',
    description: 'Fast TCP port scanning to identify open ports for further analysis.'
  },
  {
    id: 'favirecon_hash',
    label: 'Favirecon (favicon hash)',
    category: 'recon',
    description:
      'Download and hash favicons for clustering hosts by favicon (shodan/censys-style).'
  },
  {
    id: 'csprecon_analyze',
    label: 'CSPRecon',
    category: 'recon',
    description:
      'Fetch and parse Content-Security-Policy headers to identify asset origins and misconfigs.'
  },
  {
    id: 'whatweb_fingerprint',
    label: 'WhatWeb (fingerprinting)',
    category: 'recon',
    description: 'Fingerprint web applications and technologies running on target URLs.'
  },
  {
    id: 'gowitness_screenshot',
    label: 'Screenshots (gowitness-style)',
    category: 'recon',
    description: 'Capture HTTP screenshots for discovered web services for visual triage.'
  },

  //
  // ENUMERATION
  //
  {
    id: 'enum4linux_ng',
    label: 'enum4linux-ng',
    category: 'enumeration',
    description: 'SMB / AD enumeration (users, shares, groups, policies) on Windows domains.'
  },
  {
    id: 'smb_share_enum',
    label: 'SMB shares',
    category: 'enumeration',
    description: 'Enumerate SMB shares and permissions for target hosts.'
  },
  {
    id: 'netbios_enum',
    label: 'NetBIOS / NBNS',
    category: 'enumeration',
    description: 'NetBIOS name service enumeration (workgroups, hostnames).'
  },
  {
    id: 'netexec_smb',
    label: 'NetExec (SMB module)',
    category: 'enumeration',
    description:
      'Use netexec (crackmapexec-style tooling) to enumerate SMB information and access.'
  },
  {
    id: 'ldap_enum',
    label: 'LDAP / AD enum',
    category: 'enumeration',
    description:
      'Query LDAP / Active Directory for users, groups, computers and high-value ACLs (via external tooling).'
  },

  //
  // CRAWLING
  //
  {
    id: 'js_crawler',
    label: 'JS/Link crawler',
    category: 'crawling',
    description:
      'Crawl web apps and JavaScript to extract endpoints, parameters and potential API routes.'
  },
  {
    id: 'wayback_crawler',
    label: 'Archive/Wayback recon',
    category: 'crawling',
    description:
      'Pull historical URLs from archives (e.g. Wayback-style) for expanded attack surface.'
  },

  //
  // FUZZING
  //
  {
    id: 'ffuf_dir',
    label: 'ffuf (directory fuzzing)',
    category: 'fuzzing',
    description: 'Directory and file brute forcing for hidden resources on web servers.'
  },
  {
    id: 'feroxbuster_dir',
    label: 'feroxbuster (content discovery)',
    category: 'fuzzing',
    description: 'Recursive content discovery and fuzzing of paths on HTTP targets.'
  },

  //
  // VULNERABILITIES
  //
  {
    id: 'nuclei_templates',
    label: 'Nuclei (HTTP templates)',
    category: 'vulnerabilities',
    description:
      'Run Nuclei templates against HTTP services for CVEs, misconfigurations and exposures.'
  },
  {
    id: 'nuclei_infra',
    label: 'Nuclei (infrastructure)',
    category: 'vulnerabilities',
    description:
      'Scan infrastructure targets (IPs/ports) with Nuclei templates for network-level issues.'
  },

  //
  // PRIVILEGE ESCALATION
  //
  {
    id: 'win_privesc_enum',
    label: 'Windows privesc enumeration',
    category: 'privilege-escalation',
    description:
      'Collect Windows privilege escalation hints (services, scheduled tasks, token privileges).'
  },
  {
    id: 'lin_privesc_enum',
    label: 'Linux privesc enumeration',
    category: 'privilege-escalation',
    description:
      'Enumerate Linux privilege escalation opportunities: SUID binaries, sudo rules, cron jobs and paths.'
  },
  {
    id: 'ad_privesc_paths',
    label: 'AD/Identity privesc paths',
    category: 'privilege-escalation',
    description:
      'Analyze AD/identity data for potential escalation paths (group memberships, delegation, ACLs).'
  },

  //
  // EXPLOITATION
  //
  {
    id: 'metasploit_module',
    label: 'Metasploit module',
    category: 'exploitation',
    description:
      'Invoke a Metasploit module via RPC (exploit/aux/post) with Rustygo as the operator UI.'
  },
  {
    id: 'havoc_beacon',
    label: 'Havoc beacon generator',
    category: 'exploitation',
    description:
      'Generate Havoc beacons/agents via the Havoc client, using preconfigured listeners and profiles.'
  },
  {
    id: 'empire_stager',
    label: 'Empire stager generator',
    category: 'exploitation',
    description:
      'Create Empire stagers/listeners with custom options over the Empire REST/RPC interface.'
  },
  {
    id: 'adaptix_agent',
    label: 'Adaptix agent generator',
    category: 'exploitation',
    description:
      'Build Adaptix agents with chosen profiles/transport, ready to be delivered via separate mechanisms.'
  },

  //
  // POST-EXPLOITATION
  //
  {
    id: 'cred_inventory',
    label: 'Credential inventory',
    category: 'post-exploitation',
    description:
      'Aggregate and normalize harvested credentials (hashes, tickets, passwords) into a central view.'
  },
  {
    id: 'host_profile_collect',
    label: 'Host profile collection',
    category: 'post-exploitation',
    description:
      'Collect situational awareness from a compromised host: OS, users, AV/EDR, network, services.'
  },
  {
    id: 'lateral_reach_map',
    label: 'Lateral reachability map',
    category: 'post-exploitation',
    description:
      'Map reachable services/ports from compromised hosts (RDP/SMB/WinRM/SSH) for potential lateral movement.'
  },

  //
  // PERSISTENCE
  //
  {
    id: 'win_persistence',
    label: 'Windows persistence candidates',
    category: 'persistence',
    description:
      'Enumerate potential persistence mechanisms on Windows (run keys, services, scheduled tasks).'
  },
  {
    id: 'lin_persistence',
    label: 'Linux persistence candidates',
    category: 'persistence',
    description:
      'Enumerate potential persistence mechanisms on Linux (systemd, cron, shell profile hooks).'
  },

  //
  // SCANNING
  //
  {
    id: 'nmap_scan',
    label: 'Nmap Graph Scan',
    category: 'scanning',
    description:
      'sudo nmap -sCV -T4 -A -O --script discovery $target -vv; build host/service graph from XML.'
  },
  {
    id: 'nextnet_exposure',
    label: 'Nextnet exposure scan',
    category: 'scanning',
    description:
      'Run nextnet-style scanning to map network exposure and connectivity between nodes.'
  },

  //
  // AUXILIARY / META
  //
  {
    id: 'graph_only',
    label: 'Graph: manual node editor',
    category: 'auxiliary',
    description:
      'Manipulate the current graph manually (add/remove nodes and edges) without running tools.'
  },
  {
    id: 'playbook_runner',
    label: 'Playbook runner',
    category: 'auxiliary',
    description:
      'Execute saved playbooks that chain multiple tools (recon → scan → vuln → reporting).'
  }
];