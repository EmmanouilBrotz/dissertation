# Ubuntu Server Security Hardening Script (24.04)

A comprehensive **Ubuntu Server 24.04 security hardening script** designed for fresh or existing servers.  
This script installs essential security tools, applies sane hardening defaults, and prepares the system for production use **without locking you out**.

> ⚠️ Designed to be safe-by-default: SSH password login is still enabled, and UFW is configured but not activated.

---

## 🔐 What This Script Does

### ✅ Security Tools Installed

- **Unattended Upgrades** – automatic security updates  
- **AIDE** – file integrity monitoring  
- **Auditd** – system and security auditing  
- **AppArmor** – mandatory access control  
- **ClamAV** – antivirus with daily scans  
- **UFW** – firewall (configured, not enabled)  
- **Fail2Ban** – intrusion prevention  
- **rkhunter & chkrootkit** – rootkit detection  
- **Lynis** – system security auditing  
- **debsums** – package integrity verification  

---

### 🛡️ System Hardening Applied

- **SSH hardening**
  - Root login disabled
  - Strong cryptography enforced
  - Connection limits applied

- **Kernel security parameters**
  - SYN flood protection
  - IP spoofing protection
  - ICMP hardening

- Disabled unnecessary services
- Account security policies
  - Strong password requirements
- Secure shared memory (`/dev/shm`)
- Core dump prevention
- Time synchronization (NTP)

---

## 🚧 Important Safety Notes (READ FIRST)

- ❌ **SSH is NOT key-only yet**
  - Password authentication is still enabled so you can:
    - Log in safely
    - Upload SSH keys
    - Test access before locking it down

- ❌ **UFW is NOT enabled**
  - Firewall rules are prepared
  - You must enable it manually after verifying SSH access

This is intentional to avoid accidental lockouts.

---

## 🖥️ Supported Systems

- Ubuntu Server **24.04 LTS**
- Works on:
  - Bare metal
  - Virtual machines
  - Servers behind firewalls (e.g. pfSense)

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/EmmanouilBrotz/dissertation.git
cd dissertation
```

Make the script executable:
```bash
chmod +x harden.sh
```


Run as root:
```bash
sudo ./harden.sh
```
⚠️ Disclaimer

This script improves baseline security but does not replace:

Monitoring

Backups

Network firewalls

Regular security audits

Always test in a VM before production use.
