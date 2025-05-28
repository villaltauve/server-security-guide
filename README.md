# Server Security Guide (Updated April 2025)
A comprehensive, up-to-date guide to securing a Linux server.

## Table of Contents
1. System Updates & Package Management
2. SSH Configuration & Authentication
3. Firewall Setup (UFW & iptables)
4. Brute-Force Protection with Fail2Ban
5. Intrusion Detection & Logging
6. Port Spoofing & Scan Prevention
7. Additional Hardening Tips

---

## 1. System Updates & Package Management
Keeping your server’s software up to date is the foundation of security.

```bash
# Fetch the latest package lists and upgrade installed packages
sudo apt update && sudo apt -y upgrade

# Enable unattended security upgrades for automatic installs of security patches
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

- **Verify kernel updates** and reboot if required: `sudo reboot` when `/var/run/reboot-required` exists.
- **Remove unused services**: `sudo apt purge package-name` and `sudo systemctl disable service-name`.

---

## 2. SSH Configuration & Authentication
Secure SSH access by minimizing attack surface and enforcing key-based logins.

1. **Generate SSH key pair** on your local machine:
   ```bash
   ssh-keygen -t ed25519 -C "you@example.com"
   ```
2. **Copy your public key** to the server:
   ```bash
   ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server_ip
   ```
3. **Edit sshd_config** (`/etc/ssh/sshd_config`):
   ```conf
   Port 2222                     # change default port for obscurity
   PermitRootLogin no            # disable root login
   PasswordAuthentication no     # enforce key-based auth only
   PubkeyAuthentication yes
   PermitEmptyPasswords no
   AllowUsers youruser           # restrict which accounts can SSH
   ```
4. **Restart SSH**:
   ```bash
   sudo systemctl restart sshd
   ```

Optionally, **enable two-factor authentication**:
```bash
sudo apt install libpam-google-authenticator
google-authenticator                 # follow prompts for each user
# Then add to /etc/pam.d/sshd:
auth required pam_google_authenticator.so
``` 

---

## 3. Firewall Setup (UFW & iptables)
### Using UFW (Uncomplicated Firewall)
```bash
sudo apt install ufw
sudo ufw default deny incoming  # block all incoming
sudo ufw default allow outgoing # allow all outgoing
sudo ufw allow 2222/tcp         # allow SSH on custom port
sudo ufw allow http             # allow HTTP (80)
sudo ufw allow https            # allow HTTPS (443)
sudo ufw logging on
sudo ufw enable
```

### Using iptables (if you prefer granular control)
```bash
# Flush existing rules
sudo iptables -F

# Default policy: drop all incoming, allow outgoing
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established sessions
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH & web traffic
sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save rules permanently (Debian/Ubuntu)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

---

## 4. Brute-Force Protection with Fail2Ban
Install Fail2Ban to ban IPs with repeated failed auth attempts.

```bash
sudo apt install fail2ban
sudo tee /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port    = 2222
filter  = sshd
action  = iptables[name=SSH, port=2222, protocol=tcp]
logpath = /var/log/auth.log
maxretry = 5
bantime  = 3600    # 1 hour
findtime = 600     # 10 minutes
EOF

sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

---

## 5. Intrusion Detection & Logging
Monitor file integrity and log events to detect suspicious changes.

- **Install AIDE (Advanced Intrusion Detection Environment)**:
  ```bash
  sudo apt install aide
  sudo aideinit
  sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  ```
  - Schedule daily checks via cron:
    ```cron
    0 2 * * * /usr/bin/aide --check
    ```
- **Centralized logs**: forward to a remote syslog server or use Logwatch:
  ```bash
  sudo apt install logwatch
  sudo logwatch --detail High --service all --range today
  ```

---

## 6. Port Spoofing & Scan Prevention
Use Portspoof to mislead automated scanners.

```bash
sudo apt install git make g++
git clone https://github.com/drk1wi/portspoof.git
cd portspoof
./configure && make && sudo make install

# Run Portspoof in daemon mode (adjust paths as needed)
sudo portspoof -c /etc/portspoof/portspoof.conf -s /etc/portspoof/portspoof_signatures -D

# Redirect unused ports to Portspoof (example: allow only 2222, 80, 443)
sudo iptables -t nat -A PREROUTING -p tcp \
  -m multiport --dports 1:2221,2223:79,81:442,444:65535 \
  -j REDIRECT --to-ports 4444
```

---

## 7. Additional Hardening Tips
- **Disable IPv6 if unused**: edit `/etc/sysctl.conf` and set `net.ipv6.conf.all.disable_ipv6 = 1`, then `sudo sysctl -p`.
- **Limit user privileges** with `sudo`ers file: grant only necessary commands.
- **Chroot or containers**: isolate services (e.g., using Docker or chroot).
- **Use TLS certificates** for all services (Let’s Encrypt recommended).
- **Regular backups** stored off-server and encrypted.
- **Monitor system metrics** with tools like Prometheus + Grafana or Netdata.

---

*End of Guide. Stay secure!*
