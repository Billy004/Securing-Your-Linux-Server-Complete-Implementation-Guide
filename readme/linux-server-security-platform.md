# Linux Server Security Platform

**Secure your Linux infrastructure with confidence**

A comprehensive implementation guide for hardening Linux servers with battle-tested security measures. Get your server production-ready in under 2 hours.

```bash
# Quick Security Setup
curl -fsSL https://raw.githubusercontent.com/your-repo/linux-security/main/quick-setup.sh | bash
```

{% hint style="info" %}
**Before you start**: Always test configurations in a non-production environment and ensure you have console access before implementing SSH changes.
{% endhint %}

***

## Overview

This platform provides **15 essential security measures** divided into two phases:

* **Phase 1**: 10 fundamental security steps
* **Phase 2**: 5 advanced protection measures

**Time to complete**: \~90-120 minutes\
**Skill level**: Intermediate\
**Supported systems**: Ubuntu/Debian, CentOS/RHEL/Rocky Linux

***

## Quick Start

### Prerequisites

```bash
# Ensure you have sudo access
sudo whoami

# Update system first
sudo apt update && sudo apt upgrade -y  # Debian/Ubuntu
sudo yum update -y                       # CentOS/RHEL
```

### Installation Options

{% tabs %}
{% tab title="Automated Setup" %}
```bash
# Download and run our security setup script
wget https://raw.githubusercontent.com/your-repo/linux-security/main/setup.sh
chmod +x setup.sh
sudo ./setup.sh
```
{% endtab %}

{% tab title="Manual Implementation" %}
Follow the step-by-step guide below for complete control over each security measure.
{% endtab %}
{% endtabs %}

***

## Phase 1: Essential Security (10 Steps)

### 1. System Updates

Keep your system current with security patches.

{% tabs %}
{% tab title="Debian/Ubuntu" %}
```bash
# Update package list
sudo apt update

# Upgrade all packages
sudo apt upgrade -y

# Remove unnecessary packages
sudo apt autoremove -y

# Configure automatic security updates
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```
{% endtab %}

{% tab title="CentOS/RHEL" %}
```bash
# Update all packages
sudo yum update -y
# For newer versions: sudo dnf update -y

# Install automatic updates
sudo yum install yum-cron -y
sudo systemctl enable yum-cron
sudo systemctl start yum-cron

# Configure auto-updates
sudo sed -i 's/apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
**Pro Tip**: Set up email notifications for update status by configuring your MTA (mail transfer agent).
{% endhint %}

### 2. Service Management

Reduce attack surface by disabling unnecessary services.

```bash
# Audit running services
sudo systemctl list-units --type=service --state=running

# Check network connections  
sudo ss -tulpn

# Disable common unnecessary services
sudo systemctl disable --now cups
sudo systemctl disable --now avahi-daemon  
sudo systemctl disable --now bluetooth
sudo systemctl disable --now ModemManager
```

**Configure UFW Firewall:**

```bash
# Install and setup UFW
sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow essential services
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

### 3. Password Security

Implement strong password policies.

```bash
# Install password quality tools
sudo apt install libpam-pwquality -y    # Debian/Ubuntu
sudo yum install libpwquality -y        # CentOS/RHEL
```

**Configure Password Policy:**

{% code title="/etc/security/pwquality.conf" %}
```bash
# Minimum password length
minlen = 12

# Minimum number of character classes
minclass = 3

# Maximum consecutive characters
maxrepeat = 3

# Require character types
ucredit = -1  # Uppercase
lcredit = -1  # Lowercase  
dcredit = -1  # Digits
ocredit = -1  # Special characters
```
{% endcode %}

### 4. User Account Management

Create secure non-root user accounts.

```bash
# Create new user
sudo adduser secureuser

# Add to sudo group
sudo usermod -aG sudo secureuser        # Debian/Ubuntu
sudo usermod -aG wheel secureuser       # CentOS/RHEL

# Test sudo access
su - secureuser
sudo whoami
```

**Configure Sudo Settings:**

{% code title="/etc/sudoers (via visudo)" %}
```bash
# User privilege specification
secureuser ALL=(ALL:ALL) ALL

# Optional: Passwordless sudo (use cautiously)  
# secureuser ALL=(ALL) NOPASSWD:ALL
```
{% endcode %}

### 5. Fail2Ban Protection

Defend against brute-force attacks.

```bash
# Install Fail2Ban
sudo apt install fail2ban -y           # Debian/Ubuntu
sudo yum install epel-release fail2ban # CentOS/RHEL

# Create local configuration
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

**Configuration:**

{% code title="/etc/fail2ban/jail.local" %}
```bash
[DEFAULT]
bantime = 3600        # 1 hour ban
findtime = 600        # 10 minute window
maxretry = 3          # 3 failures before ban
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```
{% endcode %}

```bash
# Start and enable
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check status
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

### 6. SSH Hardening

Secure remote access with advanced SSH configuration.

{% hint style="warning" %}
**Critical**: Ensure you have console access before modifying SSH settings. Test each change carefully.
{% endhint %}

**Generate SSH Keys:**

```bash
# On your local machine
ssh-keygen -t rsa -b 4096 -C "your_email@domain.com"

# Copy to server
ssh-copy-id username@server_ip
```

**SSH Configuration:**

{% code title="/etc/ssh/sshd_config" %}
```bash
# Change default port
Port 2222

# Disable root login
PermitRootLogin no

# Key-only authentication
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no

# Limit users
AllowUsers yourusername

# Connection limits
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60

# Strong cryptography
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
```
{% endcode %}

```bash
# Test and restart SSH
sudo sshd -t
sudo systemctl restart sshd
```

### 7. Firewall Configuration

Implement robust network filtering.

{% tabs %}
{% tab title="UFW (Recommended)" %}
```bash
# Reset and configure UFW
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow services (adjust port for custom SSH)
sudo ufw allow 2222/tcp  # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS

# Allow from specific IP
sudo ufw allow from 192.168.1.100

# Enable and check
sudo ufw enable
sudo ufw status numbered
```
{% endtab %}

{% tab title="iptables" %}
```bash
# Basic iptables rules
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback and established connections
sudo iptables -I INPUT 1 -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow services
sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```
{% endtab %}
{% endtabs %}

### 8. SSL/TLS Encryption

Secure data transmission with certificates.

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Obtain certificate
sudo certbot --nginx -d yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run

# Schedule renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

**Nginx SSL Configuration:**

{% code title="/etc/nginx/sites-available/default" %}
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
}
```
{% endcode %}

### 9. Automated Backups

Implement reliable data protection.

**Create Backup Script:**

{% code title="/usr/local/bin/backup.sh" %}
```bash
#!/bin/bash

# Configuration
BACKUP_SOURCE="/home /etc /var/www"
BACKUP_DEST="/backup/$(date +%Y%m%d)"
LOG_FILE="/var/log/backup.log"

# Create backup directory
mkdir -p $BACKUP_DEST

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

# Backup using rsync
log_message "Starting backup to $BACKUP_DEST"

for dir in $BACKUP_SOURCE; do
    if [ -d "$dir" ]; then
        log_message "Backing up $dir"
        rsync -avz --delete "$dir" "$BACKUP_DEST/" >> $LOG_FILE 2>&1
    fi
done

# Compress backup
tar -czf "$BACKUP_DEST.tar.gz" -C "$BACKUP_DEST" .
rm -rf "$BACKUP_DEST"

# Clean old backups (keep 7 days)
find /backup -name "*.tar.gz" -mtime +7 -delete

log_message "Backup completed successfully"
```
{% endcode %}

```bash
# Make executable and schedule
sudo chmod +x /usr/local/bin/backup.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /usr/local/bin/backup.sh" | sudo crontab -
```

### 10. Log Monitoring

Set up comprehensive system monitoring.

```bash
# Install monitoring tools
sudo apt install logwatch logrotate -y
```

**Configure Log Rotation:**

{% code title="/etc/logrotate.d/custom-logs" %}
```bash
/var/log/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        systemctl reload nginx
    endscript
}

/var/log/auth.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
```
{% endcode %}

**Real-time Monitoring:**

```bash
# Monitor authentication logs
sudo tail -f /var/log/auth.log

# Monitor system logs
sudo tail -f /var/log/syslog

# Monitor multiple logs
sudo multitail /var/log/auth.log /var/log/syslog
```

***

## Phase 2: Advanced Security (5 Steps)

### 11. Two-Factor Authentication

Add an extra security layer to SSH access.

```bash
# Install Google Authenticator
sudo apt install libpam-google-authenticator -y

# Configure for user (run as user, not root)
google-authenticator
```

**Follow the prompts:**

* Time-based tokens: `y`
* Update file: `y`
* Disallow multiple uses: `y`
* Increase window: `n`
* Enable rate-limiting: `y`

**Configure PAM and SSH:**

{% code title="/etc/pam.d/sshd" %}
```bash
# Add at top
auth required pam_google_authenticator.so
```
{% endcode %}

{% code title="/etc/ssh/sshd_config" %}
```bash
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```
{% endcode %}

### 12. Security Auditing

Implement automated vulnerability scanning.

```bash
# Install Lynis security auditor
sudo apt install lynis -y

# Run full system audit
sudo lynis audit system

# Install RKHunter for rootkit detection
sudo apt install rkhunter -y
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --check
```

**Automated Security Scanning:**

{% code title="/usr/local/bin/security-scan.sh" %}
```bash
#!/bin/bash

REPORT_FILE="/var/log/security-scan-$(date +%Y%m%d).log"

echo "=== Security Scan Report - $(date) ===" > $REPORT_FILE

echo "=== Lynis Audit ===" >> $REPORT_FILE
lynis audit system --quiet >> $REPORT_FILE 2>&1

echo "=== RKHunter Scan ===" >> $REPORT_FILE  
rkhunter --check --sk --report-warnings-only >> $REPORT_FILE 2>&1

# Email report if configured
# mail -s "Security Report - $(hostname)" admin@domain.com < $REPORT_FILE
```
{% endcode %}

### 13. Intrusion Detection

Deploy Host-based Intrusion Detection System.

```bash
# Install AIDE
sudo apt install aide -y

# Initialize database
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run integrity check
sudo aide --check
```

**AIDE Configuration:**

{% code title="/etc/aide/aide.conf" %}
```bash
# Monitor critical directories
/boot p+i+n+u+g+s+b+m+c+md5+sha1
/bin p+i+n+u+g+s+b+m+c+md5+sha1
/sbin p+i+n+u+g+s+b+m+c+md5+sha1
/etc p+i+n+u+g+s+b+m+c+md5+sha1

# Ignore dynamic content
!/var/log/.*
!/tmp/.*
!/proc/.*
!/sys/.*
```
{% endcode %}

### 14. Web Application Security

Implement Web Application Firewall protection.

```bash
# Install ModSecurity for Nginx
sudo apt install libnginx-mod-security -y

# Download OWASP Core Rule Set
cd /tmp
wget https://github.com/coreruleset/coreruleset/archive/v3.3.2.tar.gz
tar xzf v3.3.2.tar.gz
sudo mv coreruleset-3.3.2 /etc/nginx/modsecurity/owasp-crs
```

**ModSecurity Configuration:**

{% code title="/etc/nginx/modsecurity/modsecurity.conf" %}
```bash
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecResponseBodyAccess On
SecAuditEngine RelevantOnly
SecAuditLog /var/log/nginx/modsec_audit.log
```
{% endcode %}

### 15. System Hardening

Apply kernel-level security measures.

**Kernel Security Parameters:**

{% code title="/etc/sysctl.d/99-security.conf" %}
```bash
# Network security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_all = 1

# Memory protections  
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
fs.suid_dumpable = 0
```
{% endcode %}

```bash
# Apply settings
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

**Secure GRUB Bootloader:**

```bash
# Generate password hash
grub-mkpasswd-pbkdf2

# Add to GRUB config
echo "set superusers=\"admin\"" | sudo tee -a /etc/grub.d/40_custom
echo "password_pbkdf2 admin YOUR_HASH_HERE" | sudo tee -a /etc/grub.d/40_custom

# Update GRUB
sudo update-grub
```

***

## Monitoring & Maintenance

### Security Health Check

Run our comprehensive security verification script:

{% code title="/usr/local/bin/security-check.sh" %}
```bash
#!/bin/bash

echo "=== Linux Server Security Health Check ==="
echo

# System updates
echo "📦 Pending Updates:"
apt list --upgradable 2>/dev/null | wc -l

# SSH configuration
echo "🔐 SSH Security Status:"
grep -E "^Port|^PermitRootLogin|^PasswordAuthentication" /etc/ssh/sshd_config

# Firewall status
echo "🛡️  Firewall Status:"
ufw status | head -5

# Fail2ban status  
echo "🚫 Fail2Ban Status:"
fail2ban-client status

# SSL certificates
echo "🔒 SSL Certificate Status:"
certbot certificates 2>/dev/null | grep "Certificate Name" | wc -l

# Recent backups
echo "💾 Recent Backups:"
ls -lt /backup/ 2>/dev/null | head -3

echo "✅ Security check completed!"
```
{% endcode %}

### Automated Monitoring

```bash
# Make script executable
sudo chmod +x /usr/local/bin/security-check.sh

# Schedule hourly checks
echo "0 * * * * /usr/local/bin/security-check.sh" | sudo crontab -

# View monitoring logs
sudo tail -f /var/log/security-monitor.log
```

***

## Testing & Verification

### Connection Testing

```bash
# Test SSH with new configuration
ssh -p 2222 username@your-server

# Verify firewall rules
sudo ufw status verbose

# Check SSL certificate
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Test fail2ban  
sudo fail2ban-client status
```

### Security Validation

Run the complete security checklist:

```bash
# Download and run our validation script
wget https://raw.githubusercontent.com/your-repo/linux-security/main/validate.sh
chmod +x validate.sh
./validate.sh
```

***

## Troubleshooting

{% hint style="danger" %}
**Locked out of SSH?** Use console access to revert changes:

```bash
sudo nano /etc/ssh/sshd_config
# Temporarily set: PasswordAuthentication yes
sudo systemctl restart sshd
```
{% endhint %}

### Common Issues

| Issue                            | Solution                                              |
| -------------------------------- | ----------------------------------------------------- |
| SSH connection refused           | Check if SSH is running: `sudo systemctl status sshd` |
| UFW blocking services            | Allow the service: `sudo ufw allow service_name`      |
| Fail2ban blocking legitimate IPs | Unban IP: `sudo fail2ban-client unban IP_ADDRESS`     |
| SSL certificate errors           | Renew certificate: `sudo certbot renew`               |

***

## Support & Community

### Getting Help

* 📚 **Documentation**: Full guides and API references
* 💬 **Discord Community**: Join 3,000+ security professionals
* 🐛 **GitHub Issues**: Report bugs and request features
* 📧 **Email Support**: security@yourdomain.com

### Contributing

Help improve this security platform:

```bash
# Clone the repository  
git clone https://github.com/your-repo/linux-security-platform
cd linux-security-platform

# Create feature branch
git checkout -b feature/new-security-measure

# Submit pull request
git push origin feature/new-security-measure
```

***

## What's Next?

1. **🔍 Monitor**: Set up alerts and dashboards
2. **🛡️ Advanced Protection**: Implement SIEM solutions
3. **📊 Compliance**: Meet security standards (SOC 2, ISO 27001)
4. **🤖 Automation**: Deploy Infrastructure as Code

{% hint style="info" %}
**Security is a journey, not a destination.** Keep your systems updated and stay informed about emerging threats.
{% endhint %}

***

_Last updated: \{{ page.lastModified \}}_
