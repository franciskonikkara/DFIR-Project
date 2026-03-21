#!/bin/bash
# ============================================================================
# Linux Live Artifact Collection Script for Incident Response
# Usage: sudo ./collect_artifacts.sh -c IR-2024-001 -a "Jane Smith"
#
# Collects forensic artifacts from a live Linux system
# Run as root for complete access
# ============================================================================

CASE_ID=""
ANALYST="unknown"
OUTPUT_BASE="/tmp/dfir_triage"

while getopts "c:a:o:" opt; do
    case $opt in
        c) CASE_ID="$OPTARG" ;;
        a) ANALYST="$OPTARG" ;;
        o) OUTPUT_BASE="$OPTARG" ;;
        ?) echo "Usage: $0 -c CASE_ID -a ANALYST [-o OUTPUT_DIR]"; exit 1 ;;
    esac
done

if [ -z "$CASE_ID" ]; then
    echo "[-] Error: Case ID required (-c CASE_ID)"
    exit 1
fi

OUTPUT_DIR="${OUTPUT_BASE}/${CASE_ID}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

TRIAGE_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[*] DFIR Linux Triage - Case: $CASE_ID"
echo "[*] Analyst: $ANALYST"
echo "[*] Started: $TRIAGE_START"
echo "[*] Output: $OUTPUT_DIR"

log() { echo "[+] $1"; }
warn() { echo "[!] $1" >&2; }

# ============================================================
# METADATA
# ============================================================
log "Collecting system metadata..."
cat > "$OUTPUT_DIR/00_metadata.json" << EOF
{
  "case_id": "$CASE_ID",
  "analyst": "$ANALYST",
  "hostname": "$(hostname)",
  "fqdn": "$(hostname -f 2>/dev/null || hostname)",
  "triage_start": "$TRIAGE_START",
  "kernel": "$(uname -r)",
  "os": "$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)",
  "architecture": "$(uname -m)",
  "current_user": "$USER",
  "uptime": "$(uptime)",
  "ip_addresses": "$(ip addr show | grep 'inet ' | awk '{print $2}' | tr '\n' ',')"
}
EOF

# ============================================================
# RUNNING PROCESSES
# ============================================================
log "Collecting running processes..."
ps auxwww > "$OUTPUT_DIR/01_processes.txt"
ps -eo pid,ppid,user,%cpu,%mem,vsz,rss,stat,start,time,comm,args --sort=pid > "$OUTPUT_DIR/01_processes_detailed.txt"

# Process tree
pstree -aup 2>/dev/null > "$OUTPUT_DIR/01_process_tree.txt"

# Hashes of running process executables
while IFS= read -r exe; do
    if [ -f "$exe" ]; then
        sha256sum "$exe" 2>/dev/null >> "$OUTPUT_DIR/01_process_hashes.txt"
    fi
done < <(ls -la /proc/*/exe 2>/dev/null | awk '{print $NF}' | sort -u)

log "Processes collected"

# ============================================================
# NETWORK CONNECTIONS
# ============================================================
log "Collecting network connections..."
ss -tulpn > "$OUTPUT_DIR/02_listening_ports.txt"
ss -tanp > "$OUTPUT_DIR/02_all_connections.txt"
netstat -rn > "$OUTPUT_DIR/02_routing_table.txt"
ip addr show > "$OUTPUT_DIR/02_ip_addresses.txt"
ip route show > "$OUTPUT_DIR/02_routes.txt"
arp -n > "$OUTPUT_DIR/02_arp_cache.txt"

# DNS cache (if nscd or systemd-resolved)
if command -v resolvectl &>/dev/null; then
    resolvectl statistics > "$OUTPUT_DIR/02_dns_stats.txt" 2>/dev/null
fi

log "Network data collected"

# ============================================================
# LOGGED IN USERS & AUTH
# ============================================================
log "Collecting user sessions..."
who -a > "$OUTPUT_DIR/03_who.txt"
w > "$OUTPUT_DIR/03_who_verbose.txt"
last -F -n 200 > "$OUTPUT_DIR/03_last_logins.txt"
lastb -F -n 200 > "$OUTPUT_DIR/03_failed_logins.txt" 2>/dev/null

# Current user info
id > "$OUTPUT_DIR/03_current_user.txt"
groups >> "$OUTPUT_DIR/03_current_user.txt"

log "User sessions collected"

# ============================================================
# PERSISTENCE / AUTORUN
# ============================================================
log "Collecting persistence mechanisms..."

# Cron jobs
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null | grep -v '^#' | grep -v '^$' | \
        sed "s/^/[cron:$user] /" >> "$OUTPUT_DIR/04_cron_jobs.txt"
done
ls -la /etc/cron* /etc/cron.d/ 2>/dev/null >> "$OUTPUT_DIR/04_cron_jobs.txt"
cat /etc/crontab >> "$OUTPUT_DIR/04_cron_jobs.txt" 2>/dev/null

# Systemd services
systemctl list-units --type=service --all --no-pager > "$OUTPUT_DIR/04_systemd_services.txt" 2>/dev/null
ls -la /etc/systemd/system/*.service /usr/lib/systemd/system/*.service 2>/dev/null > "$OUTPUT_DIR/04_systemd_service_files.txt"

# Init scripts
ls -la /etc/init.d/ 2>/dev/null > "$OUTPUT_DIR/04_init_scripts.txt"

# SSH authorized keys
find /home /root -name "authorized_keys" 2>/dev/null | while IFS= read -r f; do
    echo "=== $f ===" >> "$OUTPUT_DIR/04_ssh_authorized_keys.txt"
    cat "$f" >> "$OUTPUT_DIR/04_ssh_authorized_keys.txt"
done

log "Persistence mechanisms collected"

# ============================================================
# RECENTLY MODIFIED FILES
# ============================================================
log "Collecting recently modified files..."

# Files modified in last 24 hours in sensitive directories
find /tmp /var/tmp /dev/shm /home -mtime -1 -type f 2>/dev/null | \
    xargs ls -la 2>/dev/null > "$OUTPUT_DIR/05_recent_tmp_files.txt"

# Recently modified system files (potential rootkit)
find /usr/bin /usr/sbin /bin /sbin -mtime -7 -type f 2>/dev/null | \
    xargs ls -la 2>/dev/null > "$OUTPUT_DIR/05_recent_system_binaries.txt"

# New SUID/SGID files
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null > "$OUTPUT_DIR/05_suid_sgid_files.txt"

log "Recent files collected"

# ============================================================
# COMMAND HISTORY
# ============================================================
log "Collecting command history..."

for user_home in /root /home/*; do
    username=$(basename "$user_home")
    for hist_file in .bash_history .zsh_history .sh_history .history; do
        if [ -f "$user_home/$hist_file" ]; then
            echo "=== [$username] $hist_file ===" >> "$OUTPUT_DIR/06_command_history.txt"
            cat "$user_home/$hist_file" 2>/dev/null >> "$OUTPUT_DIR/06_command_history.txt"
            echo "" >> "$OUTPUT_DIR/06_command_history.txt"
        fi
    done
done

log "Command history collected"

# ============================================================
# SYSTEM LOGS
# ============================================================
log "Collecting system logs..."

if [ -f /var/log/auth.log ]; then
    tail -2000 /var/log/auth.log > "$OUTPUT_DIR/07_auth_log.txt"
elif [ -f /var/log/secure ]; then
    tail -2000 /var/log/secure > "$OUTPUT_DIR/07_auth_log.txt"
fi

tail -2000 /var/log/syslog 2>/dev/null > "$OUTPUT_DIR/07_syslog.txt"
journalctl -n 2000 --no-pager 2>/dev/null > "$OUTPUT_DIR/07_journal.txt"
journalctl -p err -n 500 --no-pager 2>/dev/null > "$OUTPUT_DIR/07_journal_errors.txt"

log "System logs collected"

# ============================================================
# INSTALLED PACKAGES (anomaly detection)
# ============================================================
log "Collecting installed packages..."

if command -v dpkg &>/dev/null; then
    dpkg -l | sort -k3 > "$OUTPUT_DIR/08_installed_packages.txt"
elif command -v rpm &>/dev/null; then
    rpm -qa --qf "%{NAME} %{VERSION} %{INSTALLTIME:date}\n" | sort > "$OUTPUT_DIR/08_installed_packages.txt"
fi

log "Packages collected"

# ============================================================
# COMPUTE MANIFEST WITH HASHES
# ============================================================
log "Computing artifact hashes..."
cd "$OUTPUT_DIR" || exit 1
find . -maxdepth 1 -type f -not -name "00_manifest.txt" | sort | while IFS= read -r f; do
    sha256sum "$f" >> "00_manifest.txt"
done
cd - > /dev/null

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================="
echo " TRIAGE COMPLETE"
echo " Case ID : $CASE_ID"
echo " Output  : $OUTPUT_DIR"
echo " Files   : $(find "$OUTPUT_DIR" -maxdepth 1 -type f | wc -l) artifacts"
echo " Size    : $(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)"
echo "============================================="
echo ""
echo "Next steps:"
echo "  1. Verify hashes: sha256sum -c $OUTPUT_DIR/00_manifest.txt"
echo "  2. Compress: tar czf ${OUTPUT_DIR}.tar.gz $OUTPUT_DIR"
echo "  3. Transfer to secure analysis workstation"
