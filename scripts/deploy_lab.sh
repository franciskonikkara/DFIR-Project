#!/bin/bash
# ============================================================================
# DFIR Lab Deployment Script
#
# Deploys the full SOC Automation + DFIR stack:
#   - Wazuh (SIEM/XDR)
#   - TheHive 5 (Case Management)
#   - Shuffle (SOAR)
#   - Cassandra + Elasticsearch (TheHive backends)
#   - Cortex (Enrichment engine, optional)
#
# Based on: github.com/uruc/SOC-Automation-Lab
# Target OS: Ubuntu 22.04 LTS
# ============================================================================

set -e

WAZUH_IP="${1:-$(hostname -I | awk '{print $1}')}"
THEHIVE_IP="${2:-$(hostname -I | awk '{print $1}')}"

echo "======================================"
echo " DFIR Lab Stack Deployment"
echo " Wazuh IP:   $WAZUH_IP"
echo " TheHive IP: $THEHIVE_IP"
echo "======================================"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "[-] Error: Run as root (sudo ./deploy_lab.sh)"
        exit 1
    fi
}

update_system() {
    echo "[*] Updating system packages..."
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get install -y -qq curl wget apt-transport-https gpg lsb-release \
        python3 python3-pip git unzip jq
}

# ============================================================
# JAVA (Required for TheHive + Elasticsearch)
# ============================================================
install_java() {
    echo "[*] Installing Java 17..."
    apt-get install -y -qq openjdk-17-jdk
    echo "[+] Java: $(java -version 2>&1 | head -1)"
}

# ============================================================
# CASSANDRA (TheHive database backend)
# ============================================================
install_cassandra() {
    echo "[*] Installing Apache Cassandra..."
    wget -q -O /etc/apt/trusted.gpg.d/cassandra.asc \
        https://downloads.apache.org/cassandra/KEYS
    echo "deb https://downloads.apache.org/cassandra/debian 40x main" | \
        tee /etc/apt/sources.list.d/cassandra.list
    apt-get update -qq
    apt-get install -y -qq cassandra

    # Configure Cassandra for TheHive
    sed -i "s/cluster_name: 'Test Cluster'/cluster_name: 'dfir_lab'/" /etc/cassandra/cassandra.yaml
    sed -i "s/listen_address: localhost/listen_address: $THEHIVE_IP/" /etc/cassandra/cassandra.yaml
    sed -i "s/rpc_address: localhost/rpc_address: $THEHIVE_IP/" /etc/cassandra/cassandra.yaml
    sed -i "s/# broadcast_rpc_address: 1.2.3.4/broadcast_rpc_address: $THEHIVE_IP/" /etc/cassandra/cassandra.yaml
    sed -i "s/seeds: \"127.0.0.1:7000\"/seeds: \"$THEHIVE_IP:7000\"/" /etc/cassandra/cassandra.yaml

    systemctl enable cassandra
    systemctl start cassandra
    echo "[+] Cassandra installed and configured"
    sleep 15  # Wait for Cassandra to start
}

# ============================================================
# ELASTICSEARCH (TheHive indexer)
# ============================================================
install_elasticsearch() {
    echo "[*] Installing Elasticsearch..."
    wget -qO- https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
        gpg --dearmor | tee /etc/apt/trusted.gpg.d/elasticsearch.gpg > /dev/null
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | \
        tee /etc/apt/sources.list.d/elasticsearch.list
    apt-get update -qq
    apt-get install -y -qq elasticsearch

    # Configure for TheHive
    cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: dfir-lab
node.name: dfir-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $THEHIVE_IP
http.port: 9200
discovery.type: single-node
cluster.routing.allocation.disk.watermark.low: "90%"
cluster.routing.allocation.disk.watermark.high: "95%"
EOF

    # JVM heap size (adjust based on available RAM)
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    HEAP_GB=$(( RAM_GB / 4 ))
    [ "$HEAP_GB" -lt 1 ] && HEAP_GB=1
    sed -i "s/-Xms1g/-Xms${HEAP_GB}g/" /etc/elasticsearch/jvm.options 2>/dev/null || true
    sed -i "s/-Xmx1g/-Xmx${HEAP_GB}g/" /etc/elasticsearch/jvm.options 2>/dev/null || true

    systemctl enable elasticsearch
    systemctl start elasticsearch
    echo "[+] Elasticsearch installed (heap: ${HEAP_GB}GB)"
}

# ============================================================
# THEHIVE 5
# ============================================================
install_thehive() {
    echo "[*] Installing TheHive 5..."
    wget -qO- https://raw.githubusercontent.com/StrangeBee/TheHive/main/PGP-PUBLIC-KEY | \
        gpg --dearmor | tee /etc/apt/trusted.gpg.d/strangebee.gpg > /dev/null
    echo 'deb https://deb.strangebee.com thehive-5.x main' | \
        tee /etc/apt/sources.list.d/strangebee.list
    apt-get update -qq
    apt-get install -y -qq thehive

    cat > /etc/thehive/application.conf << EOF
db.janusgraph {
  storage.backend: cql
  storage.hostname: ["$THEHIVE_IP"]
  storage.cql.cluster-name: dfir_lab
  storage.cql.keyspace: thehive
}

index.search {
  backend: elasticsearch
  hostname: ["$THEHIVE_IP"]
  index-name: thehive
}

application.baseUrl: "http://$THEHIVE_IP:9000"

storage {
  provider: localfs
  localfs.location: /opt/thp/thehive/files
}
EOF

    mkdir -p /opt/thp/thehive/files
    chown -R thehive:thehive /opt/thp/thehive

    systemctl enable thehive
    systemctl start thehive
    echo "[+] TheHive installed - Access: http://$THEHIVE_IP:9000"
    echo "[+] Default credentials: admin@thehive.local / secret"
    echo "[!] CHANGE DEFAULT CREDENTIALS IMMEDIATELY"
}

# ============================================================
# WAZUH MANAGER + INDEXER + DASHBOARD (4.x)
# ============================================================
install_wazuh() {
    echo "[*] Installing Wazuh (Manager + Indexer + Dashboard)..."
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
    chmod +x wazuh-install.sh
    ./wazuh-install.sh -a -i  # All-in-one installation
    rm -f wazuh-install.sh
    echo "[+] Wazuh installed"
    echo "[+] Dashboard: https://$WAZUH_IP"
    echo "[+] Credentials stored in: /etc/wazuh-install-files.tar"
}

# ============================================================
# SHUFFLE SOAR
# ============================================================
install_shuffle() {
    echo "[*] Installing Shuffle SOAR..."

    # Install Docker
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker

    # Install Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    # Clone Shuffle
    git clone https://github.com/Shuffle/Shuffle /opt/shuffle
    cd /opt/shuffle

    # Set Elasticsearch host for Shuffle
    sed -i "s/opensearch-node1/localhost/g" docker-compose.yml 2>/dev/null || true

    # Start Shuffle
    docker-compose up -d
    echo "[+] Shuffle SOAR started"
    echo "[+] Access: http://$WAZUH_IP:3001"
    echo "[+] Default: admin@example.com / password"
    echo "[!] CHANGE DEFAULT CREDENTIALS IMMEDIATELY"
}

# ============================================================
# PYTHON DFIR DEPENDENCIES
# ============================================================
install_python_deps() {
    echo "[*] Installing Python dependencies..."
    pip3 install -q \
        requests \
        psutil \
        pefile \
        yara-python \
        scapy \
        dpkt \
        python-evtx \
        pyyaml \
        python-docx \
        volatility3 \
        pyshark \
        tqdm \
        rich
    echo "[+] Python dependencies installed"
}

# ============================================================
# INSTALL CUSTOM WAZUH RULES
# ============================================================
deploy_wazuh_rules() {
    echo "[*] Deploying custom Wazuh rules..."
    if [ -d "/var/ossec/etc/rules" ]; then
        cp configs/wazuh_custom_rules.xml /var/ossec/etc/rules/dfir_custom_rules.xml
        /var/ossec/bin/ossec-control restart 2>/dev/null || systemctl restart wazuh-manager
        echo "[+] Custom Wazuh rules deployed"
    else
        echo "[!] Wazuh not found at /var/ossec - skipping rule deployment"
    fi
}

# ============================================================
# MAIN
# ============================================================
check_root
update_system
install_java
install_cassandra
install_elasticsearch
install_thehive
install_wazuh
install_shuffle
install_python_deps
deploy_wazuh_rules

echo ""
echo "======================================"
echo " DFIR LAB DEPLOYMENT COMPLETE"
echo "======================================"
echo ""
echo " Wazuh Dashboard:  https://$WAZUH_IP"
echo " TheHive:          http://$THEHIVE_IP:9000"
echo " Shuffle SOAR:     http://$WAZUH_IP:3001"
echo " Elasticsearch:    http://$THEHIVE_IP:9200"
echo ""
echo " IMPORTANT: Change all default credentials!"
echo "======================================"
