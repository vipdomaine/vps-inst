#!/bin/bash
# ============================================
# VIP Domaine VPS Manager - Version Professionnelle
# Compatible Ubuntu 22.04 - Niveau Production
# Version: 2025-10-06
# ============================================

# Gestion stricte des erreurs (fail-fast)
set -euo pipefail

# Variables globales et configuration
readonly SCRIPT_VERSION="2025-10-06-PRO"
readonly COMPANY_NAME="VIP Domaine"
readonly SUPPORTED_OS_VERSION="22.04"
readonly DEFAULT_SWAP_GB=2
readonly LOG_FILE="/var/log/vip_manager.log"
readonly CONFIG_BACKUP_DIR="/root/vip_manager_backups"
readonly REPORT_DIR="/root/vip_reports"

# Couleurs pour interface utilisateur
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Créer les répertoires nécessaires
init_directories() {
    local dirs=("$(dirname "$LOG_FILE")" "$CONFIG_BACKUP_DIR" "$REPORT_DIR")
    for dir in "${dirs[@]}"; do
        [[ ! -d "$dir" ]] && mkdir -p "$dir"
    done
    touch "$LOG_FILE"
}

# --------------------------------------------
# Système de logging professionnel
# --------------------------------------------

log_action() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

info() { 
    echo -e "${BLUE}[INFO]${NC} $*"
    log_action "INFO" "$*"
}

warn() { 
    echo -e "${YELLOW}[WARN]${NC} $*"
    log_action "WARN" "$*"
}

error() { 
    echo -e "${RED}[ERROR]${NC} $*"
    log_action "ERROR" "$*"
}

success() { 
    echo -e "${GREEN}[SUCCESS]${NC} $*"
    log_action "SUCCESS" "$*"
}

debug() {
    [[ "${DEBUG:-0}" == "1" ]] && echo -e "${PURPLE}[DEBUG]${NC} $*"
    log_action "DEBUG" "$*"
}

fatal() {
    echo -e "${RED}[FATAL]${NC} $*" >&2
    log_action "FATAL" "$*"
    exit 1
}

# --------------------------------------------
# Vérifications système et prérequis
# --------------------------------------------

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        fatal "Ce script doit être exécuté en root. Utilisez: sudo bash $0"
    fi
}

check_ubuntu_version() {
    local detected_version=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        detected_version="$VERSION_ID"
        if [[ "$VERSION_ID" != "$SUPPORTED_OS_VERSION" ]]; then
            warn "Script conçu pour Ubuntu $SUPPORTED_OS_VERSION. Version détectée: $VERSION_ID"
            echo -e "${YELLOW}Risques potentiels:${NC}"
            echo "  • Commandes différentes selon la version"
            echo "  • Paquets non disponibles"
            echo "  • Comportements inattendus"
            echo
            read -rp "Voulez-vous continuer malgré tout ? (y/N): " confirm
            [[ "$confirm" != [yY] ]] && { info "Installation interrompue par l'utilisateur"; exit 0; }
        else
            success "Ubuntu $VERSION_ID détecté - Compatible ✓"
        fi
    else
        warn "Impossible de détecter la version Ubuntu"
        read -rp "Continuer quand même ? (y/N): " confirm
        [[ "$confirm" != [yY] ]] && exit 1
    fi
}

check_internet_connectivity() {
    info "Vérification de la connectivité Internet..."
    local test_hosts=("8.8.8.8" "1.1.1.1" "google.com")
    local connected=false
    
    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 3 "$host" >/dev/null 2>&1; then
            connected=true
            break
        fi
    done
    
    if [[ "$connected" == "true" ]]; then
        success "Connectivité Internet: OK"
    else
        fatal "Aucune connectivité Internet détectée. Vérifiez votre connexion."
    fi
}

ensure_package() {
    local pkg="$1"
    local max_retries=3
    local retry=0
    
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        debug "Paquet $pkg déjà installé"
        return 0
    fi
    
    info "Installation du paquet: $pkg"
    
    while [[ $retry -lt $max_retries ]]; do
        if apt-get update -y >/dev/null 2>&1 && apt-get install -y "$pkg" >/dev/null 2>&1; then
            success "Paquet $pkg installé avec succès"
            return 0
        else
            ((retry++))
            warn "Tentative $retry/$max_retries échouée pour $pkg"
            [[ $retry -lt $max_retries ]] && sleep 2
        fi
    done
    
    error "Impossible d'installer le paquet: $pkg"
    return 1
}

ensure_prereqs() {
    info "Installation des prérequis système..."
    
    local essential_packages=(
        curl wget sudo ufw fail2ban lsb-release 
        net-tools dnsutils bc jq openssl
        software-properties-common apt-transport-https
    )
    
    local failed_packages=()
    
    for pkg in "${essential_packages[@]}"; do
        if ! ensure_package "$pkg"; then
            failed_packages+=("$pkg")
        fi
    done
    
    # Netcat avec fallback
    if ! command -v nc >/dev/null 2>&1; then
        ensure_package netcat-openbsd || ensure_package netcat || failed_packages+=("netcat")
    fi
    
    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        error "Échec d'installation des paquets: ${failed_packages[*]}"
        return 1
    fi
    
    success "Tous les prérequis sont installés"
}

# --------------------------------------------
# Fonctions de validation
# --------------------------------------------

validate_domain() {
    local domain="$1"
    # Regex pour validation domaine (RFC compliant)
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        # Vérifications supplémentaires
        if [[ ${#domain} -gt 253 ]]; then
            return 1  # Trop long
        fi
        if [[ "$domain" == *.* ]]; then
            return 0  # Valide
        fi
    fi
    return 1
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$ip"
        for octet in $a $b $c $d; do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
        # Éviter les IPs réservées
        if [[ "$ip" == "0.0.0.0" ]] || [[ "$ip" == "127.0.0.1" ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
            debug "IP privée/réservée détectée: $ip"
        fi
        return 0
    fi
    return 1
}

validate_email() {
    local email="$1"
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

get_public_ip() {
    local ip=""
    local services=(
        "curl -s --max-time 5 ifconfig.me"
        "curl -s --max-time 5 ipecho.net/plain"
        "curl -s --max-time 5 icanhazip.com"
        "curl -s --max-time 5 ifconfig.co"
        "dig +short myip.opendns.com @resolver1.opendns.com"
    )
    
    for service in "${services[@]}"; do
        ip=$(eval "$service" 2>/dev/null | tr -d '\n\r' || true)
        if validate_ip "$ip"; then
            echo "$ip"
            return 0
        fi
    done
    
    warn "Impossible de détecter l'IP publique automatiquement"
    echo ""
}

# --------------------------------------------
# Gestion mémoire et swap
# --------------------------------------------

detect_total_ram_gb() {
    local ram_gb
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    
    if [[ -z "$ram_gb" || "$ram_gb" == "0" ]]; then
        local kb
        kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
        if [[ -n "$kb" && "$kb" -gt 0 ]]; then
            ram_gb=$(( kb / 1024 / 1024 ))
            [[ "$ram_gb" -eq 0 ]] && ram_gb=1
        else
            ram_gb=1
        fi
    fi
    
    echo "$ram_gb"
}

recommend_swap_for_ram() {
    local ram_gb="$1"
    local swap_gb
    
    if (( ram_gb <= 1 )); then
        swap_gb=2
    elif (( ram_gb <= 2 )); then
        swap_gb=4
    elif (( ram_gb <= 8 )); then
        swap_gb=$((ram_gb * 2))
    elif (( ram_gb <= 16 )); then
        swap_gb=$ram_gb
    else
        swap_gb=$((ram_gb / 2))
        # Maximum raisonnable
        [[ $swap_gb -gt 32 ]] && swap_gb=32
    fi
    
    echo "$swap_gb"
}

check_available_disk_space() {
    local required_gb="$1"
    local available_kb
    available_kb=$(df --output=avail / | tail -1)
    local available_gb=$(( available_kb / 1024 / 1024 ))
    
    if (( available_gb < required_gb + 2 )); then
        return 1
    fi
    return 0
}

create_swap_file() {
    local size_gb="$1"
    
    # Vérifier si swap existe déjà
    if swapon --show | grep -q "/swapfile\|swap"; then
        local existing_swap=$(swapon --show | awk '/swapfile/ {print $3}' | sed 's/G//' || echo "0")
        info "Swap existant détecté: ${existing_swap}G"
        return 0
    fi
    
    # Vérifier l'espace disque
    if ! check_available_disk_space "$size_gb"; then
        error "Espace disque insuffisant pour créer le swap de ${size_gb}G"
        return 1
    fi
    
    info "Création d'un fichier swap de ${size_gb}G..."
    
    # Backup de fstab avant modification
    cp /etc/fstab "${CONFIG_BACKUP_DIR}/fstab.backup.$(date +%s)" 2>/dev/null || true
    
    # Création du fichier swap
    if command -v fallocate >/dev/null 2>&1; then
        fallocate -l "${size_gb}G" /swapfile
    else
        dd if=/dev/zero of=/swapfile bs=1M count=$((size_gb * 1024)) status=progress
    fi
    
    # Configuration swap
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    
    # Ajouter à fstab si pas déjà présent
    if ! grep -q "/swapfile" /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    # Optimisation swap (optionnel)
    echo 'vm.swappiness=10' >> /etc/sysctl.conf 2>/dev/null || true
    
    success "Swap de ${size_gb}G créé et configuré"
    return 0
}

# --------------------------------------------
# Diagnostic système avancé
# --------------------------------------------

check_system_load() {
    local load_1min load_5min load_15min
    read -r load_1min load_5min load_15min < /proc/loadavg
    
    local cpu_cores
    cpu_cores=$(nproc)
    
    info "Charge système:"
    echo "  • 1 minute:  $load_1min"
    echo "  • 5 minutes: $load_5min" 
    echo "  • 15 minutes: $load_15min"
    echo "  • CPU cores: $cpu_cores"
    
    # Alertes basées sur le nombre de cœurs
    if awk "BEGIN {exit !($load_1min > $cpu_cores)}"; then
        warn "⚠️  Charge CPU élevée (1min): $load_1min > $cpu_cores cœurs"
    fi
    
    if awk "BEGIN {exit !($load_5min > $cpu_cores)}"; then
        warn "⚠️  Charge CPU soutenue (5min): $load_5min > $cpu_cores cœurs"
    fi
}

check_memory_usage() {
    local mem_info
    mem_info=$(free -h)
    
    local mem_used mem_total mem_available
    read -r mem_total mem_used _ _ _ mem_available <<< "$(free -m | awk '/^Mem:/ {print $2, $3, $4, $5, $6, $7}')"
    
    local mem_usage_percent=$(( (mem_used * 100) / mem_total ))
    
    info "Utilisation mémoire:"
    echo "  • Total: ${mem_total}MB"
    echo "  • Utilisé: ${mem_used}MB (${mem_usage_percent}%)"
    echo "  • Disponible: ${mem_available}MB"
    
    if (( mem_usage_percent > 85 )); then
        warn "⚠️  Utilisation mémoire élevée: ${mem_usage_percent}%"
    fi
    
    # Vérifier swap
    local swap_info
    swap_info=$(free -h | awk '/^Swap:/ {print $2, $3, $4}')
    if [[ "$swap_info" != "0B 0B 0B" ]]; then
        info "Swap: $swap_info"
    else
        warn "Aucun swap configuré"
    fi
}

check_disk_usage() {
    info "Utilisation disques:"
    
    while IFS= read -r line; do
        local filesystem mountpoint usage
        read -r filesystem _ _ _ usage mountpoint <<< "$line"
        
        # Ignorer les systèmes de fichiers temporaires
        if [[ "$filesystem" =~ ^/dev/ && ! "$mountpoint" =~ ^/(proc|sys|dev|run) ]]; then
            local usage_num=${usage%\%}
            echo "  • $mountpoint: $usage ($filesystem)"
            
            if (( usage_num > 85 )); then
                warn "⚠️  Espace disque faible sur $mountpoint: $usage"
            fi
        fi
    done < <(df -h | tail -n +2)
}

check_network_connectivity() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        info "Aucun domaine spécifié pour le test DNS"
        return 0
    fi
    
    info "Test de connectivité réseau pour: $domain"
    
    # Test résolution DNS
    local dns_result
    dns_result=$(dig +short "$domain" A 2>/dev/null | head -1)
    
    if [[ -z "$dns_result" ]]; then
        warn "❌ Aucun enregistrement A trouvé pour $domain"
        return 1
    elif validate_ip "$dns_result"; then
        success "✅ DNS résolu: $domain → $dns_result"
        
        # Test de connectivité HTTP si possible
        if command -v curl >/dev/null 2>&1; then
            if curl -s --connect-timeout 5 --max-time 10 "http://$domain" >/dev/null 2>&1; then
                success "✅ HTTP accessible: $domain"
            else
                warn "⚠️  HTTP non accessible sur $domain"
            fi
        fi
        
        return 0
    else
        warn "❌ Réponse DNS invalide pour $domain: $dns_result"
        return 1
    fi
}

check_services_status() {
    info "État des services système:"
    
    local services=(
        "ssh:SSH Server"
        "ufw:Pare-feu UFW" 
        "fail2ban:Protection Fail2ban"
        "nginx:Serveur Nginx"
        "apache2:Serveur Apache"
        "mysql:Base de données MySQL"
        "postgresql:Base de données PostgreSQL"
    )
    
    for service_info in "${services[@]}"; do
        IFS=':' read -r service_name service_desc <<< "$service_info"
        
        if systemctl is-active --quiet "$service_name" 2>/dev/null; then
            success "✅ $service_desc actif"
        elif systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
            warn "⚠️  $service_desc installé mais arrêté"
        else
            debug "ℹ️  $service_desc non installé"
        fi
    done
}

check_security_status() {
    info "Vérification sécurité:"
    
    # SSH root login
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        success "✅ Connexion SSH root désactivée"
    else
        warn "⚠️  Connexion SSH root potentiellement activée"
    fi
    
    # SSH password authentication
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        success "✅ Authentification SSH par mot de passe désactivée"
    else
        warn "⚠️  Authentification SSH par mot de passe activée"
    fi
    
    # UFW status
    if ufw status | grep -q "Status: active"; then
        success "✅ Pare-feu UFW actif"
    else
        warn "⚠️  Pare-feu UFW inactif"
    fi
    
    # Fail2ban
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        success "✅ Fail2ban actif"
    else
        warn "⚠️  Fail2ban inactif ou non installé"
    fi
}

generate_diagnostic_report() {
    local domain="$1"
    local report_file="$REPORT_DIR/diagnostic_$(date +%Y%m%d_%H%M%S).txt"
    
    info "Génération du rapport de diagnostic..."
    
    {
        echo "=========================================="
        echo "RAPPORT DE DIAGNOSTIC VIP MANAGER"
        echo "Date: $(date)"
        echo "Domaine testé: ${domain:-"Aucun"}"
        echo "=========================================="
        echo
        
        echo "SYSTÈME:"
        echo "• OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Inconnu")"
        echo "• Kernel: $(uname -r)"
        echo "• Uptime: $(uptime -p 2>/dev/null || uptime)"
        echo
        
        echo "RESSOURCES:"
        echo "• RAM: $(free -h | awk '/^Mem:/ {print $2 " total, " $7 " disponible"}')"
        echo "• Swap: $(free -h | awk '/^Swap:/ {print $2 " total, " $4 " libre"}')"
        echo "• Disque /: $(df -h / | awk 'NR==2 {print $4 " libre sur " $2}')"
        echo "• Load: $(uptime | awk -F'load average:' '{print $2}')"
        echo
        
        echo "RÉSEAU:"
        if [[ -n "$domain" ]]; then
            echo "• DNS $domain: $(dig +short "$domain" A 2>/dev/null | head -1 || echo "Non résolu")"
        fi
        echo "• IP publique: $(get_public_ip || echo "Non détectée")"
        echo
        
        echo "SERVICES:"
        systemctl list-units --type=service --state=active | grep -E "(nginx|apache|mysql|ssh|fail2ban)" || echo "Aucun service web détecté"
        echo
        
    } > "$report_file"
    
    success "Rapport sauvegardé: $report_file"
    echo "$report_file"
}

run_full_diagnostic() {
    local domain="$1"
    
    info "🔍 Lancement du diagnostic complet système"
    echo "=========================================="
    
    check_system_load
    echo
    check_memory_usage
    echo
    check_disk_usage
    echo
    check_services_status
    echo
    check_security_status
    echo
    
    if [[ -n "$domain" ]]; then
        check_network_connectivity "$domain"
        echo
    fi
    
    local report_path
    report_path=$(generate_diagnostic_report "$domain")
    
    success "🎉 Diagnostic terminé!"
    info "📄 Rapport détaillé: $report_path"
    info "📋 Logs disponibles: $LOG_FILE"
}

# --------------------------------------------
# Installation et configuration services
# --------------------------------------------

backup_config_file() {
    local file="$1"
    local backup_name="$2"
    
    if [[ -f "$file" ]]; then
        local backup_path="${CONFIG_BACKUP_DIR}/${backup_name}.$(date +%s)"
        cp "$file" "$backup_path"
        debug "Sauvegarde: $file → $backup_path"
    fi
}

install_nginx() {
    info "🌐 Installation et configuration de Nginx..."
    
    backup_config_file "/etc/nginx/nginx.conf" "nginx.conf"
    
    ensure_package nginx
    
    # Configuration basique optimisée
    cat > /etc/nginx/conf.d/optimization.conf << 'EOF'
# Optimisations générales
sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
types_hash_max_size 2048;
server_tokens off;

# Gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
EOF
    
    systemctl enable nginx
    systemctl start nginx
    
    # Test configuration
    if nginx -t >/dev/null 2>&1; then
        success "✅ Nginx installé et configuré"
    else
        warn "⚠️  Erreur dans la configuration Nginx"
    fi
}

install_apache() {
    info "🌐 Installation et configuration d'Apache..."
    
    backup_config_file "/etc/apache2/apache2.conf" "apache2.conf"
    
    ensure_package apache2
    
    # Modules utiles
    a2enmod rewrite >/dev/null 2>&1 || true
    a2enmod ssl >/dev/null 2>&1 || true
    a2enmod headers >/dev/null 2>&1 || true
    
    systemctl enable apache2
    systemctl start apache2
    
    success "✅ Apache installé et configuré"
}

install_certbot() {
    info "🔒 Installation de Certbot pour SSL..."
    
    ensure_package certbot
    ensure_package python3-certbot-nginx
    ensure_package python3-certbot-apache
    
    success "✅ Certbot installé"
    info "📝 Pour obtenir un certificat SSL:"
    echo "   • Nginx: certbot --nginx -d votre-domaine.com"
    echo "   • Apache: certbot --apache -d votre-domaine.com"
}

configure_firewall() {
    info "🛡️  Configuration du pare-feu UFW..."
    
    backup_config_file "/etc/ufw/user.rules" "ufw-user.rules"
    
    # Reset UFW pour partir sur une base propre
    ufw --force reset >/dev/null 2>&1
    
    # Règles de base
    ufw default deny incoming
    ufw default allow outgoing
    
    # Services essentiels
    ufw allow OpenSSH
    ufw allow 'Nginx Full' 2>/dev/null || ufw allow 80,443/tcp
    ufw allow 'Apache Full' 2>/dev/null || true
    
    # Activer UFW
    ufw --force enable
    
    success "✅ Pare-feu UFW configuré et activé"
    
    # Afficher le statut
    info "Règles UFW actives:"
    ufw status numbered | grep -v "^$" | while read -r line; do
        echo "  $line"
    done
}

configure_fail2ban() {
    info "🛡️  Configuration de Fail2ban..."
    
    ensure_package fail2ban
    
    backup_config_file "/etc/fail2ban/jail.local" "jail.local"
    
    # Configuration personnalisée
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Temps de bannissement (en secondes)
bantime = 3600
# Période d'observation (en secondes)  
findtime = 600
# Nombre max de tentatives
maxretry = 3
# Action à effectuer
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    success "✅ Fail2ban configuré et activé"
}

create_default_vhost() {
    local domain="$1"
    local server_type="${2:-nginx}"
    
    if [[ "$server_type" == "nginx" ]]; then
        info "📄 Création du virtual host Nginx pour: $domain"
        
        local vhost_file="/etc/nginx/sites-available/$domain"
        local doc_root="/var/www/$domain"
        
        # Créer le répertoire web
        mkdir -p "$doc_root"
        
        # Page d'accueil simple
        cat > "$doc_root/index.html" << EOF
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$domain - Site configuré</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .success { color: #28a745; }
        .info { color: #007bff; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">✅ $domain fonctionne!</h1>
        <p>Votre serveur web est correctement configuré.</p>
        <div class="info">
            <p><strong>IP du serveur:</strong> $(get_public_ip)</p>
            <p><strong>Date de configuration:</strong> $(date)</p>
            <p><strong>Serveur:</strong> Nginx</p>
        </div>
    </div>
</body>
</html>
EOF
        
        # Configuration virtual host
        cat > "$vhost_file" << EOF
server {
    listen 80;
    server_name $domain www.$domain;
    root $doc_root;
    index index.html index.htm index.php;

    # Sécurité
    server_tokens off;
    
    # Logs
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Protection fichiers sensibles
    location ~ /\. {
        deny all;
    }
    
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF
        
        # Activer le site
        ln -sf "$vhost_file" "/etc/nginx/sites-enabled/$domain"
        rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
        
        # Test et reload
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx
            success "✅ Virtual host Nginx créé pour: $domain"
        else
            error "❌ Erreur dans la configuration Nginx"
            return 1
        fi
        
    elif [[ "$server_type" == "apache" ]]; then
        info "📄 Création du virtual host Apache pour: $domain"
        
        local vhost_file="/etc/apache2/sites-available/$domain.conf"
        local doc_root="/var/www/$domain"
        
        mkdir -p "$doc_root"
        
        # Page d'accueil Apache
        cat > "$doc_root/index.html" << EOF
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$domain - Site configuré</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .success { color: #28a745; }
        .info { color: #007bff; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">✅ $domain fonctionne!</h1>
        <p>Votre serveur web Apache est correctement configuré.</p>
        <div class="info">
            <p><strong>IP du serveur:</strong> $(get_public_ip)</p>
            <p><strong>Date de configuration:</strong> $(date)</p>
            <p><strong>Serveur:</strong> Apache</p>
        </div>
    </div>
</body>
</html>
EOF
        
        # Configuration virtual host Apache
        cat > "$vhost_file" << EOF
<VirtualHost *:80>
    ServerName $domain
    ServerAlias www.$domain
    DocumentRoot $doc_root
    
    # Logs
    ErrorLog \${APACHE_LOG_DIR}/${domain}_error.log
    CustomLog \${APACHE_LOG_DIR}/${domain}_access.log combined
    
    # Sécurité
    ServerTokens Prod
    
    <Directory $doc_root>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Protection fichiers sensibles
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>
</VirtualHost>
EOF
        
        # Activer le site
        a2ensite "$domain" >/dev/null 2>&1
        a2dissite 000-default >/dev/null 2>&1 || true
        
        # Test et reload
        if apache2ctl configtest >/dev/null 2>&1; then
            systemctl reload apache2
            success "✅ Virtual host Apache créé pour: $domain"
        else
            error "❌ Erreur dans la configuration Apache"
            return 1
        fi
    fi
    
    # Fixer les permissions
    chown -R www-data:www-data "$doc_root"
    chmod -R 755 "$doc_root"
}

# --------------------------------------------
# Auto-fix et maintenance
# --------------------------------------------

auto_fix_services() {
    info "🔧 Auto-fix: Démarrage des services..."
    
    local services_to_check=(
        "nginx:Nginx"
        "apache2:Apache" 
        "fail2ban:Fail2ban"
        "ufw:UFW"
    )
    
    for service_info in "${services_to_check[@]}"; do
        IFS=':' read -r service_name service_desc <<< "$service_info"
        
        if systemctl is-installed "$service_name" >/dev/null 2>&1; then
            if ! systemctl is-active --quiet "$service_name"; then
                info "Démarrage de $service_desc..."
                systemctl start "$service_name" || warn "Impossible de démarrer $service_name"
            fi
            
            if ! systemctl is-enabled --quiet "$service_name"; then
                systemctl enable "$service_name" >/dev/null 2>&1 || true
            fi
        fi
    done
}

auto_fix_permissions() {
    info "🔧 Auto-fix: Correction des permissions web..."
    
    local web_dirs=("/var/www" "/etc/nginx/sites-enabled" "/etc/apache2/sites-enabled")
    
    for dir in "${web_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f -exec chmod 644 {} \; 2>/dev/null || true
            find "$dir" -type d -exec chmod 755 {} \; 2>/dev/null || true
            
            # Propriétaire spécifique pour /var/www
            if [[ "$dir" == "/var/www" ]]; then
                chown -R www-data:www-data "$dir" 2>/dev/null || true
            fi
        fi
    done
}

auto_fix_firewall() {
    info "🔧 Auto-fix: Configuration pare-feu..."
    
    # S'assurer que les ports essentiels sont ouverts
    ufw allow OpenSSH >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    
    # Activer UFW s'il ne l'est pas
    if ! ufw status | grep -q "Status: active"; then
        ufw --force enable >/dev/null 2>&1 || true
    fi
}

guided_auto_fix() {
    require_root
    ensure_prereqs
    
    local total_ram_gb
    total_ram_gb=$(detect_total_ram_gb)
    local recommended_swap_gb
    recommended_swap_gb=$(recommend_swap_for_ram "$total_ram_gb")
    
    info "🛠️  Mode AUTO-FIX - Réparation automatique"
    echo "=========================================="
    info "RAM détectée: ${total_ram_gb}G"
    info "Swap recommandé: ${recommended_swap_gb}G" 
    echo
    
    echo -e "${YELLOW}Actions qui seront effectuées:${NC}"
    echo "  ✓ Création/vérification du swap"
    echo "  ✓ Démarrage des services web"
    echo "  ✓ Configuration du pare-feu"
    echo "  ✓ Correction des permissions"
    echo
    
    read -rp "Continuer avec l'auto-fix ? (y/N): " confirm
    [[ "$confirm" != [yY] ]] && { info "Auto-fix annulé"; return 0; }
    
    echo
    info "🚀 Début de l'auto-fix..."
    
    # Créer swap si nécessaire
    if ! swapon --show | grep -q "swap"; then
        create_swap_file "$recommended_swap_gb"
    else
        success "✅ Swap déjà configuré"
    fi
    
    auto_fix_services
    auto_fix_firewall
    auto_fix_permissions
    
    success "🎉 Auto-fix terminé!"
    info "Lancez un diagnostic pour vérifier: $0 --diag"
}

# --------------------------------------------
# Interface utilisateur principale
# --------------------------------------------

show_main_menu() {
    clear
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║                  🚀 ${COMPANY_NAME} VPS MANAGER                 ║${NC}"
    echo -e "${BOLD}${BLUE}║                     Version ${SCRIPT_VERSION}                    ║${NC}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║                                                              ║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}1)${NC} 🏗️  Installation complète d'un nouveau serveur    ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}2)${NC} 🔍 Diagnostic complet du système                   ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}3)${NC} 🛠️  Auto-réparation (services, swap, sécurité)    ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}4)${NC} 📊 Monitoring des performances en temps réel      ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}5)${NC} ⚙️  Configuration avancée                         ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}6)${NC} 📄 Voir les logs et rapports                      ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}0)${NC} 🚪 Quitter                                        ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║                                                              ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

get_user_input() {
    local prompt="$1"
    local default="$2"
    local validator="$3"
    local value=""
    
    while true; do
        if [[ -n "$default" ]]; then
            read -rp "$prompt [$default]: " value
            value=${value:-$default}
        else
            read -rp "$prompt: " value
        fi
        
        if [[ -z "$validator" ]] || eval "$validator '$value'"; then
            echo "$value"
            return 0
        else
            error "Valeur invalide, veuillez réessayer."
        fi
    done
}

interactive_installation() {
    require_root
    check_ubuntu_version
    ensure_prereqs
    check_internet_connectivity
    
    clear
    echo -e "${BOLD}${GREEN}🏗️  ASSISTANT D'INSTALLATION VPS${NC}"
    echo "=============================================="
    echo
    info "Cet assistant va configurer votre VPS étape par étape."
    echo
    
    # Configuration domaine
    echo -e "${CYAN}📋 CONFIGURATION DOMAINE${NC}"
    echo "----------------------------------------"
    local domain
    domain=$(get_user_input "🌐 Nom de domaine principal" "" "validate_domain")
    
    local public_ip
    public_ip=$(get_public_ip)
    if [[ -n "$public_ip" ]]; then
        info "IP publique détectée: $public_ip"
    else
        public_ip=$(get_user_input "🌍 IP publique de ce serveur" "" "validate_ip")
    fi
    
    echo
    echo -e "${YELLOW}💡 Configuration DNS requise:${NC}"
    echo "   Chez votre registrar, créez ces enregistrements:"
    echo -e "   ${WHITE}A${NC}     $domain     →  $public_ip"
    echo -e "   ${WHITE}A${NC}     www.$domain →  $public_ip"
    echo
    read -rp "Avez-vous configuré ces enregistrements DNS ? (y/N): " dns_ready
    
    # Configuration serveur web
    echo
    echo -e "${CYAN}🌐 SERVEUR WEB${NC}"
    echo "----------------------------------------"
    echo "Choisissez votre serveur web:"
    echo "  1) Nginx (recommandé - rapide et léger)"
    echo "  2) Apache (compatible avec plus d'applications)"
    echo "  3) Les deux (Nginx en frontal, Apache en backend)"
    echo
    
    local web_server_choice
    web_server_choice=$(get_user_input "Votre choix" "1" "[[ '$1' =~ ^[123]$ ]]")
    
    # Configuration SSL
    echo
    echo -e "${CYAN}🔒 CERTIFICAT SSL${NC}"
    echo "----------------------------------------"
    local use_ssl
    use_ssl=$(get_user_input "Installer un certificat SSL automatique avec Let's Encrypt ? (y/N)" "y" "[[ '$1' =~ ^[yYnN]$ ]]")
    
    local email=""
    if [[ "$use_ssl" == [yY] ]]; then
        email=$(get_user_input "📧 Email pour Let's Encrypt" "" "validate_email")
    fi
    
    # Configuration système
    echo
    echo -e "${CYAN}⚙️  CONFIGURATION SYSTÈME${NC}"
    echo "----------------------------------------"
    local total_ram_gb
    total_ram_gb=$(detect_total_ram_gb)
    local recommended_swap_gb
    recommended_swap_gb=$(recommend_swap_for_ram "$total_ram_gb")
    
    info "RAM détectée: ${total_ram_gb}G"
    info "Swap recommandé: ${recommended_swap_gb}G"
    
    local create_swap
    create_swap=$(get_user_input "Créer le fichier swap recommandé ? (Y/n)" "Y" "[[ '$1' =~ ^[yYnN]$ ]]")
    
    # Résumé de configuration
    echo
    echo -e "${BOLD}${WHITE}📋 RÉSUMÉ DE LA CONFIGURATION${NC}"
    echo "=============================================="
    echo "🌐 Domaine: $domain"
    echo "🌍 IP: $public_ip"
    echo "🖥️  Serveur web: $(case $web_server_choice in 1) echo "Nginx";; 2) echo "Apache";; 3) echo "Nginx + Apache";; esac)"
    echo "🔒 SSL: $(case $use_ssl in [yY]) echo "Oui ($email)";; *) echo "Non";; esac)"
    echo "💾 Swap: $(case $create_swap in [yY]) echo "${recommended_swap_gb}G";; *) echo "Non";; esac)"
    echo "📊 DNS configuré: $(case $dns_ready in [yY]) echo "Oui";; *) echo "Non";; esac)"
    echo
    
    read -rp "Confirmer et démarrer l'installation ? (y/N): " confirm_install
    [[ "$confirm_install" != [yY] ]] && { warn "Installation annulée par l'utilisateur"; return 0; }
    
    # DÉBUT DE L'INSTALLATION
    echo
    info "🚀 Démarrage de l'installation..."
    echo "=============================================="
    
    # 1. Système de base
    info "📦 Configuration système de base..."
    
    # 2. Swap
    if [[ "$create_swap" == [yY] ]]; then
        create_swap_file "$recommended_swap_gb"
    fi
    
    # 3. Pare-feu
    configure_firewall
    configure_fail2ban
    
    # 4. Serveur web
    case "$web_server_choice" in
        1) install_nginx ;;
        2) install_apache ;;
        3) install_nginx; install_apache ;;
    esac
    
    # 5. Virtual host
    case "$web_server_choice" in
        1) create_default_vhost "$domain" "nginx" ;;
        2) create_default_vhost "$domain" "apache" ;;
        3) create_default_vhost "$domain" "nginx" ;;
    esac
    
    # 6. SSL
    if [[ "$use_ssl" == [yY] ]]; then
        install_certbot
        
        if [[ "$dns_ready" == [yY] ]]; then
            info "🔒 Tentative d'obtention du certificat SSL..."
            case "$web_server_choice" in
                1|3) 
                    if certbot --nginx -d "$domain" -d "www.$domain" --email "$email" --agree-tos --non-interactive; then
                        success "✅ Certificat SSL installé!"
                    else
                        warn "⚠️  Échec SSL - vérifiez DNS et relancez: certbot --nginx -d $domain"
                    fi
                    ;;
                2)
                    if certbot --apache -d "$domain" -d "www.$domain" --email "$email" --agree-tos --non-interactive; then
                        success "✅ Certificat SSL installé!"
                    else
                        warn "⚠️  Échec SSL - vérifiez DNS et relancez: certbot --apache -d $domain"
                    fi
                    ;;
            esac
        else
            warn "DNS non configuré - configurez puis lancez:"
            echo "  certbot --nginx -d $domain -d www.$domain"
        fi
    fi
    
    # 7. Test final
    echo
    info "🧪 Tests finaux..."
    run_full_diagnostic "$domain"
    
    # RÉSULTAT FINAL
    echo
    success "🎉 INSTALLATION TERMINÉE!"
    echo "=============================================="
    echo
    echo -e "${GREEN}Votre serveur est maintenant configuré:${NC}"
    echo "🌐 Site web: http://$domain"
    [[ "$use_ssl" == [yY] ]] && echo "🔒 HTTPS: https://$domain"
    echo "📧 IP publique: $public_ip"
    echo "📄 Logs: $LOG_FILE"
    echo "📊 Rapports: $REPORT_DIR"
    echo
    
    if [[ "$dns_ready" != [yY] ]]; then
        echo -e "${YELLOW}⚠️  N'oubliez pas de configurer vos DNS:${NC}"
        echo "   A     $domain     → $public_ip"
        echo "   A     www.$domain → $public_ip"
        echo
    fi
    
    echo -e "${CYAN}Prochaines étapes recommandées:${NC}"
    echo "• Testez votre site: http://$domain"
    echo "• Configurez vos contenus web dans /var/www/$domain/"
    echo "• Surveillez les logs: tail -f $LOG_FILE"
    echo "• Lancez un diagnostic régulier: $0 --diag $domain"
}

show_performance_monitor() {
    while true; do
        clear
        echo -e "${BOLD}${CYAN}📊 MONITORING TEMPS RÉEL${NC}"
        echo "=============================================="
        echo "Rafraîchissement automatique - Ctrl+C pour quitter"
        echo
        
        check_system_load
        echo
        check_memory_usage  
        echo
        check_disk_usage
        echo
        
        echo -e "${DIM}Prochaine mise à jour dans 5 secondes...${NC}"
        sleep 5
    done
}

show_logs_and_reports() {
    clear
    echo -e "${BOLD}${PURPLE}📄 LOGS ET RAPPORTS${NC}"
    echo "=============================================="
    echo
    
    # Logs principaux
    if [[ -f "$LOG_FILE" ]]; then
        local log_size
        log_size=$(du -h "$LOG_FILE" | cut -f1)
        echo -e "${CYAN}📋 Log principal${NC} ($log_size): $LOG_FILE"
        echo "Dernières entrées:"
        tail -10 "$LOG_FILE" | sed 's/^/  /'
        echo
    fi
    
    # Rapports de diagnostic
    if [[ -d "$REPORT_DIR" ]]; then
        echo -e "${CYAN}📊 Rapports de diagnostic:${NC}"
        find "$REPORT_DIR" -name "*.txt" -type f -printf "%T@ %p\n" | sort -nr | head -5 | while read -r timestamp filepath; do
            local date_str
            date_str=$(date -d "@${timestamp%.*}" '+%Y-%m-%d %H:%M')
            echo "  $date_str - $(basename "$filepath")"
        done
        echo
    fi
    
    # Sauvegardes de configuration
    if [[ -d "$CONFIG_BACKUP_DIR" ]]; then
        echo -e "${CYAN}💾 Sauvegardes de configuration:${NC}"
        find "$CONFIG_BACKUP_DIR" -type f -printf "%T@ %p\n" | sort -nr | head -5 | while read -r timestamp filepath; do
            local date_str
            date_str=$(date -d "@${timestamp%.*}" '+%Y-%m-%d %H:%M')
            echo "  $date_str - $(basename "$filepath")"
        done
    fi
    
    echo
    read -rp "Appuyez sur Entrée pour continuer..."
}

interactive_main_menu() {
    require_root
    init_directories
    
    while true; do
        show_main_menu
        
        local choice
        read -rp "👉 Votre choix (0-6): " choice
        
        case "$choice" in
            1)
                interactive_installation
                ;;
            2)
                echo
                local domain
                domain=$(get_user_input "🌐 Domaine à diagnostiquer (optionnel)" "" "true")
                run_full_diagnostic "$domain"
                read -rp "Appuyez sur Entrée pour continuer..."
                ;;
            3)
                guided_auto_fix
                read -rp "Appuyez sur Entrée pour continuer..."
                ;;
            4)
                show_performance_monitor
                ;;
            5)
                echo
                warn "🚧 Fonctionnalité en développement"
                read -rp "Appuyez sur Entrée pour continuer..."
                ;;
            6)
                show_logs_and_reports
                ;;
            0)
                echo
                success "Merci d'avoir utilisé ${COMPANY_NAME} VPS Manager!"
                info "🔗 Support: https://vip-domaine.com"
                exit 0
                ;;
            *)
                error "Choix invalide. Utilisez 0-6."
                sleep 2
                ;;
        esac
    done
}

# --------------------------------------------
# Gestion des arguments en ligne de commande
# --------------------------------------------

show_usage() {
    cat << EOF
${BOLD}🚀 ${COMPANY_NAME} VPS Manager v${SCRIPT_VERSION}${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    ${CYAN}--install${NC}                          Lancer l'installation interactive complète
    ${CYAN}--diag [domaine]${NC}                   Diagnostic système (avec domaine optionnel)  
    ${CYAN}--diag-non-interactive <domaine> <ip>${NC} Diagnostic automatisé
    ${CYAN}--auto-fix${NC}                         Auto-réparation des services et configuration
    ${CYAN}--monitor${NC}                          Monitoring temps réel des performances
    ${CYAN}--logs${NC}                             Afficher les logs et rapports
    
    ${CYAN}--debug${NC}                            Mode debug (verbose)
    ${CYAN}--version${NC}                          Afficher la version
    ${CYAN}--help, -h${NC}                         Afficher cette aide

${BOLD}EXEMPLES:${NC}
    $0                                    # Menu interactif
    $0 --install                          # Installation guidée
    $0 --diag monsite.com                 # Diagnostic pour un domaine
    $0 --diag-non-interactive monsite.com 1.2.3.4
    $0 --auto-fix                         # Réparation automatique
    $0 --monitor                          # Surveillance temps réel

${BOLD}FICHIERS:${NC}
    Logs:        $LOG_FILE
    Rapports:    $REPORT_DIR
    Sauvegardes: $CONFIG_BACKUP_DIR

${BOLD}SUPPORT:${NC}
    🌐 https://vip-domaine.com
    📧 support@vip-domaine.com
EOF
}

parse_command_line() {
    # Initialiser les répertoires
    init_directories
    
    # Si aucun argument, lancer le menu interactif
    if [[ $# -eq 0 ]]; then
        interactive_main_menu
        return 0
    fi
    
    # Parser les arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install)
                require_root
                interactive_installation
                shift
                ;;
            --diag)
                require_root
                shift
                local domain="${1:-}"
                [[ -n "$domain" ]] && shift
                run_full_diagnostic "$domain"
                ;;
            --diag-non-interactive)
                require_root
                shift
                if [[ $# -lt 2 ]]; then
                    error "Usage: $0 --diag-non-interactive <domaine> <ip>"
                    exit 1
                fi
                
                local domain="$1"
                local ip="$2"
                
                if ! validate_domain "$domain"; then
                    fatal "Format de domaine invalide: $domain"
                fi
                
                if ! validate_ip "$ip"; then
                    fatal "Format d'IP invalide: $ip"
                fi
                
                # Assigner avant l'appel (fix de l'erreur originale)
                TARGET_VPS_IP="$ip"
                run_full_diagnostic "$domain"
                shift 2
                ;;
            --auto-fix)
                require_root
                guided_auto_fix
                shift
                ;;
            --monitor)
                require_root
                show_performance_monitor
                shift
                ;;
            --logs)
                show_logs_and_reports
                shift
                ;;
            --debug)
                export DEBUG=1
                debug "Mode debug activé"
                shift
                ;;
            --version)
                echo "${COMPANY_NAME} VPS Manager v${SCRIPT_VERSION}"
                echo "Compatible Ubuntu ${SUPPORTED_OS_VERSION}"
                exit 0
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                error "Option inconnue: $1"
                echo "Utilisez --help pour voir les options disponibles."
                exit 1
                ;;
        esac
    done
}

# --------------------------------------------
# POINT D'ENTRÉE PRINCIPAL
# --------------------------------------------

main() {
    # Vérification initiale
    require_root
    
    # Traitement des arguments
    parse_command_line "$@"
}

# Lancer le script si exécuté directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi