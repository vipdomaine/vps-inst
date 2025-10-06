#!/bin/bash
# =============================================
# VIP Domaine VPS Manager - Version avec Upgrade Ubuntu
# Compatible Ubuntu 20.04/22.04 - Niveau Production
# Version: 2025-10-06-UPGRADE-EDITION
# =============================================

# [... Code existant ...]
#!/bin/bash
# =============================================
# VIP Domaine VPS Manager - Version Globale Complète
# Compatible Ubuntu 22.04 - Niveau Production
# Fusion des 3 scripts : global + amélioration + cms
# Version: 2025-10-06-FUSION-COMPLETE-3SCRIPTS
# =============================================

# Gestion stricte des erreurs (fail-fast)
set -euo pipefail

# Variables globales et configuration
readonly SCRIPT_VERSION="2025-10-06-FUSION-COMPLETE-3SCRIPTS"
readonly COMPANY_NAME="VIP Domaine"
readonly SUPPORTED_OS_VERSION="22.04"
readonly DEFAULT_SWAP_GB=2
readonly LOG_FILE="/var/log/vip_manager.log"
readonly CONFIG_BACKUP_DIR="/root/vip_manager_backups"
readonly REPORT_DIR="/root/vip_reports"

# Variables du script amélioration + cms
SWAP_SIZE="2G"
DOMAINS=()
EMAIL=""
INSTALL_TYPE=""
CMS=""
SITE_NAME=""
DB_NAME=""
DB_USER=""
DB_PASS=""

# Couleurs pour interface utilisateur
readonly RED='[0;31m'
readonly GREEN='[0;32m'
readonly YELLOW='[1;33m'
readonly BLUE='[0;34m'
readonly PURPLE='[0;35m'
readonly CYAN='[0;36m'
readonly WHITE='[1;37m'
readonly BOLD='[1m'
readonly NC='[0m' # No Color

# Variables globales pour monitoring
declare -g TARGET_VPS_IP=""

# ============================================
# FONCTIONS UTILITAIRES DE BASE
# ============================================

# Créer les répertoires nécessaires
init_directories() {
    local dirs=("$(dirname "$LOG_FILE")" "$CONFIG_BACKUP_DIR" "$REPORT_DIR")
    for dir in "${dirs[@]}"; do
        [[ ! -d "$dir" ]] && mkdir -p "$dir"
    done
    touch "$LOG_FILE"
}

# Fonction pause du script amélioration
pause() {
    read -p "Appuyez sur Entrée pour continuer..."
}

# ============================================
# SYSTÈME DE LOGGING PROFESSIONNEL
# ============================================

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

# ============================================
# VÉRIFICATIONS SYSTÈME ET PRÉREQUIS
# ============================================

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
        dialog unzip
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

# ============================================
# FONCTIONS DE VALIDATION
# ============================================

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
        ip=$(eval "$service" 2>/dev/null | tr -d '

' || true)
        if validate_ip "$ip"; then
            echo "$ip"
            return 0
        fi
    done

    warn "Impossible de détecter l'IP publique automatiquement"
    echo ""
}

# ============================================
# GESTION MÉMOIRE ET SWAP (AMÉLIORATION)
# ============================================

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

# Fonction create_swap fusionnée et améliorée
create_swap() {
    if ! swapon --show | grep -q "swapfile"; then
        info "Création du swap $SWAP_SIZE..."

        # Backup de fstab avant modification
        cp /etc/fstab "${CONFIG_BACKUP_DIR}/fstab.backup.$(date +%s)" 2>/dev/null || true

        # Création du fichier swap
        if command -v fallocate >/dev/null 2>&1; then
            fallocate -l "$SWAP_SIZE" /swapfile
        else
            # Fallback avec dd si fallocate n'est pas disponible
            local size_mb
            size_mb=$(echo "$SWAP_SIZE" | sed 's/G//' | awk '{print $1 * 1024}')
            dd if=/dev/zero of=/swapfile bs=1M count="$size_mb" status=progress
        fi

        chmod 600 /swapfile
        mkswap /swapfile >/dev/null
        swapon /swapfile

        # Ajouter à fstab si pas déjà présent
        if ! grep -q "/swapfile" /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi

        # Optimisation swap (optionnel)
        echo 'vm.swappiness=10' >> /etc/sysctl.conf 2>/dev/null || true

        success "Swap $SWAP_SIZE créé et activé."
    else
        success "Swap déjà configuré."
    fi
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

# ============================================
# INSTALLATION PACKAGES FUSIONNÉE
# ============================================

install_packages() {
    info "Installation des paquets essentiels..."
    apt update && apt upgrade -y

    local packages=(
        curl wget git ufw unzip software-properties-common 
        apache2 nginx certbot python3-certbot-nginx python3-certbot-apache
        fail2ban lsb-release net-tools dnsutils bc jq openssl
        apt-transport-https mysql-server php php-mysql php-fmp 
        php-cli php-curl php-gd php-mbstring php-xml composer
        dialog htop vim
    )

    local failed_packages=()

    for pkg in "${packages[@]}"; do
        if ! ensure_package "$pkg"; then
            failed_packages+=("$pkg")
        fi
    done

    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        warn "Certains paquets n'ont pas pu être installés: ${failed_packages[*]}"
    else
        success "Tous les paquets essentiels sont installés"
    fi
}

# ============================================
# CONFIGURATION UFW FUSIONNÉE
# ============================================

configure_ufw() {
    info "Configuration du pare-feu UFW..."

    # Backup des règles existantes
    if [[ -f /etc/ufw/user.rules ]]; then
        cp /etc/ufw/user.rules "${CONFIG_BACKUP_DIR}/ufw-user.rules.$(date +%s)" 2>/dev/null || true
    fi

    ufw allow OpenSSH
    ufw allow 'Nginx Full' 2>/dev/null || ufw allow 80,443/tcp
    ufw allow 'Apache Full' 2>/dev/null || true
    ufw --force enable

    success "Pare-feu UFW configuré et activé"

    # Afficher le statut
    info "Règles UFW actives:"
    ufw status numbered | grep -v "^$" | head -10 | while read -r line; do
        echo "  $line"
    done
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

# ============================================
# FONCTIONS VIRTUALHOSTS (AMÉLIORATION)
# ============================================

create_virtualhost_nginx() {
    local domain=$1
    local webroot="/var/www/$domain/html"

    info "📄 Création du virtual host Nginx pour: $domain"

    mkdir -p "$webroot"
    chown -R www-data:www-data "$webroot"
    chmod -R 755 "/var/www"

    # Page d'accueil simple
    cat > "$webroot/index.html" << EOF
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
        <p>Votre serveur web Nginx est correctement configuré.</p>
        <div class="info">
            <p><strong>IP du serveur:</strong> $(get_public_ip)</p>
            <p><strong>Date de configuration:</strong> $(date)</p>
            <p><strong>Serveur:</strong> Nginx</p>
        </div>
    </div>
</body>
</html>
EOF

    cat > "/etc/nginx/sites-available/$domain" << EOF
server {
    listen 80;
    server_name $domain www.$domain;
    root $webroot;

    index index.html index.htm index.php;

    # Sécurité
    server_tokens off;

    # Logs
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
    }

    location ~ /\. {
        deny all;
    }

    location ~* \.(jpg|jpeg|png|gif|ico|css|js)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

    ln -sf "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/$domain"
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

    # Test et reload
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || systemctl restart nginx
        success "✅ Virtual host Nginx créé pour: $domain"
    else
        error "❌ Erreur dans la configuration Nginx"
        return 1
    fi
}

create_virtualhost_apache() {
    local domain=$1
    local webroot="/var/www/$domain/html"

    info "📄 Création du virtual host Apache pour: $domain"

    mkdir -p "$webroot"
    chown -R www-data:www-data "$webroot"

    # Page d'accueil Apache
    cat > "$webroot/index.html" << EOF
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

    cat > "/etc/apache2/sites-available/$domain.conf" << EOF
<VirtualHost *:80>
    ServerAdmin $EMAIL
    ServerName $domain
    ServerAlias www.$domain
    DocumentRoot $webroot

    # Logs
    ErrorLog \${APACHE_LOG_DIR}/${domain}_error.log
    CustomLog \${APACHE_LOG_DIR}/${domain}_access.log combined

    # Sécurité
    ServerTokens Prod

    <Directory $webroot>
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

    a2ensite "$domain.conf" >/dev/null 2>&1
    a2dissite 000-default >/dev/null 2>&1 || true

    # Test et reload
    if apache2ctl configtest >/dev/null 2>&1; then
        systemctl reload apache2 2>/dev/null || systemctl restart apache2
        success "✅ Virtual host Apache créé pour: $domain"
    else
        error "❌ Erreur dans la configuration Apache"
        return 1
    fi
}

# ============================================
# SSL/CERTBOT (AMÉLIORATION)
# ============================================

enable_ssl_nginx() {
    local domain=$1
    info "🔒 Activation SSL via Certbot pour: $domain"

    if [[ -z "$EMAIL" ]]; then
        read -rp "Entrez votre email pour Certbot: " EMAIL
        if ! validate_email "$EMAIL"; then
            error "Email invalide"
            return 1
        fi
    fi

    if certbot --nginx -d "$domain" -d "www.$domain" -m "$EMAIL" --agree-tos --redirect --non-interactive >/dev/null 2>&1; then
        success "✅ SSL activé via Certbot pour $domain"
    else
        warn "⚠️  Impossible d'activer SSL pour $domain (vérifiez DNS/connectivité)"
        return 1
    fi
}

enable_ssl_apache() {
    local domain=$1
    info "🔒 Activation SSL via Certbot pour Apache: $domain"

    if [[ -z "$EMAIL" ]]; then
        read -rp "Entrez votre email pour Certbot: " EMAIL
        if ! validate_email "$EMAIL"; then
            error "Email invalide"
            return 1
        fi
    fi

    if certbot --apache -d "$domain" -d "www.$domain" -m "$EMAIL" --agree-tos --redirect --non-interactive >/dev/null 2>&1; then
        success "✅ SSL activé via Certbot pour Apache $domain"
    else
        warn "⚠️  Impossible d'activer SSL pour $domain (vérifiez DNS/connectivité)"
        return 1
    fi
}

# ============================================
# SERVICES ET REDÉMARRAGES (AMÉLIORATION)
# ============================================

restart_services() {
    info "🔄 Redémarrage des services..."

    local services=("nginx" "apache2" "mysql" "php8.2-fpm")

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            if systemctl restart "$service" 2>/dev/null; then
                success "✅ Service $service redémarré"
            else
                warn "⚠️  Impossible de redémarrer $service"
            fi
        else
            debug "Service $service non actif, ignoré"
        fi
    done
}

# ============================================
# FONCTIONS CMS (SCRIPT CMS)
# ============================================

# Fonctions utilitaires du script CMS
ask_install_type() {
    INSTALL_TYPE=$(dialog --stdout --menu "Que voulez-vous faire ?" 12 60 4         1 "Installation serveur basique (amélioration)"         2 "Installation complète avec CMS"         3 "Installation Ubuntu + paquets essentiels"         4 "Mode diagnostic et monitoring")
    clear
}

ask_cms() {
    CMS=$(dialog --stdout --menu "Choisissez le CMS à installer" 15 60 5         1 "WordPress"         2 "PrestaShop"         3 "Magento"         4 "Drupal"         5 "Aucun CMS (site statique)")
    clear
}

ask_site_info() {
    SITE_NAME=$(dialog --stdout --inputbox "Nom de domaine ou IP du site :" 8 50)
    clear
    DB_NAME=$(dialog --stdout --inputbox "Nom de la base de données :" 8 40)
    clear
    DB_USER=$(dialog --stdout --inputbox "Nom utilisateur DB :" 8 40)
    clear
    DB_PASS=$(dialog --stdout --passwordbox "Mot de passe DB :" 8 40)
    clear
}

setup_mysql() {
    info "Configuration de la base de données MySQL..."

    # Sécuriser MySQL si nécessaire
    if ! mysql -e "SELECT 1;" 2>/dev/null; then
        warn "MySQL nécessite une configuration initiale"
        mysql_secure_installation
    fi

    mysql -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME};" 2>/dev/null || {
        error "Impossible de créer la base de données $DB_NAME"
        return 1
    }
    mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';" 2>/dev/null || true
    mysql -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true

    success "Base de données MySQL configurée: $DB_NAME"
}

install_wordpress() {
    info "Installation de WordPress..."
    mkdir -p "/var/www/$SITE_NAME"
    cd "/var/www/$SITE_NAME"

    # Télécharger WordPress
    if ! wget -q https://wordpress.org/latest.tar.gz; then
        error "Impossible de télécharger WordPress"
        return 1
    fi

    tar -xzf latest.tar.gz --strip-components=1
    rm latest.tar.gz

    chown -R www-data:www-data "/var/www/$SITE_NAME"
    chmod -R 755 "/var/www/$SITE_NAME"

    # Configuration WordPress
    if [[ -f wp-config-sample.php ]]; then
        cp wp-config-sample.php wp-config.php
        sed -i "s/database_name_here/$DB_NAME/" wp-config.php
        sed -i "s/username_here/$DB_USER/" wp-config.php
        sed -i "s/password_here/$DB_PASS/" wp-config.php

        # Ajouter des clés de sécurité
        local salt_keys
        salt_keys=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/ 2>/dev/null || true)
        if [[ -n "$salt_keys" ]]; then
            sed -i '/put your unique phrase here/d' wp-config.php
            echo "$salt_keys" >> wp-config.php
        fi
    fi

    success "WordPress installé dans /var/www/$SITE_NAME"
}

install_prestashop() {
    info "Installation de PrestaShop..."
    mkdir -p "/var/www/$SITE_NAME"
    cd "/var/www/$SITE_NAME"

    if ! wget -q https://download.prestashop.com/download/releases/prestashop_8.1.0.zip; then
        error "Impossible de télécharger PrestaShop"
        return 1
    fi

    unzip -q prestashop_8.1.0.zip -d "/var/www/$SITE_NAME"
    rm prestashop_8.1.0.zip

    chown -R www-data:www-data "/var/www/$SITE_NAME"
    chmod -R 755 "/var/www/$SITE_NAME"

    success "PrestaShop installé dans /var/www/$SITE_NAME"
}

install_drupal() {
    info "Installation de Drupal..."
    mkdir -p "/var/www/$SITE_NAME"
    cd "/var/www/$SITE_NAME"

    if ! wget -q https://www.drupal.org/download-latest/tar.gz -O drupal.tar.gz; then
        error "Impossible de télécharger Drupal"
        return 1
    fi

    tar -xzf drupal.tar.gz --strip-components=1
    rm drupal.tar.gz

    chown -R www-data:www-data "/var/www/$SITE_NAME"
    chmod -R 755 "/var/www/$SITE_NAME"

    success "Drupal installé dans /var/www/$SITE_NAME"
}

install_magento() {
    info "Installation de Magento..."
    mkdir -p "/var/www/$SITE_NAME"
    cd "/var/www/$SITE_NAME"

    # Vérifier si Composer est disponible
    if ! command -v composer >/dev/null 2>&1; then
        error "Composer non installé, requis pour Magento"
        return 1
    fi

    # Installation Magento via Composer
    if ! composer create-project --repository=https://repo.magento.com/ magento/project-community-edition . 2>/dev/null; then
        warn "Impossible d'installer Magento via Composer (authentification repo.magento.com requise)"
        info "Vous devrez configurer vos clés d'accès Magento manuellement"
        return 1
    fi

    chown -R www-data:www-data "/var/www/$SITE_NAME"
    chmod -R 755 "/var/www/$SITE_NAME"

    success "Magento installé dans /var/www/$SITE_NAME"
}

configure_nginx_cms() {
    local site_name="$1"
    info "Configuration Nginx pour: $site_name"

    cat > "/etc/nginx/sites-available/$site_name" <<EOL
server {
    listen 80;
    server_name $site_name;

    root /var/www/$site_name;
    index index.php index.html index.htm;

    # Sécurité
    server_tokens off;

    # Logs
    access_log /var/log/nginx/${site_name}_access.log;
    error_log /var/log/nginx/${site_name}_error.log;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }

    # WordPress specific
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOL

    ln -sf "/etc/nginx/sites-available/$site_name" "/etc/nginx/sites-enabled/"

    # Test configuration
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx
        success "Configuration Nginx créée pour: $site_name"
    else
        error "Erreur dans la configuration Nginx"
        return 1
    fi
}

install_ubuntu_basics() {
    info "Installation Ubuntu basique..."
    apt update
    apt install -y curl wget git ufw fail2ban htop vim

    info "Configuration firewall (UFW)..."
    ufw allow OpenSSH
    ufw --force enable

    success "Installation Ubuntu basique terminée."
    pause
}

# ============================================
# DIAGNOSTIC SYSTÈME AVANCÉ (SCRIPTE-GLOBALE)
# ============================================

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
        "php8.2-fmp:PHP-FPM"
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

# ============================================
# CONFIGURATION SERVICES AVANCÉE
# ============================================

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

install_mysql() {
    info "🗄️  Installation et configuration de MySQL..."

    ensure_package mysql-server

    systemctl enable mysql
    systemctl start mysql

    success "✅ MySQL installé et démarré"
    info "⚠️  N'oubliez pas de sécuriser MySQL avec: mysql_secure_installation"
}

install_php() {
    info "🐘 Installation de PHP et extensions..."

    local php_packages=(
        php php-fmp php-mysql php-cli php-curl 
        php-gd php-mbstring php-xml php-zip php-intl
    )

    for pkg in "${php_packages[@]}"; do
        ensure_package "$pkg" || warn "Impossible d'installer $pkg"
    done

    systemctl enable php8.2-fmp
    systemctl start php8.2-fmp

    success "✅ PHP installé et configuré"
}

# ============================================
# MONITORING TEMPS RÉEL
# ============================================

show_performance_monitor() {
    clear
    echo -e "${BOLD}${CYAN}📊 MONITORING TEMPS RÉEL${NC}"
    echo "========================================"
    echo "Appuyez sur Ctrl+C pour arrêter"
    echo

    while true; do
        # Remonte en haut de l'écran
        tput cup 3 0

        # CPU et Load
        local load_1min load_5min load_15min
        read -r load_1min load_5min load_15min < /proc/loadavg
        local cpu_cores=$(nproc)

        echo -e "${YELLOW}🖥️  PROCESSEUR${NC}"
        echo "Load: $load_1min (1min) | $load_5min (5min) | $load_15min (15min)"
        echo "Cœurs CPU: $cpu_cores"
        echo

        # Mémoire
        local mem_info=$(free -m)
        local mem_total=$(echo "$mem_info" | awk '/^Mem:/ {print $2}')
        local mem_used=$(echo "$mem_info" | awk '/^Mem:/ {print $3}')
        local mem_free=$(echo "$mem_info" | awk '/^Mem:/ {print $4}')
        local mem_percent=$(( (mem_used * 100) / mem_total ))

        echo -e "${YELLOW}💾 MÉMOIRE${NC}"
        echo "Utilisée: ${mem_used}MB / ${mem_total}MB (${mem_percent}%)"
        echo "Libre: ${mem_free}MB"
        echo

        # Disque
        echo -e "${YELLOW}💿 STOCKAGE${NC}"
        df -h / | awk 'NR==2 {printf "Utilisé: %s / %s (%s)\n", $3, $2, $5}'
        echo

        # Réseau (si disponible)
        if command -v ss >/dev/null 2>&1; then
            local tcp_connections=$(ss -t | wc -l)
            echo -e "${YELLOW}🌐 RÉSEAU${NC}"
            echo "Connexions TCP actives: $((tcp_connections - 1))"
            echo
        fi

        # Services critiques
        echo -e "${YELLOW}⚙️  SERVICES${NC}"
        local services=("nginx" "apache2" "mysql" "fail2ban")
        for service in "${services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                echo -e "  ${GREEN}●${NC} $service"
            elif systemctl is-installed "$service" >/dev/null 2>&1; then
                echo -e "  ${RED}●${NC} $service (arrêté)"
            fi
        done

        echo
        echo "Dernière mise à jour: $(date '+%H:%M:%S')"

        # Effacer le reste de l'écran
        tput ed

        sleep 2
    done
}

# ============================================
# AUTO-FIX ET MAINTENANCE
# ============================================

auto_fix_services() {
    info "🔧 Auto-fix: Démarrage des services..."

    local services_to_check=(
        "nginx:Nginx"
        "apache2:Apache" 
        "mysql:MySQL"
        "php8.2-fmp:PHP-FPM"
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

# ============================================
# INTERFACE UTILISATEUR PRINCIPALE
# ============================================

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

show_main_menu() {
    clear
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║           🚀 ${COMPANY_NAME} VPS MANAGER COMPLET            ║${NC}"
    echo -e "${BOLD}${BLUE}║                     Version ${SCRIPT_VERSION}           ║${NC}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║                                                              ║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}1)${NC} 🏗️  Installation serveur basique (amélioration)    ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}2)${NC} 🎨 Installation complète avec CMS                  ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}3)${NC} 📦 Installation Ubuntu + paquets essentiels       ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}4)${NC} 🔍 Diagnostic complet du système                   ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}5)${NC} 🛠️  Auto-réparation (services, swap, sécurité)    ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}6)${NC} 📊 Monitoring des performances en temps réel      ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}7)${NC} 📄 Voir les logs et rapports                      ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}0)${NC} 🚪 Quitter                                        ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║                                                              ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Mode installation serveur basique (script amélioration)
installation_serveur_basique() {
    clear
    echo -e "${BOLD}${GREEN}🏗️  INSTALLATION SERVEUR BASIQUE${NC}"
    echo "=========================================="
    echo

    info "Cette installation va configurer:"
    echo "  ✓ Swap optimisé"
    echo "  ✓ Paquets essentiels" 
    echo "  ✓ Nginx + Apache"
    echo "  ✓ Pare-feu UFW"
    echo "  ✓ Certificats SSL"
    echo "  ✓ Virtual hosts"
    echo

    read -rp "Continuer avec l'installation ? (y/N): " confirm
    [[ "$confirm" != [yY] ]] && { info "Installation annulée"; return 0; }

    echo

    # Vérifications préliminaires
    check_ubuntu_version
    check_internet_connectivity
    ensure_prereqs

    # Détection RAM et recommandation swap
    local total_ram_gb
    total_ram_gb=$(detect_total_ram_gb)
    local recommended_swap_gb
    recommended_swap_gb=$(recommend_swap_for_ram "$total_ram_gb")

    info "RAM détectée: ${total_ram_gb}G"
    info "Swap recommandé: ${recommended_swap_gb}G"

    # Demander swap personnalisé ou utiliser recommandation
    local swap_choice
    swap_choice=$(get_user_input "Taille du swap en GB" "$recommended_swap_gb" "true")
    SWAP_SIZE="${swap_choice}G"

    # Email pour SSL
    EMAIL=$(get_user_input "Email pour Certbot SSL" "" "validate_email")

    # Domaines
    echo
    info "Entrez vos domaines (un par ligne, ligne vide pour terminer):"
    DOMAINS=()
    while true; do
        read -rp "Domaine: " domain
        [[ -z "$domain" ]] && break

        if validate_domain "$domain"; then
            DOMAINS+=("$domain")
            success "✅ $domain ajouté"
        else
            warn "Domaine invalide ignoré: $domain"
        fi
    done

    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        warn "Aucun domaine configuré, seule l'installation système sera effectuée"
    fi

    echo
    info "🚀 Début de l'installation..."

    # Installation swap
    create_swap

    # Installation paquets
    install_packages

    # Configuration pare-feu
    configure_ufw

    # Configuration domaines
    for domain in "${DOMAINS[@]}"; do
        info "========== Configuration pour $domain =========="
        create_virtualhost_nginx "$domain"
        create_virtualhost_apache "$domain"

        # SSL (avec gestion d'erreur)
        if ! enable_ssl_nginx "$domain"; then
            warn "SSL non configuré pour $domain, vérifiez DNS plus tard"
        fi
    done

    # Redémarrage des services
    restart_services

    echo
    success "🎉 Installation terminée!"

    # Rapport final
    echo
    info "========== RAPPORT FINAL =========="
    if [[ ${#DOMAINS[@]} -gt 0 ]]; then
        echo "Domaines configurés : ${DOMAINS[*]}"
    fi
    echo "Services actifs :"
    systemctl status nginx apache2 2>/dev/null | grep "Active:" || true
    echo "Swap configuré :"
    swapon --show
    echo "Pare-feu UFW :"
    ufw status verbose | head -10

    info "📋 Logs disponibles : $LOG_FILE"

    pause
}

# Mode installation CMS (script CMS fusionné)
installation_cms_complete() {
    clear
    echo -e "${BOLD}${GREEN}🎨 INSTALLATION COMPLÈTE AVEC CMS${NC}"
    echo "=========================================="
    echo

    # Vérifications préliminaires
    check_ubuntu_version
    check_internet_connectivity
    ensure_prereqs

    # Installation des services de base
    info "🔧 Installation des services de base..."
    install_packages
    install_nginx
    install_apache
    install_mysql
    install_php
    configure_firewall
    configure_fail2ban

    echo
    info "🎨 Configuration du CMS..."

    # Interface CMS
    ask_cms

    if [[ "$CMS" != "5" ]]; then
        ask_site_info

        # Validation des entrées
        if ! validate_domain "$SITE_NAME"; then
            error "Nom de domaine invalide: $SITE_NAME"
            return 1
        fi

        if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASS" ]]; then
            error "Informations de base de données incomplètes"
            return 1
        fi

        # Configuration MySQL
        setup_mysql

        # Installation du CMS choisi
        case $CMS in
            1) install_wordpress ;;
            2) install_prestashop ;;
            3) install_magento ;;
            4) install_drupal ;;
            *) error "CMS non sélectionné"; return 1 ;;
        esac

        # Configuration Nginx pour le CMS
        configure_nginx_cms "$SITE_NAME"

        echo
        success "========== Installation CMS terminée =========="
        info "🌐 Accédez à votre site sur http://$SITE_NAME pour terminer la configuration via l'interface web."

        # Informations de connexion DB
        echo
        info "📋 Informations de base de données:"
        echo "  • Nom de la base: $DB_NAME"
        echo "  • Utilisateur: $DB_USER" 
        echo "  • Mot de passe: [confidentiel]"
        echo "  • Host: localhost"

    else
        info "Site statique - configuration basique"
        SITE_NAME=$(get_user_input "Nom de domaine" "" "validate_domain")
        create_virtualhost_nginx "$SITE_NAME"
        success "Site statique configuré pour: $SITE_NAME"
    fi

    # Test SSL optionnel
    echo
    read -rp "🔒 Configurer SSL avec Let's Encrypt ? (y/N): " setup_ssl
    if [[ "$setup_ssl" == [yY] ]]; then
        EMAIL=$(get_user_input "Email pour SSL" "" "validate_email")
        if ! enable_ssl_nginx "$SITE_NAME"; then
            warn "Vérifiez que le DNS pointe vers ce serveur et relancez:"
            echo "  certbot --nginx -d $SITE_NAME"
        fi
    fi

    pause
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
        find "$REPORT_DIR" -name "*.txt" -type f -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -5 | while read -r timestamp filepath; do
            local date_str
            date_str=$(date -d "@${timestamp%.*}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "Date inconnue")
            echo "  $date_str - $(basename "$filepath")"
        done
        echo
    fi

    # Sauvegardes de configuration
    if [[ -d "$CONFIG_BACKUP_DIR" ]]; then
        echo -e "${CYAN}💾 Sauvegardes de configuration:${NC}"
        find "$CONFIG_BACKUP_DIR" -type f -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -5 | while read -r timestamp filepath; do
            local date_str
            date_str=$(date -d "@${timestamp%.*}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "Date inconnue")
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
        read -rp "👉 Votre choix (0-7): " choice

        case "$choice" in
            1)
                installation_serveur_basique
                ;;
            2)
                installation_cms_complete
                ;;
            3)
                install_ubuntu_basics
                ;;
            4)
                echo
                local domain
                domain=$(get_user_input "🌐 Domaine à diagnostiquer (optionnel)" "" "true")
                run_full_diagnostic "$domain"
                read -rp "Appuyez sur Entrée pour continuer..."
                ;;
            5)
                guided_auto_fix
                read -rp "Appuyez sur Entrée pour continuer..."
                ;;
            6)
                show_performance_monitor
                ;;
            7)
                show_logs_and_reports
                ;;
            0)
                echo
                success "Merci d'avoir utilisé ${COMPANY_NAME} VPS Manager!"
                info "🔗 Support: https://vip-domaine.com"
                exit 0
                ;;
            *)
                error "Choix invalide. Utilisez 0-7."
                sleep 2
                ;;
        esac
    done
}

# ============================================
# GESTION DES ARGUMENTS EN LIGNE DE COMMANDE
# ============================================

show_usage() {
    cat << EOF
${BOLD}🚀 ${COMPANY_NAME} VPS Manager v${SCRIPT_VERSION}${NC}
${BOLD}Script global fusionné complet (3 scripts)${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    ${CYAN}--install-basic${NC}                    Installation serveur basique (amélioration)
    ${CYAN}--install-cms${NC}                      Installation complète avec CMS
    ${CYAN}--install-ubuntu${NC}                   Installation Ubuntu basique uniquement
    ${CYAN}--diag [domaine]${NC}                   Diagnostic système (avec domaine optionnel)  
    ${CYAN}--diag-non-interactive <domaine> <ip>${NC} Diagnostic automatisé
    ${CYAN}--auto-fix${NC}                         Auto-réparation des services et configuration
    ${CYAN}--monitor${NC}                          Monitoring temps réel des performances
    ${CYAN}--logs${NC}                             Afficher les logs et rapports

    ${CYAN}--debug${NC}                            Mode debug (verbose)
    ${CYAN}--version${NC}                          Afficher la version
    ${CYAN}--help, -h${NC}                         Afficher cette aide

${BOLD}MODES D'INSTALLATION:${NC}
    ${GREEN}Serveur basique${NC}    : Nginx + Apache + SSL + Swap + Multi-domaines
    ${GREEN}CMS complet${NC}        : Serveur + MySQL + PHP + CMS (WordPress/etc.)
    ${GREEN}Ubuntu basique${NC}     : Paquets essentiels + Firewall uniquement

${BOLD}EXEMPLES:${NC}
    $0                                    # Menu interactif complet
    $0 --install-basic                    # Mode serveur basique  
    $0 --install-cms                      # Mode CMS avec interface
    $0 --diag monsite.com                 # Diagnostic pour un domaine
    $0 --auto-fix                         # Réparation automatique
    $0 --monitor                          # Surveillance temps réel

${BOLD}FICHIERS:${NC}
    Logs:        $LOG_FILE
    Rapports:    $REPORT_DIR
    Sauvegardes: $CONFIG_BACKUP_DIR

${BOLD}SUPPORT:${NC}
    🌐 https://vip-domaine.com
    📧 support@vip-domaine.com

${BOLD}FUSION COMPLÈTE:${NC}
    ✅ Script global professionnel (logging, diagnostic, monitoring)
    ✅ Script amélioration (serveur multi-domaines, SSL, swap)
    ✅ Script CMS (WordPress, PrestaShop, Magento, Drupal)
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
            --install-basic)
                require_root
                installation_serveur_basique
                shift
                ;;
            --install-cms)
                require_root
                installation_cms_complete
                shift
                ;;
            --install-ubuntu)
                require_root
                install_ubuntu_basics
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

                # Assigner avant l'appel
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
                echo "Fusion complète de 3 scripts:"
                echo "  • Script global professionnel"
                echo "  • Script amélioration serveur" 
                echo "  • Script installation CMS"
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

# ============================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================

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

# ============================================
# FONCTIONS D'UPGRADE UBUNTU
# ============================================

detect_ubuntu_version() {
    local version=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        version="$VERSION_ID"
    fi
    echo "$version"
}

can_upgrade_to_2204() {
    local current_version="$1"
    
    case "$current_version" in
        "20.04"|"21.04"|"21.10")
            return 0  # Peut upgrader
            ;;
        "22.04")
            info "Ubuntu 22.04 déjà installé"
            return 1  # Pas besoin d'upgrade
            ;;
        *)
            error "Version Ubuntu $current_version non supportée pour upgrade"
            return 1  # Ne peut pas upgrader
            ;;
    esac
}

backup_system_before_upgrade() {
    info "🛡️  Sauvegarde système avant upgrade..."
    
    local backup_dir="/root/backup_pre_upgrade_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Sauvegardes critiques
    cp -r /etc/apt "$backup_dir/" 2>/dev/null || true
    cp -r /etc/nginx "$backup_dir/" 2>/dev/null || true
    cp -r /etc/apache2 "$backup_dir/" 2>/dev/null || true
    cp /etc/fstab "$backup_dir/" 2>/dev/null || true
    
    # Liste des paquets installés
    dpkg --get-selections > "$backup_dir/installed_packages.txt"
    
    success "Sauvegarde créée dans: $backup_dir"
}

upgrade_ubuntu_to_2204() {
    local current_version
    current_version=$(detect_ubuntu_version)
    
    if ! can_upgrade_to_2204 "$current_version"; then
        return 1
    fi
    
    info "🚀 Upgrade Ubuntu $current_version vers 22.04..."
    
    # Avertissements
    echo -e "${RED}⚠️  AVERTISSEMENT CRITIQUE ⚠️${NC}"
    echo "L'upgrade Ubuntu peut:"
    echo "  • Prendre 30-60 minutes"
    echo "  • Redémarrer le serveur automatiquement"
    echo "  • Interrompre les services temporairement"
    echo "  • Nécessiter une connexion stable"
    echo
    read -rp "Voulez-vous continuer l'upgrade ? (y/N): " confirm
    [[ "$confirm" != [yY] ]] && { info "Upgrade annulée"; return 1; }
    
    # Sauvegarde préventive
    backup_system_before_upgrade
    
    # Mise à jour des paquets actuels
    info "📦 Mise à jour système actuel..."
    apt update && apt upgrade -y
    apt dist-upgrade -y
    apt autoremove -y
    
    # Installation update-manager
    ensure_package update-manager-core
    
    # Configuration upgrade
    sed -i 's/Prompt=.*/Prompt=lts/' /etc/update-manager/release-upgrades 2>/dev/null || true
    
    # Lancement upgrade
    info "🔄 Lancement do-release-upgrade..."
    
    # Mode non-interactif pour automatisation
    export DEBIAN_FRONTEND=noninteractive
    
    # Upgrade avec options automatisées
    do-release-upgrade -f DistUpgradeViewNonInteractive || {
        error "Échec de l'upgrade Ubuntu"
        return 1
    }
    
    success "✅ Upgrade Ubuntu vers 22.04 terminée"
    
    # Vérification post-upgrade
    local new_version
    new_version=$(detect_ubuntu_version)
    if [[ "$new_version" == "22.04" ]]; then
        success "🎉 Ubuntu 22.04 confirmé après upgrade"
    else
        warn "⚠️  Version détectée après upgrade: $new_version"
    fi
    
    # Redémarrage recommandé
    echo
    warn "🔄 Redémarrage recommandé après upgrade"
    read -rp "Redémarrer maintenant ? (y/N): " reboot_confirm
    if [[ "$reboot_confirm" == [yY] ]]; then
        info "Redémarrage dans 10 secondes..."
        sleep 10
        reboot
    fi
}

# ============================================
# MENU PRINCIPAL ÉTENDU
# ============================================

show_main_menu_extended() {
    clear
    local current_version
    current_version=$(detect_ubuntu_version)
    
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║           🚀 VIP MANAGER COMPLET + UPGRADE              ║${NC}"
    echo -e "${BOLD}${BLUE}║                  Ubuntu: $current_version détecté                    ║${NC}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║                                                              ║${NC}"
    
    # Option upgrade si nécessaire
    if can_upgrade_to_2204 "$current_version"; then
        echo -e "${BOLD}${BLUE}║  ${WHITE}0)${NC} 🔄 UPGRADE vers Ubuntu 22.04 (REQUIS)            ${BOLD}${BLUE}║${NC}"
        echo -e "${BOLD}${BLUE}║                                                              ║${NC}"
    fi
    
    echo -e "${BOLD}${BLUE}║  ${WHITE}1)${NC} 🏗️  Installation serveur basique (amélioration)    ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}2)${NC} 🎨 Installation complète avec CMS                  ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}3)${NC} 📦 Installation Ubuntu + paquets essentiels       ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}4)${NC} 🔍 Diagnostic complet du système                   ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}5)${NC} 🛠️  Auto-réparation (services, swap, sécurité)    ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}6)${NC} 📊 Monitoring des performances en temps réel      ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}7)${NC} 📄 Voir les logs et rapports                      ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║  ${WHITE}9)${NC} 🚪 Quitter                                        ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║                                                              ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    if can_upgrade_to_2204 "$current_version"; then
        warn "⚠️  Ubuntu $current_version détecté. Upgrade vers 22.04 recommandé avant utilisation."
    fi
}

interactive_main_menu_extended() {
    require_root
    init_directories
    
    local current_version
    current_version=$(detect_ubuntu_version)
    
    while true; do
        show_main_menu_extended
        
        local choice
        if can_upgrade_to_2204 "$current_version"; then
            read -rp "👉 Votre choix (0=Upgrade, 1-7=Config, 9=Quit): " choice
        else
            read -rp "👉 Votre choix (1-7, 9=Quit): " choice
        fi
        
        case "$choice" in
            0)
                if can_upgrade_to_2204 "$current_version"; then
                    upgrade_ubuntu_to_2204
                    current_version=$(detect_ubuntu_version)  # Refresh après upgrade
                else
                    error "Option upgrade non disponible pour cette version"
                fi
                ;;
            1)
                if [[ "$current_version" == "22.04" ]]; then
                    installation_serveur_basique
                else
                    error "Ubuntu 22.04 requis. Utilisez l'option 0 pour upgrader d'abord."
                fi
                ;;
            2)
                if [[ "$current_version" == "22.04" ]]; then
                    installation_cms_complete
                else
                    error "Ubuntu 22.04 requis. Utilisez l'option 0 pour upgrader d'abord."
                fi
                ;;
            # [... autres options ...]
            9)
                echo
                success "Merci d'avoir utilisé ${COMPANY_NAME} VPS Manager!"
                exit 0
                ;;
            *)
                error "Choix invalide."
                sleep 2
                ;;
        esac
    done
}

# ============================================
# NOUVELLES OPTIONS LIGNE DE COMMANDE
# ============================================

parse_command_line_extended() {
    # [... code existant ...]
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --upgrade-ubuntu)
                require_root
                upgrade_ubuntu_to_2204
                shift
                ;;
            --force-upgrade)
                require_root
                export FORCE_UPGRADE=1
                upgrade_ubuntu_to_2204
                shift
                ;;
            --check-version)
                local version
                version=$(detect_ubuntu_version)
                echo "Version Ubuntu détectée: $version"
                if can_upgrade_to_2204 "$version"; then
                    echo "✅ Upgrade vers 22.04 disponible"
                else
                    echo "ℹ️  Upgrade non nécessaire ou non supporté"
                fi
                exit 0
                ;;
            # [... autres options existantes ...]
        esac
    done
}

# Remplacer le main() pour utiliser la version étendue
main() {
    require_root
    parse_command_line_extended "$@"
}