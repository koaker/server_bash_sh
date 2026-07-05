#!/usr/bin/env bash
# =============================================================================
# wg-proxy.sh — Kernel WireGuard + xray TPROXY proxy manager
# =============================================================================
# Converts 3x-ui WireGuard inbound JSON configs to kernel WireGuard interfaces
# and sets up iptables TPROXY rules to forward decrypted traffic to xray.
#
# Usage:
#   wg-proxy.sh <command> [options]
#
# Commands:
#   add                    Add a new WG tunnel from 3x-ui JSON
#   remove <port>          Remove a WG tunnel
#   list                   List all configured tunnels
#   start   [port]         Start interface(s)
#   stop    [port]         Stop interface(s)
#   restart [port]         Restart interface(s)
#   status  [port]         Show detailed status
#   export  <sub> <port>   Export configurations
#
# Export sub-commands:
#   export wg     <port>          Export wg-quick server conf
#   export xray   <port>          Export dokodemo-door JSON for this port
#   export xray-all               Export ALL dokodemo-door JSONs as array
#   export client <port> [email]  Export client WG config file
#   export mihomo <port> [email]  Export mihomo WG outbound YAML
#   export link   <port> [email]  Export wireguard:// URI link
#
# Requirements: jq, wireguard-tools, iptables
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants & paths
# ---------------------------------------------------------------------------
readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="/etc/wg-proxy"
readonly CONF_DIR="${BASE_DIR}/configs"
readonly XRAY_DIR="${BASE_DIR}/xray-inbounds"
readonly PORTS_FILE="${BASE_DIR}/ports.json"
readonly WG_DIR="/etc/wireguard"
readonly SCHEMA_VERSION=2

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}=== $* ===${RESET}"; }

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
check_deps() {
    local missing=()
    for cmd in jq wg wg-quick iptables ip; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required tools: ${missing[*]}\nInstall with: apt install wireguard-tools jq iptables"
    fi
}

check_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root."
}

# ---------------------------------------------------------------------------
# Directory / file initialisation
# ---------------------------------------------------------------------------
init_dirs() {
    mkdir -p "$CONF_DIR" "$XRAY_DIR" "$WG_DIR"
    if [[ ! -f "$PORTS_FILE" ]]; then
        echo '{"version":2,"ports":[]}' > "$PORTS_FILE"
    fi
    local current_ver
    current_ver="$(get_current_version)"
    if [[ "$current_ver" -lt "$SCHEMA_VERSION" ]]; then
        warn "Configuration is at version ${current_ver}, current is ${SCHEMA_VERSION}. Run '${SCRIPT_NAME} migrate' to upgrade."
    fi
}

# ---------------------------------------------------------------------------
# Schema version helpers
# ---------------------------------------------------------------------------
get_current_version() {
    if [[ ! -f "$PORTS_FILE" ]]; then
        echo "0"
        return
    fi
    local ver
    ver="$(jq -r '.version // 0' "$PORTS_FILE")"
    echo "$ver"
}

set_schema_version() {
    local ver="$1"
    local tmp
    tmp="$(mktemp)"
    jq --argjson v "$ver" '.version = $v' "$PORTS_FILE" > "$tmp"
    mv "$tmp" "$PORTS_FILE"
}

# ---------------------------------------------------------------------------
# ports.json helpers
# ---------------------------------------------------------------------------
ports_get_all() {
    jq -r '.ports' "$PORTS_FILE"
}

port_exists() {
    local port="$1"
    jq -e --argjson p "$port" '.ports[] | select(.port == $p)' "$PORTS_FILE" &>/dev/null
}

port_get() {
    local port="$1"
    jq -r --argjson p "$port" '.ports[] | select(.port == $p)' "$PORTS_FILE"
}

port_add() {
    local entry="$1"
    local tmp
    tmp="$(mktemp)"
    jq --argjson e "$entry" '.ports += [$e]' "$PORTS_FILE" > "$tmp"
    mv "$tmp" "$PORTS_FILE"
}

port_remove() {
    local port="$1"
    local tmp
    tmp="$(mktemp)"
    jq --argjson p "$port" '.ports |= map(select(.port != $p))' "$PORTS_FILE" > "$tmp"
    mv "$tmp" "$PORTS_FILE"
}

# Return next available sequential index (0-based) for fwmark/table assignment
next_index() {
    jq '.ports | length' "$PORTS_FILE"
}

# ---------------------------------------------------------------------------
# WireGuard conf generator
# ---------------------------------------------------------------------------
generate_wg_conf() {
    local iface="$1"
    local private_key="$2"
    local listen_port="$3"
    local address="$4"
    local mtu="$5"
    local xray_port="$6"
    local fwmark="$7"
    local table="$8"
    local peers_json="$9"   # JSON array of {public_key, allowed_ips[]}

    local conf_file="${CONF_DIR}/${iface}.conf"
    local proxy_conf_file="${CONF_DIR}/${iface}-proxy.conf"

    # Extract server IP from address (e.g. "10.0.2.1/24" → "10.0.2.1")
    local server_address_ip="${address%%/*}"

    # Build peer blocks
    local peer_blocks=""
    local num_peers
    num_peers="$(echo "$peers_json" | jq 'length')"
    for (( i=0; i<num_peers; i++ )); do
        local pub_key allowed_ips_str
        pub_key="$(echo "$peers_json" | jq -r ".[$i].public_key")"
        allowed_ips_str="$(echo "$peers_json" | jq -r ".[$i].allowed_ips | join(\", \")")"
        peer_blocks+="
[Peer]
PublicKey = ${pub_key}
AllowedIPs = ${allowed_ips_str}
"
    done

    # Generate pure WG conf (no PostUp/PostDown)
    cat > "$conf_file" <<EOF
[Interface]
PrivateKey = ${private_key}
ListenPort = ${listen_port}
Address = ${address}
MTU = ${mtu}
${peer_blocks}
EOF

    chmod 600 "$conf_file"
    success "Generated ${conf_file}"

    # Generate proxy conf (with TPROXY PostUp/PostDown)
    cat > "$proxy_conf_file" <<EOF
[Interface]
PrivateKey = ${private_key}
ListenPort = ${listen_port}
Address = ${address}
MTU = ${mtu}
PostUp = ip rule add fwmark ${fwmark} table ${table}; ip route add local default dev lo table ${table}; iptables -t mangle -A PREROUTING -i ${iface} -d ${server_address_ip}/32 -j RETURN; iptables -t mangle -A PREROUTING -i ${iface} -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port ${xray_port} --tproxy-mark ${fwmark}; iptables -t mangle -A PREROUTING -i ${iface} -p udp -j TPROXY --on-ip 127.0.0.1 --on-port ${xray_port} --tproxy-mark ${fwmark}; iptables -I INPUT 1 -i ${iface} -m mark --mark ${fwmark} -j ACCEPT
PostDown = iptables -D INPUT -i ${iface} -m mark --mark ${fwmark} -j ACCEPT 2>/dev/null || true; ip rule del fwmark ${fwmark} table ${table}; ip route del local default dev lo table ${table}; iptables -t mangle -D PREROUTING -i ${iface} -d ${server_address_ip}/32 -j RETURN 2>/dev/null || true; iptables -t mangle -D PREROUTING -i ${iface} -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port ${xray_port} --tproxy-mark ${fwmark}; iptables -t mangle -D PREROUTING -i ${iface} -p udp -j TPROXY --on-ip 127.0.0.1 --on-port ${xray_port} --tproxy-mark ${fwmark}
${peer_blocks}
EOF

    chmod 600 "$proxy_conf_file"
    success "Generated ${proxy_conf_file}"
}

# ---------------------------------------------------------------------------
# xray dokodemo-door JSON generator
# ---------------------------------------------------------------------------
generate_xray_inbound() {
    local port="$1"
    local xray_port="$2"
    local out_file="${XRAY_DIR}/wg-${port}.json"

    jq -n \
        --arg tag "wg-${port}" \
        --argjson xp "$xray_port" \
        '{
            tag: $tag,
            listen: "127.0.0.1",
            port: $xp,
            protocol: "dokodemo-door",
            settings: {
                network: "tcp,udp",
                followRedirect: true
            },
            sniffing: {
                enabled: true,
                destOverride: ["http","tls"]
            },
            streamSettings: {
                sockopt: {
                    tproxy: "tproxy"
                }
            }
        }' > "$out_file"

    success "Generated ${out_file}"
}

# ---------------------------------------------------------------------------
# Symlink conf to /etc/wireguard/
# ---------------------------------------------------------------------------
symlink_conf() {
    local iface="$1"
    local mode="${2:-proxy}"  # "proxy" or "pure"
    local suffix=""
    [[ "$mode" == "proxy" ]] && suffix="-proxy"
    local src="${CONF_DIR}/${iface}${suffix}.conf"
    local dst="${WG_DIR}/${iface}.conf"
    [[ -f "$src" ]] || { error "Config not found: ${src}"; return 1; }
    if [[ -L "$dst" ]]; then
        rm -f "$dst"
    fi
    ln -s "$src" "$dst"
    success "Symlinked ${src} → ${dst}"
}

remove_symlink() {
    local iface="$1"
    local dst="${WG_DIR}/${iface}.conf"
    [[ -L "$dst" ]] && rm -f "$dst" && info "Removed symlink ${dst}"
}

# ---------------------------------------------------------------------------
# Derive server address from first client's allowedIPs
# e.g. client has 10.0.0.2/32 → server gets 10.0.0.1/24
# ---------------------------------------------------------------------------
derive_server_address() {
    local first_allowed_ip="$1"   # e.g. "10.0.0.2/32"
    # Strip the prefix, replace last octet with 1, use /24
    local base
    base="$(echo "$first_allowed_ip" | cut -d'/' -f1 | sed 's/\.[0-9]*$/.1/')"
    echo "${base}/24"
}

# ---------------------------------------------------------------------------
# URL-encode a string (for wireguard:// links)
# ---------------------------------------------------------------------------
urlencode() {
    local string="$1"
    local encoded=""
    local i c
    for (( i=0; i<${#string}; i++ )); do
        c="${string:$i:1}"
        case "$c" in
            [a-zA-Z0-9._~-]) encoded+="$c" ;;
            '+') encoded+="%2B" ;;
            '/') encoded+="%2F" ;;
            '=') encoded+="%3D" ;;
            ' ') encoded+="%20" ;;
            *) encoded+="$(printf '%%%02X' "'$c")" ;;
        esac
    done
    echo "$encoded"
}

# ---------------------------------------------------------------------------
# Interface status helpers
# ---------------------------------------------------------------------------
iface_is_up() {
    local iface="$1"
    ip link show "$iface" &>/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# CMD: add
# ---------------------------------------------------------------------------
cmd_add() {
    local json_file=""
    local json_input=""

    # Parse flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --file|-f)
                json_file="$2"
                shift 2
                ;;
            --help|-h)
                cat <<EOF
Usage: ${SCRIPT_NAME} add [--file <json_file>]

Add a new WireGuard tunnel from a 3x-ui inbound JSON config.

Options:
  --file, -f <path>   Read JSON from file instead of interactive paste
  --help, -h          Show this help

If --file is not given, you will be prompted to paste the JSON interactively.
EOF
                return 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    header "Add WireGuard Tunnel"

    # Read JSON
    if [[ -n "$json_file" ]]; then
        [[ -f "$json_file" ]] || die "File not found: $json_file"
        json_input="$(cat "$json_file")"
    else
        echo "Paste the 3x-ui WireGuard inbound JSON (press Ctrl+D when done):"
        json_input="$(cat)"
    fi

    # Validate JSON
    echo "$json_input" | jq . &>/dev/null || die "Invalid JSON input."

    # Extract fields
    local wg_port server_private_key mtu
    wg_port="$(echo "$json_input" | jq -r '.port // empty')"
    server_private_key="$(echo "$json_input" | jq -r '.settings.secretKey // empty')"
    mtu="$(echo "$json_input" | jq -r '.settings.mtu // 1280')"

    [[ -n "$wg_port" ]]           || die "JSON missing field: .port"
    [[ -n "$server_private_key" ]] || die "JSON missing field: .settings.secretKey"

    # Validate port is numeric
    [[ "$wg_port" =~ ^[0-9]+$ ]] || die "Port must be numeric, got: $wg_port"

    # Check for duplicate
    if port_exists "$wg_port"; then
        die "Port ${wg_port} is already configured. Remove it first with: ${SCRIPT_NAME} remove ${wg_port}"
    fi

    # Extract clients
    local clients_json
    clients_json="$(echo "$json_input" | jq -r '.settings.clients // []')"
    local num_clients
    num_clients="$(echo "$clients_json" | jq 'length')"
    [[ "$num_clients" -gt 0 ]] || die "No clients found in JSON (.settings.clients is empty)."

    # Derive server public key
    local server_public_key
    server_public_key="$(echo "$server_private_key" | wg pubkey)" || die "Failed to derive public key from secretKey."

    # Prompt for xray TPROXY port
    local xray_port
    echo ""
    read -rp "Enter the xray TPROXY target port (dokodemo-door listen port) for WG port ${wg_port}: " xray_port
    [[ "$xray_port" =~ ^[0-9]+$ ]] || die "xray port must be numeric."

    # Prompt for server endpoint
    local endpoint
    read -rp "Enter server public endpoint (IP or domain, without port) for client config export: " endpoint
    [[ -n "$endpoint" ]] || die "Endpoint cannot be empty."

    # Assign fwmark and routing table
    local idx
    idx="$(next_index)"
    local fwmark
    fwmark="$(printf '0x%x' $(( 0x100 + idx )))"
    local table=$(( 200 + idx ))

    local iface="wg-${wg_port}"

    # Build peers array for conf and metadata
    local peers_for_conf="[]"
    local clients_meta="[]"

    for (( i=0; i<num_clients; i++ )); do
        local email pub_key priv_key allowed_ips_raw
        email="$(echo "$clients_json" | jq -r ".[$i].email // \"client${i}\"")"
        pub_key="$(echo "$clients_json" | jq -r ".[$i].publicKey // empty")"
        priv_key="$(echo "$clients_json" | jq -r ".[$i].privateKey // \"\"")"
        allowed_ips_raw="$(echo "$clients_json" | jq -r ".[$i].allowedIPs // [] | join(\",\")")"

        [[ -n "$pub_key" ]] || { warn "Client $i missing publicKey, skipping."; continue; }

        # Parse allowedIPs into array
        local allowed_ips_arr
        IFS=',' read -ra allowed_ips_arr <<< "$allowed_ips_raw"

        # Build JSON array of allowed IPs
        local allowed_ips_json="[]"
        for ip in "${allowed_ips_arr[@]}"; do
            ip="$(echo "$ip" | tr -d ' ')"
            [[ -n "$ip" ]] && allowed_ips_json="$(echo "$allowed_ips_json" | jq --arg ip "$ip" '. += [$ip]')"
        done

        # Add to peers_for_conf
        peers_for_conf="$(echo "$peers_for_conf" | jq \
            --arg pk "$pub_key" \
            --argjson ips "$allowed_ips_json" \
            '. += [{"public_key": $pk, "allowed_ips": $ips}]')"

        # Add to clients_meta
        clients_meta="$(echo "$clients_meta" | jq \
            --arg email "$email" \
            --arg pk "$pub_key" \
            --arg sk "$priv_key" \
            --argjson ips "$allowed_ips_json" \
            '. += [{"email": $email, "public_key": $pk, "private_key": $sk, "allowed_ips": $ips}]')"
    done

    # Derive server address from first client's first allowedIP
    local first_client_ip
    first_client_ip="$(echo "$clients_json" | jq -r '.[0].allowedIPs // [] | .[0] // "10.0.0.2/32"')"
    # Handle comma-separated string in allowedIPs
    first_client_ip="$(echo "$first_client_ip" | cut -d',' -f1 | tr -d ' ')"
    local server_address
    server_address="$(derive_server_address "$first_client_ip")"

    info "Server interface address: ${server_address}"
    info "fwmark: ${fwmark}, routing table: ${table}"

    # Generate WG conf
    generate_wg_conf \
        "$iface" \
        "$server_private_key" \
        "$wg_port" \
        "$server_address" \
        "$mtu" \
        "$xray_port" \
        "$fwmark" \
        "$table" \
        "$peers_for_conf"

    # Generate xray inbound JSON
    generate_xray_inbound "$wg_port" "$xray_port"

    # Symlink to /etc/wireguard/ (default: proxy mode with TPROXY enabled)
    symlink_conf "$iface" "proxy"

    # Save metadata to ports.json
    local entry
    entry="$(jq -n \
        --argjson port "$wg_port" \
        --argjson xp "$xray_port" \
        --arg endpoint "$endpoint" \
        --arg fwmark "$fwmark" \
        --argjson table "$table" \
        --arg iface "$iface" \
        --argjson mtu "$mtu" \
        --arg spk "$server_private_key" \
        --arg spub "$server_public_key" \
        --argjson clients "$clients_meta" \
        --argjson tproxy true \
        '{
            port: $port,
            xray_port: $xp,
            endpoint: $endpoint,
            fwmark: $fwmark,
            table: $table,
            interface: $iface,
            mtu: $mtu,
            server_private_key: $spk,
            server_public_key: $spub,
            clients: $clients,
            tproxy_enabled: $tproxy
        }')"
    port_add "$entry"
    success "Saved metadata to ${PORTS_FILE}"

    # Bring up the interface
    echo ""
    info "Bringing up interface ${iface}..."
    wg-quick up "$iface" && success "Interface ${iface} is UP" || warn "wg-quick up failed — check logs."

    echo ""
    success "Tunnel wg-${wg_port} added successfully!"
    echo -e "  ${BOLD}WG listen port:${RESET}   ${wg_port}"
    echo -e "  ${BOLD}xray TPROXY port:${RESET} ${xray_port}"
    echo -e "  ${BOLD}Interface:${RESET}        ${iface}"
    echo -e "  ${BOLD}fwmark:${RESET}           ${fwmark}"
    echo -e "  ${BOLD}Routing table:${RESET}    ${table}"
    echo ""
    echo -e "Next step: copy the xray inbound JSON into 3x-ui:"
    echo -e "  ${SCRIPT_NAME} export xray ${wg_port}"
}

# ---------------------------------------------------------------------------
# CMD: remove
# ---------------------------------------------------------------------------
cmd_remove() {
    local port="$1"
    [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} remove <port>"
    [[ "$port" =~ ^[0-9]+$ ]] || die "Port must be numeric."

    port_exists "$port" || die "Port ${port} is not configured."

    local iface="wg-${port}"

    header "Remove WireGuard Tunnel: ${iface}"

    # Bring down if up
    if iface_is_up "$iface"; then
        info "Bringing down ${iface}..."
        wg-quick down "$iface" && success "Interface ${iface} stopped." || warn "wg-quick down failed (may already be down)."
    else
        info "Interface ${iface} is already down."
    fi

    # Remove files
    local conf_file="${CONF_DIR}/${iface}.conf"
    local xray_file="${XRAY_DIR}/${iface}.json"

    [[ -f "$conf_file" ]] && rm -f "$conf_file" && info "Removed ${conf_file}"
    local proxy_conf_file="${CONF_DIR}/${iface}-proxy.conf"
    [[ -f "$proxy_conf_file" ]] && rm -f "$proxy_conf_file" && info "Removed ${proxy_conf_file}"
    [[ -f "$xray_file" ]] && rm -f "$xray_file" && info "Removed ${xray_file}"
    remove_symlink "$iface"

    # Remove from ports.json
    port_remove "$port"
    success "Removed port ${port} from registry."

    success "Tunnel ${iface} removed."
}

# ---------------------------------------------------------------------------
# CMD: list
# ---------------------------------------------------------------------------
cmd_list() {
    header "Configured WireGuard Tunnels"

    local count
    count="$(jq '.ports | length' "$PORTS_FILE")"

    if [[ "$count" -eq 0 ]]; then
        echo "No tunnels configured. Use '${SCRIPT_NAME} add' to add one."
        return 0
    fi

    printf "${BOLD}%-12s %-14s %-12s %-8s %-20s %-6s${RESET}\n" \
        "INTERFACE" "WG PORT" "XRAY PORT" "STATUS" "ENDPOINT" "PEERS"
    printf '%s\n' "$(printf '%.0s-' {1..75})"

    jq -c '.ports[]' "$PORTS_FILE" | while IFS= read -r entry; do
        local port xray_port endpoint iface num_clients
        port="$(echo "$entry" | jq -r '.port')"
        xray_port="$(echo "$entry" | jq -r '.xray_port')"
        endpoint="$(echo "$entry" | jq -r '.endpoint')"
        iface="$(echo "$entry" | jq -r '.interface')"
        num_clients="$(echo "$entry" | jq '.clients | length')"

        local status_str
        if iface_is_up "$iface"; then
            status_str="${GREEN}UP${RESET}"
        else
            status_str="${RED}DOWN${RESET}"
        fi

        printf "%-12s %-14s %-12s %-8b %-20s %-6s\n" \
            "$iface" "$port" "$xray_port" "$status_str" "$endpoint" "$num_clients"
    done
}

# ---------------------------------------------------------------------------
# CMD: start / stop / restart
# ---------------------------------------------------------------------------
cmd_start() {
    local port="${1:-}"
    if [[ -n "$port" ]]; then
        port_exists "$port" || die "Port ${port} is not configured."
        local iface="wg-${port}"
        info "Starting ${iface}..."
        wg-quick up "$iface" && success "${iface} started." || die "Failed to start ${iface}."
    else
        header "Starting all WireGuard tunnels"
        jq -r '.ports[].interface' "$PORTS_FILE" | while IFS= read -r iface; do
            if iface_is_up "$iface"; then
                warn "${iface} is already up, skipping."
            else
                info "Starting ${iface}..."
                wg-quick up "$iface" && success "${iface} started." || warn "Failed to start ${iface}."
            fi
        done
    fi
}

cmd_stop() {
    local port="${1:-}"
    if [[ -n "$port" ]]; then
        port_exists "$port" || die "Port ${port} is not configured."
        local iface="wg-${port}"
        info "Stopping ${iface}..."
        wg-quick down "$iface" && success "${iface} stopped." || die "Failed to stop ${iface}."
    else
        header "Stopping all WireGuard tunnels"
        jq -r '.ports[].interface' "$PORTS_FILE" | while IFS= read -r iface; do
            if iface_is_up "$iface"; then
                info "Stopping ${iface}..."
                wg-quick down "$iface" && success "${iface} stopped." || warn "Failed to stop ${iface}."
            else
                warn "${iface} is already down, skipping."
            fi
        done
    fi
}

cmd_restart() {
    local port="${1:-}"
    if [[ -n "$port" ]]; then
        cmd_stop "$port"
        cmd_start "$port"
    else
        cmd_stop
        cmd_start
    fi
}

# ---------------------------------------------------------------------------
# CMD: status
# ---------------------------------------------------------------------------
cmd_status() {
    local port="${1:-}"

    if [[ -n "$port" ]]; then
        port_exists "$port" || die "Port ${port} is not configured."
        _show_status "$port"
    else
        header "WireGuard Proxy Status"
        local count
        count="$(jq '.ports | length' "$PORTS_FILE")"
        if [[ "$count" -eq 0 ]]; then
            echo "No tunnels configured."
            return 0
        fi
        jq -r '.ports[].port' "$PORTS_FILE" | while IFS= read -r p; do
            _show_status "$p"
        done
    fi
}

_show_status() {
    local port="$1"
    local entry iface xray_port fwmark table endpoint
    entry="$(port_get "$port")"
    iface="$(echo "$entry" | jq -r '.interface')"
    xray_port="$(echo "$entry" | jq -r '.xray_port')"
    fwmark="$(echo "$entry" | jq -r '.fwmark')"
    table="$(echo "$entry" | jq -r '.table')"
    endpoint="$(echo "$entry" | jq -r '.endpoint')"

    echo ""
    echo -e "${BOLD}${CYAN}── ${iface} ──────────────────────────────────────${RESET}"
    echo -e "  WG Port:      ${port}"
    echo -e "  xray Port:    ${xray_port}"
    echo -e "  Endpoint:     ${endpoint}"
    echo -e "  fwmark:       ${fwmark}"
    echo -e "  Table:        ${table}"
    local tproxy_mode
    tproxy_mode="$(_get_tproxy_mode "$port")"
    if [[ "$tproxy_mode" == "proxy" ]]; then
        echo -e "  TPROXY:       ${GREEN}ENABLED${RESET}"
    else
        echo -e "  TPROXY:       ${YELLOW}DISABLED${RESET}"
    fi

    if iface_is_up "$iface"; then
        echo -e "  Status:       ${GREEN}UP${RESET}"
        echo ""
        echo -e "  ${BOLD}WireGuard peers:${RESET}"
        wg show "$iface" 2>/dev/null | sed 's/^/    /' || true
    else
        echo -e "  Status:       ${RED}DOWN${RESET}"
    fi

    echo ""
    echo -e "  ${BOLD}iptables TPROXY rules:${RESET}"
    iptables -t mangle -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep -E "TPROXY.*${iface}|${iface}.*TPROXY" \
        | sed 's/^/    /' \
        || echo "    (none found)"

    echo ""
    echo -e "  ${BOLD}ip rules (fwmark ${fwmark}):${RESET}"
    ip rule list 2>/dev/null | grep "fwmark ${fwmark}" | sed 's/^/    /' || echo "    (none found)"
}

# ---------------------------------------------------------------------------
# CMD: export
# ---------------------------------------------------------------------------
cmd_export() {
    local sub="${1:-}"
    shift || true

    case "$sub" in
        wg)      export_wg "$@" ;;
        xray)    export_xray "$@" ;;
        xray-all) export_xray_all ;;
        client)  export_client "$@" ;;
        mihomo)  export_mihomo "$@" ;;
        link)    export_link "$@" ;;
        --help|-h|"")
            cat <<EOF
Usage: ${SCRIPT_NAME} export <sub-command> [args]

Sub-commands:
  wg     <port>          Print wg-quick server conf
  xray   <port>          Print dokodemo-door JSON for this port
  xray-all               Print ALL dokodemo-door JSONs as a JSON array
  client <port> [email]  Print client wg-quick config
  mihomo <port> [email]  Print mihomo WG outbound YAML
  link   <port> [email]  Print wireguard:// URI link

If [email] is omitted, configs for ALL clients are printed.
EOF
            ;;
        *)
            die "Unknown export sub-command: ${sub}. Run '${SCRIPT_NAME} export --help'."
            ;;
    esac
}

export_wg() {
    local port="${1:-}"
    [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} export wg <port>"
    port_exists "$port" || die "Port ${port} is not configured."
    local iface="wg-${port}"
    local mode
    mode="$(_get_tproxy_mode "$port")"
    local conf_file
    if [[ "$mode" == "proxy" ]]; then
        conf_file="${CONF_DIR}/${iface}-proxy.conf"
    else
        conf_file="${CONF_DIR}/${iface}.conf"
    fi
    [[ -f "$conf_file" ]] || die "Config file not found: ${conf_file}"
    header "WG Server Config: ${iface} (mode: ${mode})"
    cat "$conf_file"
}

export_xray() {
    local port="${1:-}"
    [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} export xray <port>"
    port_exists "$port" || die "Port ${port} is not configured."
    local xray_file="${XRAY_DIR}/wg-${port}.json"
    [[ -f "$xray_file" ]] || die "xray inbound file not found: ${xray_file}"
    header "xray Inbound JSON: wg-${port}"
    cat "$xray_file"
}

export_xray_all() {
    header "All xray Inbound JSONs"
    local files=("${XRAY_DIR}"/wg-*.json)
    if [[ ${#files[@]} -eq 0 ]] || [[ ! -f "${files[0]}" ]]; then
        echo "[]"
        return 0
    fi
    # Combine all JSON files into an array
    local combined="["
    local first=true
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        if $first; then
            combined+="$(cat "$f")"
            first=false
        else
            combined+=",$(cat "$f")"
        fi
    done
    combined+="]"
    echo "$combined" | jq .
}

export_client() {
    local port="${1:-}"
    local target_email="${2:-}"
    [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} export client <port> [email]"
    port_exists "$port" || die "Port ${port} is not configured."

    local entry
    entry="$(port_get "$port")"
    local server_pub_key mtu endpoint
    server_pub_key="$(echo "$entry" | jq -r '.server_public_key')"
    mtu="$(echo "$entry" | jq -r '.mtu')"
    endpoint="$(echo "$entry" | jq -r '.endpoint')"

    local num_clients
    num_clients="$(echo "$entry" | jq '.clients | length')"

    for (( i=0; i<num_clients; i++ )); do
        local email priv_key allowed_ips_str
        email="$(echo "$entry" | jq -r ".clients[$i].email")"
        priv_key="$(echo "$entry" | jq -r ".clients[$i].private_key")"
        allowed_ips_str="$(echo "$entry" | jq -r ".clients[$i].allowed_ips | join(\", \")")"

        # Filter by email if specified
        if [[ -n "$target_email" && "$email" != "$target_email" ]]; then
            continue
        fi

        if [[ -z "$priv_key" ]]; then
            warn "Client '${email}' has no private key stored — cannot generate client config."
            continue
        fi

        header "Client Config: ${email} (port ${port})"
        cat <<EOF
[Interface]
PrivateKey = ${priv_key}
Address = ${allowed_ips_str}
MTU = ${mtu}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${server_pub_key}
Endpoint = ${endpoint}:${port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    done
}

export_mihomo() {
    local port="${1:-}"
    local target_email="${2:-}"
    [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} export mihomo <port> [email]"
    port_exists "$port" || die "Port ${port} is not configured."

    local entry
    entry="$(port_get "$port")"
    local server_pub_key mtu endpoint
    server_pub_key="$(echo "$entry" | jq -r '.server_public_key')"
    mtu="$(echo "$entry" | jq -r '.mtu')"
    endpoint="$(echo "$entry" | jq -r '.endpoint')"

    local num_clients
    num_clients="$(echo "$entry" | jq '.clients | length')"

    header "Mihomo WG Outbound YAML (port ${port})"

    for (( i=0; i<num_clients; i++ )); do
        local email priv_key client_ip
        email="$(echo "$entry" | jq -r ".clients[$i].email")"
        priv_key="$(echo "$entry" | jq -r ".clients[$i].private_key")"
        client_ip="$(echo "$entry" | jq -r ".clients[$i].allowed_ips[0]" | cut -d'/' -f1)"

        if [[ -n "$target_email" && "$email" != "$target_email" ]]; then
            continue
        fi

        if [[ -z "$priv_key" ]]; then
            warn "Client '${email}' has no private key — skipping."
            continue
        fi

        cat <<EOF
- name: "wg-${port}-${email}"
  type: wireguard
  server: ${endpoint}
  port: ${port}
  ip: "${client_ip}"
  private-key: "${priv_key}"
  public-key: "${server_pub_key}"
  mtu: ${mtu}
  udp: true

EOF
    done
}

export_link() {
    local port="${1:-}"
    local target_email="${2:-}"
    [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} export link <port> [email]"
    port_exists "$port" || die "Port ${port} is not configured."

    local entry
    entry="$(port_get "$port")"
    local server_pub_key mtu endpoint
    server_pub_key="$(echo "$entry" | jq -r '.server_public_key')"
    mtu="$(echo "$entry" | jq -r '.mtu')"
    endpoint="$(echo "$entry" | jq -r '.endpoint')"

    local num_clients
    num_clients="$(echo "$entry" | jq '.clients | length')"

    header "WireGuard Links (port ${port})"

    for (( i=0; i<num_clients; i++ )); do
        local email priv_key allowed_ips_str
        email="$(echo "$entry" | jq -r ".clients[$i].email")"
        priv_key="$(echo "$entry" | jq -r ".clients[$i].private_key")"
        allowed_ips_str="$(echo "$entry" | jq -r ".clients[$i].allowed_ips | join(\",\")")"

        if [[ -n "$target_email" && "$email" != "$target_email" ]]; then
            continue
        fi

        if [[ -z "$priv_key" ]]; then
            warn "Client '${email}' has no private key — cannot generate link."
            continue
        fi

        local enc_priv enc_addr enc_pub
        enc_priv="$(urlencode "$priv_key")"
        enc_addr="$(urlencode "$allowed_ips_str")"
        enc_pub="$(urlencode "$server_pub_key")"

        local link="wireguard://${enc_priv}@${endpoint}:${port}?address=${enc_addr}&mtu=${mtu}&publickey=${enc_pub}#${email}"
        echo -e "${BOLD}${email}:${RESET}"
        echo "$link"
        echo ""
    done
}

# ---------------------------------------------------------------------------
# CMD: tproxy
# ---------------------------------------------------------------------------
cmd_tproxy() {
    local action="${1:-}"
    local port="${2:-}"

    case "$action" in
        enable)
            [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} tproxy enable <port>"
            [[ "$port" =~ ^[0-9]+$ ]] || die "Port must be numeric."
            port_exists "$port" || die "Port ${port} is not configured."
            local iface="wg-${port}"

            # Check current state
            local current_mode
            current_mode="$(_get_tproxy_mode "$port")"
            if [[ "$current_mode" == "proxy" ]]; then
                warn "TPROXY is already enabled for ${iface}."
                return 0
            fi

            info "Enabling TPROXY for ${iface}..."
            if iface_is_up "$iface"; then
                wg-quick down "$iface" || warn "wg-quick down failed."
            fi
            symlink_conf "$iface" "proxy"
            wg-quick up "$iface" && success "TPROXY enabled. ${iface} is UP with proxy rules." || die "Failed to start ${iface}."
            _set_tproxy_state "$port" true
            ;;
        disable)
            [[ -n "$port" ]] || die "Usage: ${SCRIPT_NAME} tproxy disable <port>"
            [[ "$port" =~ ^[0-9]+$ ]] || die "Port must be numeric."
            port_exists "$port" || die "Port ${port} is not configured."
            local iface="wg-${port}"

            local current_mode
            current_mode="$(_get_tproxy_mode "$port")"
            if [[ "$current_mode" == "pure" ]]; then
                warn "TPROXY is already disabled for ${iface}."
                return 0
            fi

            info "Disabling TPROXY for ${iface}..."
            if iface_is_up "$iface"; then
                wg-quick down "$iface" || warn "wg-quick down failed."
            fi
            symlink_conf "$iface" "pure"
            wg-quick up "$iface" && success "TPROXY disabled. ${iface} is UP without proxy rules." || die "Failed to start ${iface}."
            _set_tproxy_state "$port" false
            ;;
        status)
            if [[ -n "$port" ]]; then
                port_exists "$port" || die "Port ${port} is not configured."
                _show_tproxy_status "$port"
            else
                header "TPROXY Status"
                local count
                count="$(jq '.ports | length' "$PORTS_FILE")"
                if [[ "$count" -eq 0 ]]; then
                    echo "No tunnels configured."
                    return 0
                fi
                jq -r '.ports[].port' "$PORTS_FILE" | while IFS= read -r p; do
                    _show_tproxy_status "$p"
                done
            fi
            ;;
        --help|-h|"")
            cat <<EOF
Usage: ${SCRIPT_NAME} tproxy <action> [port]

Actions:
  enable  <port>   Enable TPROXY (restarts WG with proxy config)
  disable <port>   Disable TPROXY (restarts WG with pure config)
  status  [port]   Show TPROXY state (all tunnels if port omitted)
EOF
            ;;
        *)
            die "Unknown tproxy action: ${action}. Use enable/disable/status."
            ;;
    esac
}

_get_tproxy_mode() {
    local port="$1"
    local iface="wg-${port}"
    local dst="${WG_DIR}/${iface}.conf"
    if [[ -L "$dst" ]]; then
        local target
        target="$(readlink "$dst")"
        if [[ "$target" == *"-proxy.conf" ]]; then
            echo "proxy"
        else
            echo "pure"
        fi
    else
        # Fallback: check ports.json
        local enabled
        enabled="$(jq -r --argjson p "$port" '.ports[] | select(.port == $p) | .tproxy_enabled // true' "$PORTS_FILE")"
        if [[ "$enabled" == "true" ]]; then
            echo "proxy"
        else
            echo "pure"
        fi
    fi
}

_set_tproxy_state() {
    local port="$1"
    local enabled="$2"  # true or false
    local tmp
    tmp="$(mktemp)"
    jq --argjson p "$port" --argjson e "$enabled" \
        '(.ports[] | select(.port == $p)).tproxy_enabled = $e' "$PORTS_FILE" > "$tmp"
    mv "$tmp" "$PORTS_FILE"
}

_show_tproxy_status() {
    local port="$1"
    local iface="wg-${port}"
    local mode
    mode="$(_get_tproxy_mode "$port")"

    local status_icon
    if [[ "$mode" == "proxy" ]]; then
        status_icon="${GREEN}ENABLED${RESET}"
    else
        status_icon="${YELLOW}DISABLED${RESET}"
    fi

    local up_icon
    if iface_is_up "$iface"; then
        up_icon="${GREEN}UP${RESET}"
    else
        up_icon="${RED}DOWN${RESET}"
    fi

    printf "  %-14s  WG: %-4b  TPROXY: %-10b\n" "$iface" "$up_icon" "$status_icon"
}

# ---------------------------------------------------------------------------
# CMD: migrate
# ---------------------------------------------------------------------------
migrate_v0_to_v1() {
    local dry_run="$1"
    # Ensure ports.json exists with at least version 1 structure
    if [[ ! -f "$PORTS_FILE" ]]; then
        if [[ "$dry_run" == "true" ]]; then
            info "[DRY RUN] Would create ${PORTS_FILE} with {\"version\":1,\"ports\":[]}"
        else
            echo '{"version":1,"ports":[]}' > "$PORTS_FILE"
            success "Created ${PORTS_FILE} with version 1 structure."
        fi
    else
        info "ports.json already exists — v0→v1 is a no-op for existing data."
    fi
}

migrate_v1_to_v2() {
    local dry_run="$1"

    header "Migration v1 → v2: dual-conf + tproxy_enabled"

    local count
    count="$(jq '.ports | length' "$PORTS_FILE")"

    if [[ "$count" -eq 0 ]]; then
        info "No tunnel entries to migrate."
    fi

    # Collect interfaces that are currently up so we can restart them
    local -a was_up=()

    # --- Step a: stop all running interfaces ---
    if [[ "$dry_run" == "true" ]]; then
        jq -r '.ports[].interface' "$PORTS_FILE" | while IFS= read -r iface; do
            if iface_is_up "$iface"; then
                info "[DRY RUN] Would bring down ${iface}"
            fi
        done
    else
        while IFS= read -r iface; do
            if iface_is_up "$iface"; then
                info "Bringing down ${iface}..."
                wg-quick down "$iface" && was_up+=("$iface") || warn "wg-quick down ${iface} failed — continuing."
            fi
        done < <(jq -r '.ports[].interface' "$PORTS_FILE")
    fi

    # --- Step b: migrate each tunnel's conf files ---
    while IFS= read -r port; do
        local iface="wg-${port}"
        local old_conf="${CONF_DIR}/${iface}.conf"
        local proxy_conf="${CONF_DIR}/${iface}-proxy.conf"
        local pure_conf="${CONF_DIR}/${iface}.conf"
        local dst="${WG_DIR}/${iface}.conf"

        info "Processing ${iface}..."

        # Check if already migrated (proxy conf already exists)
        if [[ -f "$proxy_conf" ]]; then
            info "  ${iface}: proxy conf already exists — skipping file migration."
        elif [[ -f "$old_conf" ]]; then
            if [[ "$dry_run" == "true" ]]; then
                info "[DRY RUN] Would rename ${old_conf} → ${proxy_conf}"
                info "[DRY RUN] Would generate pure conf at ${pure_conf} (strip PostUp/PostDown)"
                info "[DRY RUN] Would patch ${proxy_conf} to add server-IP RETURN rule if missing"
            else
                # Rename old conf to proxy conf
                mv "$old_conf" "$proxy_conf"
                info "  Renamed ${old_conf} → ${proxy_conf}"

                # Patch proxy conf: insert -d <server_ip>/32 -j RETURN before first -p tcp -j TPROXY
                # Only patch if the RETURN rule is not already present
                local server_ip
                server_ip="$(grep '^Address' "$proxy_conf" | awk '{print $3}' | cut -d'/' -f1)"
                if [[ -n "$server_ip" ]]; then
                    local return_rule="-d ${server_ip}/32 -j RETURN"
                    if ! grep -qF -- "$return_rule" "$proxy_conf"; then
                        # Insert the RETURN rule in PostUp before the first -p tcp -j TPROXY
                        sed -i "s|-p tcp -j TPROXY|$return_rule; iptables -t mangle -A PREROUTING -i $iface -p tcp -j TPROXY|" "$proxy_conf"
                        # Insert the RETURN rule cleanup in PostDown before the first -p tcp -j TPROXY
                        sed -i "/^PostDown/s|-p tcp -j TPROXY|$return_rule 2>/dev/null || true; iptables -t mangle -D PREROUTING -i $iface -p tcp -j TPROXY|" "$proxy_conf"
                        info "  Patched ${proxy_conf} with server-IP RETURN rule (${server_ip}/32)"
                    else
                        info "  ${proxy_conf} already has RETURN rule — skipping patch."
                    fi
                else
                    warn "  Could not extract server IP from ${proxy_conf} — skipping RETURN rule patch."
                fi

                # Generate pure conf by stripping PostUp/PostDown
                grep -v '^PostUp\|^PostDown' "$proxy_conf" > "$pure_conf"
                chmod 600 "$pure_conf"
                info "  Generated pure conf at ${pure_conf}"
            fi
        else
            warn "  ${iface}: no conf file found at ${old_conf} — skipping."
        fi

        # Update symlink to point to proxy conf
        if [[ "$dry_run" == "true" ]]; then
            local current_target=""
            [[ -L "$dst" ]] && current_target="$(readlink "$dst")"
            if [[ "$current_target" == *"-proxy.conf" ]]; then
                info "[DRY RUN] ${iface}: symlink already points to proxy conf — no change needed."
            else
                info "[DRY RUN] Would update symlink ${dst} → ${proxy_conf}"
            fi
        else
            if [[ -L "$dst" ]]; then
                local current_target
                current_target="$(readlink "$dst")"
                if [[ "$current_target" == *"-proxy.conf" ]]; then
                    info "  ${iface}: symlink already points to proxy conf — skipping."
                else
                    rm -f "$dst"
                    ln -s "$proxy_conf" "$dst"
                    info "  Updated symlink ${dst} → ${proxy_conf}"
                fi
            elif [[ -f "$proxy_conf" ]]; then
                ln -s "$proxy_conf" "$dst"
                info "  Created symlink ${dst} → ${proxy_conf}"
            fi
        fi

    done < <(jq -r '.ports[].port' "$PORTS_FILE")

    # --- Step c: add tproxy_enabled to each port entry if missing ---
    if [[ "$dry_run" == "true" ]]; then
        local needs_tproxy
        needs_tproxy="$(jq '[.ports[] | select(.tproxy_enabled == null)] | length' "$PORTS_FILE")"
        if [[ "$needs_tproxy" -gt 0 ]]; then
            info "[DRY RUN] Would set tproxy_enabled=true on ${needs_tproxy} port entry(ies) missing the field."
        else
            info "[DRY RUN] All port entries already have tproxy_enabled — no change needed."
        fi
    else
        local tmp
        tmp="$(mktemp)"
        jq '(.ports[] | select(.tproxy_enabled == null)).tproxy_enabled = true' "$PORTS_FILE" > "$tmp"
        mv "$tmp" "$PORTS_FILE"
        success "Set tproxy_enabled=true on all port entries that were missing it."
    fi

    # --- Step d: set version to 2 ---
    if [[ "$dry_run" == "true" ]]; then
        info "[DRY RUN] Would set ports.json version to 2."
    else
        set_schema_version 2
        success "Set ports.json schema version to 2."
    fi

    # --- Step e: restart interfaces that were up ---
    if [[ "$dry_run" == "true" ]]; then
        jq -r '.ports[].interface' "$PORTS_FILE" | while IFS= read -r iface; do
            if iface_is_up "$iface"; then
                : # already up, nothing to restart in dry-run
            else
                info "[DRY RUN] Would bring up ${iface} after migration."
            fi
        done
    else
        for iface in "${was_up[@]:-}"; do
            [[ -n "$iface" ]] || continue
            info "Restarting ${iface}..."
            wg-quick up "$iface" && success "${iface} restarted." || warn "Failed to restart ${iface} — start it manually."
        done
    fi
}

cmd_migrate() {
    local dry_run="false"

    # Parse flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                dry_run="true"
                shift
                ;;
            --help|-h)
                cat <<EOF
Usage: ${SCRIPT_NAME} migrate [--dry-run]

Migrate configuration to the current schema version (v${SCHEMA_VERSION}).

Options:
  --dry-run   Show what would be done without making any changes
  --help, -h  Show this help
EOF
                return 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    header "Configuration Migration"

    local current_ver
    current_ver="$(get_current_version)"

    info "Current schema version : ${current_ver}"
    info "Target schema version  : ${SCHEMA_VERSION}"

    if [[ "$current_ver" -ge "$SCHEMA_VERSION" ]]; then
        success "Already up to date (version ${current_ver})."
        return 0
    fi

    if [[ "$dry_run" == "true" ]]; then
        warn "DRY RUN mode — no changes will be made."
    fi

    # Run migrations sequentially
    if [[ "$current_ver" -lt 1 ]]; then
        info "Running migration: v0 → v1"
        migrate_v0_to_v1 "$dry_run"
        [[ "$dry_run" == "true" ]] || current_ver=1
    fi

    if [[ "$current_ver" -lt 2 ]]; then
        info "Running migration: v1 → v2"
        migrate_v1_to_v2 "$dry_run"
        [[ "$dry_run" == "true" ]] || current_ver=2
    fi

    if [[ "$dry_run" == "true" ]]; then
        echo ""
        info "Dry run complete. No changes were made."
    else
        echo ""
        success "Migration complete. Schema is now at version ${SCHEMA_VERSION}."
    fi
}

# ---------------------------------------------------------------------------
# Global help
# ---------------------------------------------------------------------------
show_help() {
    cat <<EOF
${BOLD}${CYAN}wg-proxy.sh${RESET} — Kernel WireGuard + xray TPROXY proxy manager

${BOLD}USAGE${RESET}
  ${SCRIPT_NAME} <command> [options]

${BOLD}COMMANDS${RESET}
  add [--file <json>]    Add a new WG tunnel from 3x-ui inbound JSON
  remove <port>          Remove a WG tunnel and clean up all files
  list                   List all configured tunnels with status
  start  [port]          Start interface(s) — all if no port given
  stop   [port]          Stop interface(s)  — all if no port given
  restart [port]         Restart interface(s)
  status  [port]         Show detailed status (wg show, iptables, ip rules)
  tproxy <action> [port] Toggle TPROXY (enable/disable/status)
  migrate [--dry-run]    Migrate configuration to current schema version
  export  <sub> ...      Export configurations (see below)

${BOLD}EXPORT SUB-COMMANDS${RESET}
  export wg     <port>          Print wg-quick server conf
  export xray   <port>          Print dokodemo-door JSON for this port
  export xray-all               Print ALL dokodemo-door JSONs as array
  export client <port> [email]  Print client wg-quick config
  export mihomo <port> [email]  Print mihomo WG outbound YAML
  export link   <port> [email]  Print wireguard:// URI link

${BOLD}FILE LAYOUT${RESET}
  ${BASE_DIR}/configs/          WG conf files
  ${BASE_DIR}/xray-inbounds/   dokodemo-door JSON files
  ${BASE_DIR}/ports.json        Port registry with metadata
  ${WG_DIR}/                   Symlinks to conf files (for wg-quick)

${BOLD}REQUIREMENTS${RESET}
  jq, wireguard-tools (wg, wg-quick), iptables, iproute2

${BOLD}EXAMPLES${RESET}
  # Add a tunnel interactively
  ${SCRIPT_NAME} add

  # Add from file
  ${SCRIPT_NAME} add --file /tmp/wg-inbound.json

  # List all tunnels
  ${SCRIPT_NAME} list

  # Show status for port 20330
  ${SCRIPT_NAME} status 20330

  # Export xray inbound JSON to paste into 3x-ui
  ${SCRIPT_NAME} export xray 20330

  # Export client config for a specific user
  ${SCRIPT_NAME} export client 20330 wg1

  # Export mihomo config for all clients on port 20330
  ${SCRIPT_NAME} export mihomo 20330

  # Export WireGuard link for client wg1
  ${SCRIPT_NAME} export link 20330 wg1

  # Stop all tunnels
  ${SCRIPT_NAME} stop

  # Remove tunnel on port 20330
  ${SCRIPT_NAME} remove 20330
EOF
}

# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------
main() {
    check_root
    check_deps
    init_dirs

    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        add)      cmd_add "$@" ;;
        remove)   cmd_remove "$@" ;;
        list)     cmd_list ;;
        start)    cmd_start "$@" ;;
        stop)     cmd_stop "$@" ;;
        restart)  cmd_restart "$@" ;;
        status)   cmd_status "$@" ;;
        tproxy)   cmd_tproxy "$@" ;;
        migrate)  cmd_migrate "$@" ;;
        export)   cmd_export "$@" ;;
        --help|-h|help|"")
            show_help
            ;;
        *)
            error "Unknown command: ${cmd}"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
