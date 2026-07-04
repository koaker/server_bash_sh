#!/usr/bin/env bash
# pve_sysinfo.sh — PVE 系统硬件全量信息采集（只读，不修改任何系统文件）
#
# 用法:
#   bash pve_sysinfo.sh            默认：打印全量信息，末尾附简略概览
#   bash pve_sysinfo.sh --full/-f  仅全量信息
#   bash pve_sysinfo.sh --brief/-b 仅简略概览
#   bash pve_sysinfo.sh --help/-h  帮助

# 只保留 -u（未定义变量保护），去掉 -e 和 pipefail。
# sysinfo 脚本依赖大量 grep 过滤管道，grep 无匹配时退出 1，-e+pipefail
# 会在任意空结果处终止脚本，因此不适合此场景。
set -u

# ────────────────────────── 颜色定义 ──────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

sep()   { echo -e "${CYAN}$(printf '─%.0s' {1..70})${RESET}"; }
hdr()   { echo; sep; echo -e "  ${BOLD}${GREEN}$1${RESET}"; sep; }
kv()    { printf "  ${YELLOW}%-28s${RESET} %s\n" "$1" "$2"; }
warn()  { echo -e "  ${RED}[跳过] $1${RESET}"; }
smhdr() { echo -e "${BOLD}${CYAN}$(printf '━%.0s' {1..70})${RESET}"; }

# ────────────────────────── 参数解析 ──────────────────────────────────
MODE="both"    # both | full | brief
case "${1:-}" in
    -b|--brief) MODE="brief" ;;
    -f|--full)  MODE="full"  ;;
    -h|--help)
        echo "用法: $0 [选项]"
        echo "  (无参数)     打印全量信息 + 末尾简略概览"
        echo "  -f, --full   仅全量信息"
        echo "  -b, --brief  仅简略概览"
        exit 0 ;;
esac

# ────────────────────────── 工具检查 ──────────────────────────────────
need_tool() { command -v "$1" &>/dev/null; }

# 判断是否为物理网卡（/sys/class/net/$1/device 存在则为物理网卡）
is_physical_nic() { [[ -e "/sys/class/net/${1}/device" ]]; }

# ────────────────────────── 权限提示 ──────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${YELLOW}警告: 当前非 root 用户，dmidecode / smartctl / LVM / IPMI 等部分信息可能无法获取。${RESET}"
    echo -e "${YELLOW}      建议: sudo bash $0 ${1:-}${RESET}"
    echo
fi

# ══════════════════════════════════════════════════════════════════════
# 全量信息打印函数
# ══════════════════════════════════════════════════════════════════════
print_full() {

echo -e "\n${BOLD}${GREEN}  PVE 系统硬件全量信息采集${RESET}  $(date '+%Y-%m-%d %H:%M:%S')"
sep

# ──────────────────── 1. 操作系统 / PVE 版本 ──────────────────────────
hdr "操作系统 & PVE 版本"
kv "主机名"     "$(hostname -f 2>/dev/null || hostname)"
kv "内核版本"   "$(uname -r)"
kv "架构"       "$(uname -m)"
kv "OS 发行版"  "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo '未知')"
# pveversion 是 PVE 的官方版本工具，/etc/pve/.version 存储的是集群配置状态 JSON，不是版本字符串
if need_tool pveversion; then
    kv "PVE 版本"  "$(pveversion 2>/dev/null | head -1)"
fi
kv "运行时间"   "$(uptime -p 2>/dev/null || uptime)"
kv "当前用户"   "$(whoami)"

# ──────────────────── 2. CPU ──────────────────────────────────────────
hdr "CPU 信息"
if [[ -f /proc/cpuinfo ]]; then
    model=$(grep -m1 'model name'  /proc/cpuinfo | cut -d: -f2 | xargs)
    # 虚拟机 /proc/cpuinfo 可能没有 physical id 字段；{ grep || true; } 使管道
    # 在无匹配时仍以 exit 0 完成，wc -l 正常输出 0，避免触发 set -e。
    phys=$( { grep 'physical id'   /proc/cpuinfo 2>/dev/null || true; } | sort -u | wc -l )
    cores=$(grep -m1 'cpu cores'   /proc/cpuinfo | cut -d: -f2 | xargs)
    threads=$(grep -c 'processor'  /proc/cpuinfo)
    cache=$(grep -m1 'cache size'  /proc/cpuinfo | cut -d: -f2 | xargs)
    flags=$(grep -m1 '^flags'      /proc/cpuinfo | cut -d: -f2 | xargs)
    kv "型号"         "${model:-未知}"
    kv "物理 CPU 数"  "${phys:-未知}"
    kv "每颗核心数"   "${cores:-未知}"
    kv "逻辑线程数"   "${threads:-未知}"
    kv "L3 缓存"      "${cache:-未知}"
    # [[ ]] 字符串匹配：不启动子进程，不受 set -e 影响，比 grep -qw 更安全
    # 两端加空格确保 "avx" 不误匹配 "avx2"，"avx2" 先判断再判断 "avx"
    virt_flags=""
    [[ " $flags " == *" vmx  "* ]]  && virt_flags+="Intel VT-x "
    [[ " $flags " == *" svm "* ]]   && virt_flags+="AMD-V "
    [[ " $flags " == *" ept "* ]]   && virt_flags+="EPT "
    [[ " $flags " == *" avx2 "* ]]  && virt_flags+="AVX2 "
    [[ " $flags " == *" avx "* ]]   && virt_flags+="AVX "
    [[ " $flags " == *" aes "* ]]   && virt_flags+="AES-NI "
    kv "关键指令集"   "${virt_flags:-无}"
fi

if need_tool lscpu; then
    echo
    echo -e "  ${BOLD}lscpu 详情:${RESET}"
    # 过滤掉 Vulnerability 行，保持输出简洁；全量漏洞信息可用 lscpu 单独查看
    lscpu | grep -v '^Vulnerability' | while IFS=: read -r k v; do
        [[ -n "${k// /}" ]] && kv "$(echo "$k" | xargs)" "$(echo "$v" | xargs)"
    done
    echo
    echo -e "  ${BOLD}CPU 漏洞缓解状态 (摘要):${RESET}"
    lscpu | grep '^Vulnerability' | while IFS=: read -r k v; do
        printf "  %-38s %s\n" "$(echo "$k" | xargs)" "$(echo "$v" | xargs)"
    done
fi

# CPU 频率
if [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
    echo
    echo -e "  ${BOLD}CPU 当前频率 (MHz):${RESET}"
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq; do
        [[ -f "$f" ]] || continue
        cpu=$(echo "$f" | grep -oP 'cpu\d+')
        freq=$(awk '{printf "%.0f", $1/1000}' "$f" 2>/dev/null)
        printf "    %-12s %s MHz\n" "$cpu" "$freq"
    done | sort -V | head -20
    total=$(ls /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq 2>/dev/null | wc -l)
    [[ $total -gt 20 ]] && echo "    ... (共 ${total} 核，仅显示前 20)"
fi

# CPU 温度
if [[ -d /sys/class/thermal ]]; then
    first=1
    for zone in /sys/class/thermal/thermal_zone*/; do
        type=$(cat "${zone}type" 2>/dev/null || echo 'unknown')
        temp_raw=$(cat "${zone}temp" 2>/dev/null || echo '')
        if [[ -n "$temp_raw" ]] && [[ "$temp_raw" -gt 0 ]] 2>/dev/null; then
            temp=$(awk "BEGIN{printf \"%.1f\", $temp_raw/1000}")
            [[ $first -eq 1 ]] && echo && echo -e "  ${BOLD}CPU 温度:${RESET}" && first=0
            kv "  ${type}" "${temp} °C"
        fi
    done
fi

# ──────────────────── 3. 内存 ────────────────────────────────────────
hdr "内存信息"
if [[ -f /proc/meminfo ]]; then
    awk '
    /^MemTotal/    {total=$2}
    /^MemFree/     {free=$2}
    /^MemAvailable/{avail=$2}
    /^Buffers/     {buf=$2}
    /^Cached/      {cached=$2}
    /^SwapTotal/   {st=$2}
    /^SwapFree/    {sf=$2}
    END {
        used = total - avail
        pct  = (total>0) ? int(used*100/total) : 0
        printf "  \033[1;33m%-28s\033[0m %.2f GiB\n",   "总内存",   total/1024/1024
        printf "  \033[1;33m%-28s\033[0m %.2f GiB (%d%% 已用)\n", "已用", used/1024/1024, pct
        printf "  \033[1;33m%-28s\033[0m %.2f GiB\n",   "可用",     avail/1024/1024
        printf "  \033[1;33m%-28s\033[0m %.2f GiB\n",   "Buffers",  buf/1024/1024
        printf "  \033[1;33m%-28s\033[0m %.2f GiB\n",   "Cached",   cached/1024/1024
        printf "  \033[1;33m%-28s\033[0m %.2f GiB\n",   "Swap 总量", st/1024/1024
        printf "  \033[1;33m%-28s\033[0m %.2f GiB\n",   "Swap 空闲", sf/1024/1024
    }' /proc/meminfo
fi

if need_tool dmidecode; then
    echo
    echo -e "  ${BOLD}物理内存条 (dmidecode):${RESET}"
    result=$(dmidecode -t memory 2>/dev/null | awk '
        /^Memory Device$/ { in_dev=1; slot_info="" }
        in_dev && /^\tSize:/ && !/No Module/ {
            size=$0; gsub(/^\t/,"",size)
        }
        in_dev && /^\t(Type|Speed|Manufacturer|Part Number|Locator|Form Factor|Bank Locator):/ {
            line=$0; gsub(/^\t/,"  ",line)
            slot_info = slot_info "\n" line
        }
        in_dev && /^$/ {
            if (size ~ /[0-9]/) print "  ---\n  " size slot_info
            in_dev=0; size=""; slot_info=""
        }
    ')
    if [[ -n "$result" ]]; then
        echo "$result"
    else
        warn "dmidecode 无输出（可能需要 root 权限，或平台不支持）"
    fi
else
    warn "dmidecode 未安装，跳过物理内存槽位信息"
fi

# ──────────────────── 4. GPU ─────────────────────────────────────────
hdr "GPU / 显卡信息"

if need_tool lspci; then
    echo -e "  ${BOLD}PCI 显示设备 (lspci -v):${RESET}"
    lspci -v 2>/dev/null | awk '
        /VGA compatible controller|3D controller|Display controller|Display adapter/ {
            gsub(/^[[:space:]]*/,""); print "  " $0; in_dev=1; next
        }
        in_dev && /^\t(Subsystem|Memory|Region|Flags|Kernel driver|Kernel modules):/ {
            gsub(/^\t/,"    "); print; next
        }
        in_dev && /^[0-9a-f]/ { in_dev=0 }
    '
    echo
fi

# NVIDIA GPU
if need_tool nvidia-smi; then
    echo -e "  ${BOLD}NVIDIA GPU (nvidia-smi):${RESET}"
    nvidia-smi \
        --query-gpu=index,name,driver_version,memory.total,memory.free,memory.used,temperature.gpu,utilization.gpu,power.draw,clocks.current.graphics \
        --format=csv,noheader,nounits 2>/dev/null \
    | while IFS=',' read -r idx name drv mem_t mem_f mem_u temp util pwr clk; do
        echo
        kv "  GPU #$(echo "$idx"|xargs) 型号"  "$(echo "$name"|xargs)"
        kv "  驱动版本"   "$(echo "$drv"|xargs)"
        kv "  显存总量"   "$(echo "$mem_t"|xargs) MiB"
        kv "  显存已用"   "$(echo "$mem_u"|xargs) MiB"
        kv "  显存空闲"   "$(echo "$mem_f"|xargs) MiB"
        kv "  温度"       "$(echo "$temp"|xargs) °C"
        kv "  GPU 使用率" "$(echo "$util"|xargs) %"
        kv "  功耗"       "$(echo "$pwr"|xargs) W"
        kv "  核心频率"   "$(echo "$clk"|xargs) MHz"
    done
else
    warn "未检测到 nvidia-smi，跳过 NVIDIA GPU 详情"
fi

# AMD GPU
if need_tool rocm-smi; then
    echo -e "  ${BOLD}AMD GPU (rocm-smi):${RESET}"
    rocm-smi 2>/dev/null || warn "rocm-smi 执行失败"
else
    warn "未检测到 rocm-smi，跳过 AMD GPU 详情"
fi

# Intel GPU (sysfs)
# ls glob 在无 drm 目录时返回 2；|| true 掩盖失败，避免 set -e 下的脚本退出
intel_gpu=$(ls /sys/class/drm/*/device/vendor 2>/dev/null \
            | xargs grep -l '0x8086' 2>/dev/null | head -1 || true)
if [[ -n "$intel_gpu" ]]; then
    drm_dir=$(dirname "$(dirname "$intel_gpu")")
    echo -e "  ${BOLD}Intel GPU (sysfs):${RESET}"
    kv "  DRM 设备路径" "$drm_dir"
    uevent="${drm_dir}/device/uevent"
    if [[ -f "$uevent" ]]; then
        while IFS='=' read -r k v; do
            [[ -n "$k" ]] && printf "    ${YELLOW}%-20s${RESET} %s\n" "$k" "$v"
        done < "$uevent"
    fi
    # 尝试获取 i915 驱动信息
    if need_tool ethtool; then
        drv_info=$(cat "/sys/class/drm/$(basename "$drm_dir")/device/driver/module/version" 2>/dev/null || true)
        [[ -n "$drv_info" ]] && kv "  驱动版本" "$drv_info"
    fi
fi

# ──────────────────── 5. 硬盘 / 存储 ────────────────────────────────
hdr "硬盘 & 存储信息"

if need_tool lsblk; then
    echo -e "  ${BOLD}块设备树 (lsblk):${RESET}"
    lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,TRAN,ROTA,SCHED 2>/dev/null \
        || lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT 2>/dev/null
    echo
fi

echo -e "  ${BOLD}文件系统使用率 (df):${RESET}"
df -hT 2>/dev/null | grep -v 'tmpfs\|devtmpfs\|overlay\|squashfs' || df -h 2>/dev/null

echo
echo -e "  ${BOLD}磁盘健康 (smartctl):${RESET}"
if need_tool smartctl; then
    for dev in $(lsblk -dn -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print "/dev/"$1}'); do
        echo -e "\n  ${YELLOW}>>> $dev${RESET}"
        smartctl -i -H "$dev" 2>/dev/null | grep -Ei \
            'Device Model|Serial Number|Firmware|User Capacity|Sector|Rotation|SMART overall|NVMe Version' \
            | while IFS= read -r line; do echo "    $line"; done \
            || warn "$dev 需要 root 或不支持 SMART"
    done
elif need_tool nvme; then
    for dev in /dev/nvme[0-9]; do
        [[ -b "$dev" ]] || continue
        echo -e "\n  ${YELLOW}>>> $dev${RESET}"
        nvme id-ctrl "$dev" 2>/dev/null \
            | grep -Ei 'mn|sn|fr|tnvmcap' \
            | while IFS= read -r line; do echo "    $line"; done \
            || warn "$dev 访问失败"
    done
else
    warn "smartctl / nvme 未安装，跳过磁盘健康检查"
fi

echo
if need_tool pvs; then
    echo -e "  ${BOLD}LVM 物理卷:${RESET}"
    pvs 2>/dev/null || warn "pvs 需要 root"
    echo -e "\n  ${BOLD}LVM 卷组:${RESET}"
    vgs 2>/dev/null || warn "vgs 需要 root"
fi
if [[ -f /proc/mdstat ]]; then
    echo -e "\n  ${BOLD}软 RAID (mdstat):${RESET}"
    cat /proc/mdstat
fi
if need_tool zpool; then
    echo -e "\n  ${BOLD}ZFS 存储池:${RESET}"
    zpool list 2>/dev/null && zpool status 2>/dev/null || warn "zpool 访问失败"
fi

# ──────────────────── 6. 网卡 ────────────────────────────────────────
hdr "网卡 & 网络信息"

if need_tool lspci; then
    echo -e "  ${BOLD}PCI 网络设备:${RESET}"
    lspci 2>/dev/null \
        | grep -i 'ethernet\|network\|infiniband\|wireless\|wi-fi\|mellanox\|broadcom\|intel.*network' \
        | while IFS= read -r line; do echo "  $line"; done
    echo
fi

if need_tool ip; then
    echo -e "  ${BOLD}网络接口 (ip link):${RESET}"
    ip -br link show 2>/dev/null || ip link show 2>/dev/null
    echo
    echo -e "  ${BOLD}IP 地址 (ip addr):${RESET}"
    ip -br addr show 2>/dev/null || ip addr show 2>/dev/null
    echo
    echo -e "  ${BOLD}路由表:${RESET}"
    ip route show 2>/dev/null
fi

if need_tool ethtool; then
    echo
    echo -e "  ${BOLD}物理网卡详情 (ethtool，已过滤虚拟接口):${RESET}"
    # 只遍历物理网卡：/sys/class/net/$iface/device 存在的接口
    for iface in $(ip -br link show 2>/dev/null | awk '$1!="lo"{print $1}' | sed 's/@.*//'); do
        is_physical_nic "$iface" || continue
        echo -e "\n  ${YELLOW}>>> $iface${RESET}"
        ethtool "$iface" 2>/dev/null \
            | grep -Ei 'Speed|Duplex|Port|Auto-negotiation|Link detected|Supported link modes' \
            | while IFS= read -r line; do echo "    $line"; done
        ethtool -i "$iface" 2>/dev/null \
            | grep -Ei 'driver|version|firmware-version|bus-info' \
            | while IFS= read -r line; do echo "    $line"; done
    done
else
    warn "ethtool 未安装，跳过网卡详情"
fi

# ──────────────────── 7. PCI / USB 设备 ──────────────────────────────
hdr "PCI & USB 设备"

if need_tool lspci; then
    echo -e "  ${BOLD}全部 PCI 设备:${RESET}"
    lspci 2>/dev/null | while IFS= read -r line; do echo "  $line"; done
fi
echo
if need_tool lsusb; then
    echo -e "  ${BOLD}USB 设备:${RESET}"
    lsusb 2>/dev/null | while IFS= read -r line; do echo "  $line"; done
else
    warn "lsusb 未安装"
fi

# ──────────────────── 8. BIOS / 主板 ─────────────────────────────────
hdr "BIOS & 主板信息"

if need_tool dmidecode; then
    echo -e "  ${BOLD}BIOS:${RESET}"
    dmidecode -t bios 2>/dev/null \
        | grep -Ei 'Vendor|Version|Release Date|BIOS Revision|Firmware Revision' \
        | while IFS= read -r line; do echo "  $line"; done
    echo
    echo -e "  ${BOLD}主板:${RESET}"
    dmidecode -t baseboard 2>/dev/null \
        | grep -Ei 'Manufacturer|Product Name|Version|Serial Number|Asset Tag' \
        | while IFS= read -r line; do echo "  $line"; done
    echo
    echo -e "  ${BOLD}系统 (整机):${RESET}"
    dmidecode -t system 2>/dev/null \
        | grep -Ei 'Manufacturer|Product Name|Version|Serial Number|UUID|SKU Number|Family' \
        | while IFS= read -r line; do echo "  $line"; done
else
    warn "dmidecode 未安装或非 root，跳过 BIOS / 主板信息"
fi

# ──────────────────── 9. 电源 & IPMI ─────────────────────────────────
hdr "电源 & IPMI / BMC"

if need_tool ipmitool; then
    echo -e "  ${BOLD}IPMI 功耗:${RESET}"
    ipmitool dcmi power reading 2>/dev/null \
        | while IFS= read -r line; do echo "  $line"; done \
        || warn "IPMI 访问失败"
    echo
    echo -e "  ${BOLD}IPMI 传感器 (温度/风扇):${RESET}"
    ipmitool sdr type Temperature 2>/dev/null \
        | while IFS= read -r line; do echo "  $line"; done
    ipmitool sdr type Fan        2>/dev/null \
        | while IFS= read -r line; do echo "  $line"; done
else
    warn "ipmitool 未安装，跳过 IPMI 信息"
fi

if need_tool sensors; then
    echo
    echo -e "  ${BOLD}硬件传感器 (lm-sensors):${RESET}"
    sensors 2>/dev/null | while IFS= read -r line; do echo "  $line"; done
else
    warn "lm-sensors 未安装，跳过传感器信息"
fi

# ──────────────────── 10. PVE 虚拟化层 ───────────────────────────────
hdr "PVE 虚拟化层信息"

if [[ -d /etc/pve ]]; then
    echo -e "  ${BOLD}已运行 VM 列表 (qm):${RESET}"
    if need_tool qm; then
        qm list 2>/dev/null | while IFS= read -r line; do echo "  $line"; done \
            || warn "qm list 失败"
    fi
    echo
    echo -e "  ${BOLD}已运行 CT 列表 (pct):${RESET}"
    if need_tool pct; then
        pct list 2>/dev/null | while IFS= read -r line; do echo "  $line"; done \
            || warn "pct list 失败"
    fi
    echo
    echo -e "  ${BOLD}PVE 存储配置 (pvesm):${RESET}"
    if need_tool pvesm; then
        pvesm status 2>/dev/null | while IFS= read -r line; do echo "  $line"; done \
            || warn "pvesm 访问失败"
    fi
fi

# ──────────────────── 11. 内核模块 & 驱动 ────────────────────────────
hdr "已加载内核模块 (关键驱动)"
lsmod 2>/dev/null \
    | grep -Ei 'kvm|vfio|iommu|virtio|xen|vmware|nvidia|amdgpu|radeon|i915|mlx|ixgbe|igb|e1000|r8169|tg3|bnxt|nvme|ahci|megaraid|mpt|lpfc|qla' \
    | awk '{printf "  %-30s 被引用: %s\n", $1, $3}' | sort \
    || true

# ──────────────────── 12. IOMMU / 直通信息 ───────────────────────────
hdr "IOMMU & PCIe 直通"

iommu_enabled=false
if grep -q 'iommu=on\|intel_iommu=on\|amd_iommu=on' /proc/cmdline 2>/dev/null; then
    iommu_enabled=true
fi
if dmesg 2>/dev/null | grep -qi 'iommu.*enabled\|IOMMU.*enabled'; then
    iommu_enabled=true
fi
kv "IOMMU 状态" "$( [[ "$iommu_enabled" == "true" ]] && echo '已启用' || echo '未检测到启用' )"

echo -e "\n  ${BOLD}/proc/cmdline:${RESET}"
echo "  $(cat /proc/cmdline 2>/dev/null)"

if [[ -d /sys/kernel/iommu_groups ]]; then
    group_count=$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l)
    echo
    kv "  IOMMU 总分组数" "$group_count"
    echo -e "\n  ${BOLD}各 IOMMU 组内 PCI 设备（前 30 组）:${RESET}"
    for grp in $(ls -v /sys/kernel/iommu_groups/ 2>/dev/null | head -30); do
        devices=$(ls "/sys/kernel/iommu_groups/${grp}/devices/" 2>/dev/null)
        [[ -n "$devices" ]] && printf "    组 %-4s: %s\n" "$grp" "$(echo "$devices" | tr '\n' ' ')"
    done
fi

sep
echo -e "  ${BOLD}${GREEN}全量信息采集完成  $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
sep
echo

} # end print_full()

# ══════════════════════════════════════════════════════════════════════
# 简略概览打印函数
# ══════════════════════════════════════════════════════════════════════
print_summary() {

# ── 采集数据 ──────────────────────────────────────────────────────────
local hn os_ver kernel pve_ver uptime_str

hn=$(hostname -f 2>/dev/null || hostname)
os_ver=$(grep PRETTY_NAME /etc/os-release 2>/dev/null \
         | cut -d= -f2 | tr -d '"' || echo '未知')
kernel=$(uname -r)
pve_ver=$(need_tool pveversion && pveversion 2>/dev/null \
          | grep -oP 'pve-manager/\K[^/]+' || echo '未知')
uptime_str=$(uptime -p 2>/dev/null || uptime)

# CPU
local cpu_model cpu_cores cpu_threads cpu_cache virt_flags=""
cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo '未知')
cpu_cores=$(grep -m1 'cpu cores'  /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo '?')
cpu_threads=$(grep -c 'processor' /proc/cpuinfo 2>/dev/null || echo '?')
cpu_cache=$(grep -m1 'cache size' /proc/cpuinfo 2>/dev/null \
            | awk -F: '{print $2}' | xargs || echo '?')
local flags
flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo '')
[[ " $flags " == *" vmx "* ]]  && virt_flags+="VT-x "
[[ " $flags " == *" svm "* ]]  && virt_flags+="AMD-V "
[[ " $flags " == *" ept "* ]]  && virt_flags+="EPT "
[[ " $flags " == *" avx2 "* ]] && virt_flags+="AVX2 "
[[ " $flags " == *" avx "* ]]  && virt_flags+="AVX "
[[ " $flags " == *" aes "* ]]  && virt_flags+="AES-NI "
[[ -z "$virt_flags" ]] && virt_flags="无"

# 内存
local mem_total mem_used mem_avail mem_pct swap_total swap_used swap_pct
mem_total=$(awk '/^MemTotal/{printf "%.1f", $2/1024/1024}' /proc/meminfo)
mem_avail=$(awk '/^MemAvailable/{printf "%.1f", $2/1024/1024}' /proc/meminfo)
mem_used=$(awk '/^MemTotal/{t=$2} /^MemAvailable/{a=$2} END{printf "%.1f",(t-a)/1024/1024}' /proc/meminfo)
mem_pct=$(awk '/^MemTotal/{t=$2} /^MemAvailable/{a=$2} END{printf "%d",(t-a)*100/t}' /proc/meminfo)
swap_total=$(awk '/^SwapTotal/{printf "%.1f",$2/1024/1024}' /proc/meminfo)
swap_used=$(awk '/^SwapTotal/{t=$2}/^SwapFree/{f=$2} END{printf "%.1f",(t-f)/1024/1024}' /proc/meminfo)
swap_pct=$(awk '/^SwapTotal/{t=$2}/^SwapFree/{f=$2} END{if(t>0)printf "%d",(t-f)*100/t; else print "0"}' /proc/meminfo)

# 存储
local disk_summary=""
if need_tool lsblk; then
    while IFS= read -r line; do
        name=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        model=$(echo "$line" | awk '{print substr($0, index($0,$4))}' | xargs)
        disk_summary+="    ${YELLOW}${name}${RESET}  ${size}  ${model}\n"
    done < <(lsblk -dn -o NAME,SIZE,MODEL 2>/dev/null | grep -v '^loop')
fi

# 磁盘使用率（根分区）
local root_used root_total root_pct
root_used=$(df -h / 2>/dev/null | awk 'NR==2{print $3}')
root_total=$(df -h / 2>/dev/null | awk 'NR==2{print $2}')
root_pct=$(df / 2>/dev/null | awk 'NR==2{print $5}')

# 物理网卡 & 速度
local nic_summary=""
if need_tool ethtool && need_tool ip; then
    for iface in $(ip -br link show 2>/dev/null | awk '$1!="lo"{print $1}' | sed 's/@.*//'); do
        is_physical_nic "$iface" || continue
        speed=$(ethtool "$iface" 2>/dev/null | awk '/Speed:/{print $2}' || echo '?')
        link=$(ethtool "$iface" 2>/dev/null | awk '/Link detected:/{print $3}' || echo '?')
        driver=$(ethtool -i "$iface" 2>/dev/null | awk '/^driver:/{print $2}' || echo '?')
        link_color="${GREEN}"; [[ "$link" != "yes" ]] && link_color="${RED}"
        nic_summary+="    ${YELLOW}${iface}${RESET}  速度: ${speed}  链路: ${link_color}${link}${RESET}  驱动: ${driver}\n"
    done
fi

# GPU
local gpu_summary=""
if need_tool lspci; then
    while IFS= read -r line; do
        gpu_summary+="    $line\n"
    done < <(lspci 2>/dev/null | grep -Ei 'vga|3d controller|display controller')
fi

# IOMMU
local iommu_status="未检测到启用"
local iommu_groups="0"
grep -q 'iommu=on\|intel_iommu=on\|amd_iommu=on' /proc/cmdline 2>/dev/null && iommu_status="已启用"
[[ -d /sys/kernel/iommu_groups ]] && \
    iommu_groups=$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l)

# KVM
local kvm_status="未加载"
lsmod 2>/dev/null | grep -q '^kvm ' && kvm_status="已加载"

# VM / CT 统计
local vm_running=0 vm_stopped=0 ct_running=0 ct_stopped=0
if need_tool qm; then
    vm_running=$(qm list 2>/dev/null | awk 'NR>1 && $3=="running"{c++} END{print c+0}')
    vm_stopped=$(qm list 2>/dev/null | awk 'NR>1 && $3=="stopped"{c++} END{print c+0}')
fi
if need_tool pct; then
    ct_running=$(pct list 2>/dev/null | awk 'NR>1 && $2=="running"{c++} END{print c+0}')
    ct_stopped=$(pct list 2>/dev/null | awk 'NR>1 && $2=="stopped"{c++} END{print c+0}')
fi

# PVE 存储池
local storage_summary=""
if need_tool pvesm; then
    while IFS= read -r line; do
        [[ "$line" =~ ^Name ]] && continue
        storage_summary+="    $line\n"
    done < <(pvesm status 2>/dev/null || true)
fi

# ── 打印简略概览 ──────────────────────────────────────────────────────
echo
smhdr
echo -e "  ${BOLD}${GREEN}系统概览 (简略版)${RESET}  $(date '+%Y-%m-%d %H:%M:%S')"
smhdr

printf "\n  ${BOLD}%-14s${RESET} %s\n"      "主机名"      "$hn"
printf "  ${BOLD}%-14s${RESET} %s\n"         "操作系统"    "$os_ver"
printf "  ${BOLD}%-14s${RESET} %s\n"         "PVE 版本"    "$pve_ver"
printf "  ${BOLD}%-14s${RESET} %s\n"         "内核"        "$kernel"
printf "  ${BOLD}%-14s${RESET} %s\n\n"       "运行时间"    "$uptime_str"

smhdr
echo -e "  ${BOLD}${CYAN}▸ CPU${RESET}"
printf "  %-14s %s\n"  "型号"   "$cpu_model"
printf "  %-14s %dC / %dT  L3 %s\n"  "规格" "$cpu_cores" "$cpu_threads" "$cpu_cache"
printf "  %-14s %s\n\n" "指令集" "$virt_flags"

smhdr
echo -e "  ${BOLD}${CYAN}▸ 内存${RESET}"
printf "  %-14s %s GiB  已用 %s GiB (%s%%)\n" \
    "物理内存" "$mem_total" "$mem_used" "$mem_pct"
printf "  %-14s %s GiB  已用 %s GiB (%s%%)\n\n" \
    "Swap" "$swap_total" "$swap_used" "$swap_pct"

smhdr
echo -e "  ${BOLD}${CYAN}▸ 存储${RESET}"
if [[ -n "$disk_summary" ]]; then
    echo -e "$disk_summary"
else
    echo "  (无法获取磁盘信息)"
    echo
fi
printf "  %-14s %s 已用 / %s 总量 (%s)\n\n" \
    "/ 文件系统" "${root_used:-?}" "${root_total:-?}" "${root_pct:-?}"

smhdr
echo -e "  ${BOLD}${CYAN}▸ 网卡 (仅物理网卡)${RESET}"
if [[ -n "$nic_summary" ]]; then
    echo -e "$nic_summary"
else
    echo "  (无法获取网卡信息或无物理网卡)"
    echo
fi

smhdr
echo -e "  ${BOLD}${CYAN}▸ 显卡${RESET}"
if [[ -n "$gpu_summary" ]]; then
    echo -e "$gpu_summary"
else
    echo "  (未检测到 PCI 显示设备)"
    echo
fi

smhdr
echo -e "  ${BOLD}${CYAN}▸ 虚拟化${RESET}"
printf "  %-14s %s\n"   "IOMMU"       "$iommu_status  ($iommu_groups 个分组)"
printf "  %-14s %s\n"   "KVM 模块"    "$kvm_status"
printf "  %-14s VM运行 %d / 停止 %d   CT运行 %d / 停止 %d\n\n" \
    "VM/CT 状态" "$vm_running" "$vm_stopped" "$ct_running" "$ct_stopped"

if [[ -n "$storage_summary" ]]; then
    smhdr
    echo -e "  ${BOLD}${CYAN}▸ PVE 存储池${RESET}"
    echo -e "$storage_summary"
fi

smhdr
echo

} # end print_summary()

# ══════════════════════════════════════════════════════════════════════
# 主逻辑
# ══════════════════════════════════════════════════════════════════════
case "$MODE" in
    full)   print_full    ;;
    brief)  print_summary ;;
    both)   print_full
            print_summary ;;
esac
