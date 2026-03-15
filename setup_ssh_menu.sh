#!/bin/bash
 
# ==========================================
# Debian 12 SSH 综合安全加固配置工具 (交互菜单版)
# ==========================================
 
# 1. 检查运行权限
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[31m❌ 请使用 root 权限或 sudo 运行此脚本。\033[0m"
  exit 1
fi
 
# 确保 sudo 已安装
if ! command -v sudo &> /dev/null; then
    apt-get update -qq && apt-get install -y sudo -qq
fi
 
# ==========================================
# 初始化全局变量 (默认状态)
# ==========================================
if [ -n "$SUDO_USER" ]; then
    TARGET_USER="$SUDO_USER"
else
    TARGET_USER="root"
fi
 
SSH_PORT=22
PERMIT_ROOT="prohibit-password"
FAIL2BAN_ENABLE="未开启"
KEY_CONFIGURED="否"
CONFIG_DROPIN="/etc/ssh/sshd_config.d/01-custom-security.conf"

# 读取当前系统实际生效的 SSH 配置
load_current_state() {
    local sshd_dump
    sshd_dump=$(sshd -T 2>/dev/null)

    # 当前监听端口（取第一个，防止多 Port 行导致多行匹配使校验失败）
    local current_port
    current_port=$(echo "$sshd_dump" | grep -i "^port " | awk 'NR==1{print $2}')
    if [[ "$current_port" =~ ^[0-9]+$ ]]; then
        SSH_PORT=$current_port
    fi

    # 当前 Root 登录策略
    local current_permit
    current_permit=$(echo "$sshd_dump" | grep -i "^permitrootlogin " | awk '{print $2}')
    if [ -n "$current_permit" ]; then
        PERMIT_ROOT="$current_permit"
    fi

    # 当前 Fail2ban 状态
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        if fail2ban-client status sshd &>/dev/null; then
            FAIL2BAN_ENABLE="已开启"
        else
            FAIL2BAN_ENABLE="已开启 (sshd jail 未启用)"
        fi
    fi

    # 当前用户密钥状态
    local auth_keys
    auth_keys="$(getent passwd "$TARGET_USER" | cut -d: -f6)/.ssh/authorized_keys"
    if [ -f "$auth_keys" ] && [ -s "$auth_keys" ]; then
        local key_count
        key_count=$(grep -cE "^(ssh-|ecdsa-|sk-)" "$auth_keys" 2>/dev/null || echo 0)
        KEY_CONFIGURED="是 (已有 ${key_count} 个公钥)"
    fi
}
 
# ==========================================
# 功能函数定义
# ==========================================
 
# 暂停函数
pause() {
    echo ""
    read -p "按回车键返回主菜单..."
}
 
# 菜单 1: 用户与密钥配置
config_user_and_key() {
    echo -e "\n\033[1;36m--- [1] 配置目标用户与 SSH 密钥 ---\033[0m"
    echo "1. 为当前用户 [$TARGET_USER] 配置密钥"
    echo "2. 创建新的 Sudo 用户并配置密钥"
    read -p "请选择 (1 或 2): " user_choice
 
    if [ "$user_choice" == "2" ]; then
        read -p "请输入新用户名: " NEW_USER
        if [[ ! "$NEW_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            echo -e "\033[31m❌ 用户名无效，只允许小写字母、数字、下划线和连字符，且必须以字母或下划线开头（最长32位）。\033[0m"
            pause; return
        fi
        if id "$NEW_USER" &>/dev/null; then
            echo -e "\033[33m⚠️ 用户 $NEW_USER 已存在，直接使用该用户。\033[0m"
        else
            useradd -m -s /bin/bash "$NEW_USER"
            echo -e "\033[36m请为新用户设置 sudo 密码:\033[0m"
            passwd "$NEW_USER"
            usermod -aG sudo "$NEW_USER"
            echo -e "\033[32m✅ 用户 $NEW_USER 创建并配置 sudo 权限成功。\033[0m"
        fi
        TARGET_USER="$NEW_USER"
    elif [ "$user_choice" != "1" ]; then
        echo -e "\033[31m❌ 无效选择。\033[0m"; pause; return
    fi

    # TARGET_USER 确定后重新检查该用户的密钥状态，防止显示旧用户的检测结果
    local _ak
    _ak="$(getent passwd "$TARGET_USER" | cut -d: -f6)/.ssh/authorized_keys"
    if [ -f "$_ak" ] && [ -s "$_ak" ]; then
        local _kc
        _kc=$(grep -cE "^(ssh-|ecdsa-|sk-)" "$_ak" 2>/dev/null || echo 0)
        KEY_CONFIGURED="是 (已有 ${_kc} 个公钥)"
    else
        KEY_CONFIGURED="否"
    fi

    USER_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
 
    sudo -u "$TARGET_USER" mkdir -p "$SSH_DIR"
    sudo -u "$TARGET_USER" chmod 700 "$SSH_DIR"
 
    echo -e "\n请选择密钥配置方式:"
    echo "1. 自动生成全新 id_rsa 密钥对 (打印到终端)"
    echo "2. 手动粘贴现有的公钥 (ssh-rsa ...)"
    read -p "请选择 (1 或 2): " key_choice
 
    if [ "$key_choice" == "1" ]; then
        if [ -f "$SSH_DIR/id_rsa" ]; then
            echo -e "\033[31m⚠️ $TARGET_USER 的 id_rsa 密钥已存在，取消生成以防覆盖。\033[0m"
        else
            sudo -u "$TARGET_USER" ssh-keygen -t rsa -b 4096 -f "$SSH_DIR/id_rsa" -N "" >/dev/null 2>&1
            echo -e "\n\033[32m✅ 密钥对已生成：$SSH_DIR/id_rsa\033[0m"
            echo -e "\033[33m⚠️  私钥保存在服务器上，请通过安全方式（如 scp）将其下载到本地。\033[0m"
            echo -e "   示例：scp root@<服务器IP>:$SSH_DIR/id_rsa ~/.ssh/id_rsa_server"
            echo ""
            read -p "是否在终端明文显示私钥内容？（存在被终端日志记录的风险，y/N）: " show_key
            if [[ "$show_key" =~ ^[Yy]$ ]]; then
                echo -e "\n\033[41;37m 🚨 高危提示：请立即复制并妥善保存以下 私钥 (Private Key)！ \033[0m"
                echo -e "\033[31m 丢失此私钥将导致您无法登录！\033[0m"
                echo -e "======================================================="
                cat "$SSH_DIR/id_rsa"
                echo -e "=======================================================\n"
                read -p "⚠️ 请确认已复制上述私钥！按回车键继续..."
            fi
            echo -e "📄 公钥 (Public Key)："
            echo -e "-------------------------------------------------------"
            cat "$SSH_DIR/id_rsa.pub"
            echo -e "-------------------------------------------------------\n"
            sudo -u "$TARGET_USER" tee -a "$AUTH_KEYS" < "$SSH_DIR/id_rsa.pub" >/dev/null
            KEY_CONFIGURED="是 (已生成)"
        fi
    elif [ "$key_choice" == "2" ]; then
        read -p "请粘贴公钥内容: " user_pub_key
        if [ -n "$user_pub_key" ]; then
            printf '%s\n' "$user_pub_key" | sudo -u "$TARGET_USER" tee -a "$AUTH_KEYS" >/dev/null
            KEY_CONFIGURED="是 (手动输入)"
            echo -e "\033[32m✅ 公钥保存成功。\033[0m"
        else
            echo -e "\033[31m❌ 公钥不能为空。\033[0m"
        fi
    else
        echo -e "\033[31m❌ 无效选择。\033[0m"
    fi
    sudo -u "$TARGET_USER" chmod 600 "$AUTH_KEYS" 2>/dev/null
    pause
}
 
# 菜单 2: 修改端口
config_port() {
    echo -e "\n\033[1;36m--- [2] 修改 SSH 端口 ---\033[0m"
    read -p "请输入新的 SSH 端口号 (1-65535, 当前: $SSH_PORT): " input_port
    if [[ "$input_port" =~ ^[0-9]+$ ]] && [ "$input_port" -ge 1 ] && [ "$input_port" -le 65535 ]; then
        SSH_PORT=$input_port
        echo -e "\033[32m✅ SSH 端口已设定为: $SSH_PORT\033[0m"
    else
        echo -e "\033[31m❌ 输入无效，保持原有端口。\033[0m"
    fi
    pause
}
 
# 菜单 3: Root 登录策略
config_root() {
    echo -e "\n\033[1;36m--- [3] 设置 Root 登录策略 ---\033[0m"
    echo "1. 彻底禁止 Root 登录 (安全度最高，推荐配合 Sudo 用户使用)"
    echo "2. 仅允许 Root 通过密钥登录 (禁止密码，推荐单人开发机)"
    echo "3. 允许 Root 通过密码和密钥登录 (极其危险，不推荐)"
    read -p "请选择 (1/2/3): " root_choice
    case $root_choice in
        1) PERMIT_ROOT="no"; echo -e "\033[32m✅ 已设为：彻底禁止 Root 登录\033[0m" ;;
        2) PERMIT_ROOT="prohibit-password"; echo -e "\033[32m✅ 已设为：仅允许 Root 密钥登录\033[0m" ;;
        3) PERMIT_ROOT="yes"; echo -e "\033[31m⚠️ 已设为：允许 Root 任意登录\033[0m" ;;
        *) echo -e "\033[31m❌ 无效选择。\033[0m" ;;
    esac
    pause
}
 
# 菜单 4: Fail2ban 开关
config_fail2ban() {
    if [ "$FAIL2BAN_ENABLE" == "未开启" ]; then
        FAIL2BAN_ENABLE="已开启 (将在此次应用时安装)"
        echo -e "\033[32m✅ 已标记：在应用配置时自动安装并配置 Fail2ban。\033[0m"
    else
        FAIL2BAN_ENABLE="未开启"
        echo -e "\033[33m⏸️ 已取消 Fail2ban 安装计划。\033[0m"
    fi
    pause
}
 
# 菜单 5: 应用并重启
apply_and_restart() {
    echo -e "\n\033[1;33m>>> 最终确认与应用 <<<\033[0m"
    
    # 防呆检测
    if [ "$KEY_CONFIGURED" == "否" ]; then
        echo -e "\033[41;37m 严重警告：您尚未在本次配置中添加任何 SSH 密钥！ \033[0m"
        echo -e "\033[31m如果强制关闭密码登录，您可能会被彻底锁在服务器外！\033[0m"
        read -p "是否依然强制继续下发配置？(y/N): " force_apply
        if [[ ! "$force_apply" =~ ^[Yy]$ ]]; then
            echo "已取消应用，请先配置密钥。"
            pause; return
        fi
    fi
 
    # 注释掉主配置及其他 drop-in 中与本脚本冲突的指令：
    #   Port          —— 叠加型，多行会同时监听多个端口
    #   PermitRootLogin / PasswordAuthentication 等 —— 先出现者优先，其他文件的值可能覆盖本脚本
    local conflict_pattern="^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication)[[:space:]]"
    local main_cfg="/etc/ssh/sshd_config"
    if grep -qE "$conflict_pattern" "$main_cfg" 2>/dev/null; then
        sed -i -E "s/${conflict_pattern}/# (由安全加固脚本注释) &/" "$main_cfg"
        echo "已注释主配置中的冲突指令。"
    fi
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [ "$f" = "$CONFIG_DROPIN" ] && continue
        [ -f "$f" ] || continue
        if grep -qE "$conflict_pattern" "$f" 2>/dev/null; then
            sed -i -E "s/${conflict_pattern}/# (由安全加固脚本注释) &/" "$f"
            echo "已注释 $f 中的冲突指令。"
        fi
    done

    echo "正在写入配置文件 $CONFIG_DROPIN ..."
    cat <<EOF > "$CONFIG_DROPIN"
# 自动生成的 SSH 安全配置项
Port $SSH_PORT
PermitRootLogin $PERMIT_ROOT
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
    chmod 644 "$CONFIG_DROPIN"
 
    if [[ "$FAIL2BAN_ENABLE" == *"已开启"* ]]; then
        echo "正在安装并配置 Fail2ban ..."
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban -qq
        cat <<EOF > /etc/fail2ban/jail.d/sshd.local
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
backend = systemd
maxretry = 5
bantime = 3600
findtime = 600
EOF
        systemctl enable fail2ban >/dev/null 2>&1
        systemctl restart fail2ban
        echo -e "\033[32m✅ Fail2ban 防护已启动。\033[0m"
    fi
 
    echo "正在检查 SSH 配置语法..."
    if sshd -t; then
        echo -e "\033[32m✅ 语法检查通过。准备重启服务...\033[0m"
        if systemctl restart ssh; then
            echo -e "\n\033[1;32m🎉 恭喜！所有配置已生效！\033[0m"
            echo -e "\033[33m💡 请勿关闭当前窗口！立即新开一个终端测试登录：\033[0m"
            echo -e "   ssh -i <你的私钥路径> -p $SSH_PORT $TARGET_USER@<服务器IP>"
            exit 0
        else
            echo -e "\033[31m❌ 重启失败，请检查系统日志 journalctl -xeu ssh\033[0m"
        fi
    else
        echo -e "\033[31m❌ 语法错误！已中止重启，请检查配置。\033[0m"
        # 发生错误时，自动将高危配置文件重命名以防下次重启意外生效
        mv "$CONFIG_DROPIN" "${CONFIG_DROPIN}.err"
    fi
    pause
}
 
# ==========================================
# 主循环 (UI 界面)
# ==========================================
load_current_state

while true; do
    clear
    echo -e "\033[36m===================================================\033[0m"
    echo -e "\033[1;32m        Debian 12 SSH 安全加固控制台\033[0m"
    echo -e "\033[36m===================================================\033[0m"
    echo -e " 当前待应用状态预览："
    echo -e " 👤 目标登录用户 : \033[1;33m$TARGET_USER\033[0m"
    echo -e " 🔑 密钥是否就绪 : \033[1;33m$KEY_CONFIGURED\033[0m"
    echo -e " 🔌 SSH 监听端口 : \033[1;33m$SSH_PORT\033[0m"
    echo -e " 👑 Root 登录策略: \033[1;33m$PERMIT_ROOT\033[0m"
    echo -e " 🛡️ Fail2ban 防护: \033[1;33m$FAIL2BAN_ENABLE\033[0m"
    echo -e "\033[36m---------------------------------------------------\033[0m"
    echo " 1. [用户/密钥] 配置目标用户与 SSH 密钥"
    echo " 2. [监听端口] 修改 SSH 端口 (防扫描)"
    echo " 3. [Root策略] 修改 Root 账户登录限制"
    echo " 4. [防爆防护] 开启/关闭 Fail2ban 自动封 IP"
    echo " 5. [执行生效] 写入配置、语法检查并重启 SSHD 服务"
    echo " 0. [退出工具] 放弃更改并退出"
    echo -e "\033[36m===================================================\033[0m"
    
    read -p "请输入对应数字进行操作: " opt
    case $opt in
        1) config_user_and_key ;;
        2) config_port ;;
        3) config_root ;;
        4) config_fail2ban ;;
        5) apply_and_restart ;;
        0) echo -e "\n已安全退出，未作最终修改。"; exit 0 ;;
        *) echo -e "\033[31m❌ 无效输入，请输入 0-5 之间的数字。\033[0m"; sleep 1 ;;
    esac
done
