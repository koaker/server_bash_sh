# Debian 12 SSH 安全加固工具

一个用于 Debian 12 服务器的交互式 SSH 安全加固脚本，通过菜单引导完成所有配置，无需手动编辑配置文件。

## 快速开始

以 root 身份登录服务器后，执行以下命令即可下载并运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/koaker/server_bash_sh/main/setup_ssh_menu.sh)
```

> 需要 root 或 sudo 权限运行。

## 功能

| 菜单项 | 说明 |
|--------|------|
| 用户/密钥 | 为现有用户或新建 sudo 用户配置 SSH 公钥认证 |
| 监听端口 | 修改 SSH 监听端口，降低自动化扫描风险 |
| Root 策略 | 设置 root 账户的登录限制（禁止/仅密钥/任意） |
| Fail2ban | 自动安装并配置暴力破解防护，封禁异常 IP |
| 执行生效 | 写入配置、语法校验、重启 sshd，一键完成 |

## 安全特性

- 应用前强制检查密钥是否就绪，防止意外锁机
- 写入配置后先执行 `sshd -t` 语法检查，通过后才重启服务
- 配置语法错误时自动将问题文件重命名为 `.err`，防止下次重启生效
- 使用 Drop-in 配置文件（`/etc/ssh/sshd_config.d/`），不直接修改主配置
- 密钥生成后默认不明文打印私钥，建议通过 `scp` 安全下载

## 系统要求

- Debian 12 (Bookworm)
- root 或 sudo 权限
- 已安装 `curl`
