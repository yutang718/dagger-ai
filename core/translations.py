"""简体中文 labels for the taxonomy, probes, pentest modules and strategies.

Kept in one place so the API can return both English and Chinese and the
console can switch language without duplicating the catalogue. Codes (OWASP /
MITRE ids) are universal and left untranslated.
"""
from __future__ import annotations

OWASP_LLM_ZH = {
    "LLM01": "提示注入", "LLM02": "敏感信息泄露", "LLM03": "供应链",
    "LLM04": "数据与模型投毒", "LLM05": "输出处理不当", "LLM06": "过度代理权限",
    "LLM07": "系统提示泄露", "LLM08": "向量与嵌入缺陷", "LLM09": "错误信息",
    "LLM10": "资源无限消耗",
}

OWASP_WEB_ZH = {
    "A01": "访问控制失效", "A02": "加密机制失效", "A03": "注入", "A04": "不安全设计",
    "A05": "安全配置错误", "A06": "易受攻击和过时的组件", "A07": "身份识别与认证失效",
    "A08": "软件与数据完整性失效", "A09": "安全日志与监控失效", "A10": "服务端请求伪造 (SSRF)",
}

STRATEGY_ZH = {
    "single_turn": "单轮扫描", "crescendo": "渐进升级（多轮）", "tree_of_attacks": "攻击树（自适应精炼）",
}

SEVERITY_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}

# Kill-chain phases for the AI pentest operator.
PHASE_ZH = {
    "recon": "侦察", "fingerprint": "指纹识别", "discovery": "内容发现",
    "vuln": "漏洞扫描", "exploit": "利用验证", "validate": "结果验证",
    "plan": "规划", "report": "报告",
}

# Per-probe Chinese name + description (built-in LLM + web probes).
PROBE_ZH = {
    "prompt_injection": ("直接提示注入", "测试不可信输入能否覆盖约束模型行为的系统/开发者指令。"),
    "system_prompt_leak": ("系统提示泄露", "测试机密系统提示能否被提取出来。"),
    "data_exfiltration": ("敏感数据窃取", "测试模型是否会泄露上下文中保存的敏感记录或密钥。"),
    "jailbreak": ("越狱 / 策略绕过", "测试对角色扮演、假设情景和抑制拒答等越狱手法的抵抗力。"),
    "agent_tool_abuse": ("智能体工具滥用（过度代理）", "测试带工具的智能体能否被诱导执行非预期命令——影响最高的大模型失陷。"),
    "sql_injection": ("SQL 注入", "测试用户输入是否未经参数化就进入了 SQL 查询。"),
    "command_injection": ("操作系统命令注入", "测试用户输入是否进入了 shell 命令。"),
    "reflected_xss": ("反射型跨站脚本", "测试用户输入是否未经编码就被反射进 HTML。"),
    "broken_access_control": ("访问控制失效（IDOR）", "测试不安全的直接对象引用 / 缺失的授权校验。"),
    "ssrf": ("服务端请求伪造", "测试 URL 参数是否允许服务器请求任意内部主机。"),
    "security_misconfiguration": ("安全配置错误", "检查是否缺失加固响应头以及栈/SQL 报错泄露。"),
    "vulnerable_components": ("易受攻击和过时的组件", "检测会便于针对已知漏洞的版本横幅泄露。"),
    "auth_failures": ("身份识别与认证失效", "用一小组默认凭据尝试登录端点。"),
    "ssti": ("服务端模板注入", "测试用户输入是否被服务端模板引擎执行（可致远程代码执行）。"),
    "cve_2024_4577": ("PHP-CGI 参数注入 (CVE-2024-4577)",
                      "测试 PHP-CGI 参数注入 RCE（CVE-2024-4577）：以软连字符 %AD 注入 -d 指令并执行良性 PHP 载荷，通过服务端计算结果验证可被利用。"),
    "cve_2021_41773": ("Apache 路径穿越 (CVE-2021-41773 / 42013)",
                       "测试 Apache 2.4.49/2.4.50 路径穿越：以编码的 ../ 越出站点根目录，读取系统文件以验证（良性）。"),
    "security_gateway": ("安全网关 / WAF 前置",
                         "识别目标是否位于安全网关/WAF/SSO 之后（跳转登录、抹掉指纹头、拦截探测），"
                         "以解释为何指纹识别（如 PHP）与漏洞探测在该 URL 下无结果，并给出应对建议。"),
    "php_fingerprint": ("PHP 指纹（不依赖响应头）",
                        "现代 PHP 默认 expose_php=Off，响应头不暴露版本/身份。此探针用行为特征判断 PHP："
                        "会话 Cookie 名（PHPSESSID、laravel_session、ci_session 等）、.php 处理行为、框架指纹路径。"),
    "cve_2026_109618": ("PHP2Shell RCE (CVE-2026-109618 / 109619)",
                        "基于版本的 PHP2Shell 检测：CVE-2026-109618（内存破坏）/ CVE-2026-109619（释放后使用）是 "
                        "PHP 核心 5.4–8.5.11 的严重未授权 RCE，正被在野利用。此探针仅从响应头识别 PHP 版本并标记"
                        "易受攻击版本，不进行利用。修复：升级到 8.5.12/8.4.27/8.3.36/8.2.35 及以上。"),
}

# Pentest module Chinese names (keyed by module id from operator.MODULES).
MODULE_ZH = {
    "recon_nmap": "Nmap 端口与服务侦察",
    "recon_subfinder": "Subfinder 子域名枚举",
    "probe_httpx": "httpx Web 探测 / 技术识别",
    "fingerprint_whatweb": "WhatWeb 指纹识别",
    "waf_wafw00f": "WAFW00F WAF 检测",
    "tls_sslscan": "sslscan TLS/SSL 分析",
    "discovery_ffuf": "ffuf 内容发现",
    "crawl_katana": "Katana 爬取 / URL 发现",
    "endpoints_js": "JS 接口 / 页面发现",
    "urls_gau": "gau 历史 URL 发现",
    "params_arjun": "arjun 隐藏参数发现",
    "vuln_nuclei": "Nuclei 漏洞扫描",
    "vuln_nikto": "Nikto Web 服务器扫描",
    "tls_testssl": "testssl.sh TLS 漏洞扫描",
    "cms_wpscan": "wpscan WordPress 扫描",
    "sqli_sqlmap": "sqlmap SQL 注入验证",
    "xss_dalfox": "dalfox XSS 验证",
    "cmdi_commix": "commix 命令注入验证",
    "secrets_gitsecrets": "暴露的 .git → 密钥扫描",
    "web_probes": "内置 Web 探针（OWASP）",
}
