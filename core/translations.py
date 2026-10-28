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
