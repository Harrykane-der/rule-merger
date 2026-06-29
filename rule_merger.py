import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
from typing import List, Dict, Optional, Any, Union
from contextlib import contextmanager
import re
import ipaddress
from datetime import datetime
from functools import lru_cache

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 常量定义
DOMAIN_PATTERN = re.compile(
    r'^(?:\.?(\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))'
    r'(?:\.(?:\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$'
)
PORT_PATTERN = re.compile(r'^\d+(?:-\d+)?$')

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'
SING_BOX_RULESET_VERSION = 5
SING_BOX_LIST_FIELDS = (
    'domain', 'domain_suffix', 'domain_keyword',
    'domain_regex', 'ip_cidr', 'port', 'network'
)

# Classical 类型到 Sing‑Box 字段的映射
CLASSICAL_TO_SB = {
    'DOMAIN': 'domain',
    'DOMAIN-SUFFIX': 'domain_suffix',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'PORT': 'port',
    'DST-PORT': 'port',
    'NETWORK': 'network'
}


class RulesMerger:
    """规则合并器：从多种来源读取规则，在不同格式间转换并输出"""

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.mihomo_path = MIHOMO_PATH
        self.sing_box_path = SING_BOX_PATH
        # 转换器映射：键为 (source_behavior, target_behavior)
        self._transformers = {
            ('classical', 'ipcidr'): self._classical_to_ipcidr,
            ('classical', 'domain'): self._classical_to_domain,
            ('ipcidr', 'classical'): self._ipcidr_to_classical,
            ('domain', 'classical'): self._domain_to_classical,
            ('classical', 'sing-box'): self._classical_to_sing_box,
            ('domain', 'sing-box'): self._domain_to_sing_box,
            ('ipcidr', 'sing-box'): self._ipcidr_to_sing_box,
            ('sing-box', 'classical'): self._sing_box_to_classical,
            ('sing-box', 'domain'): self._sing_box_to_domain,
            ('sing-box', 'ipcidr'): self._sing_box_to_ipcidr
        }

    # -------------------- 通用工具方法 --------------------
    @staticmethod
    def _normalize_behavior(behavior: Optional[str]) -> str:
        """统一 behavior 命名规范"""
        if not behavior:
            return 'classical'
        b = behavior.strip().lower()
        return 'sing-box' if b in ('singbox', 'sing-box') else b

    @staticmethod
    def _load_config(path: str) -> dict:
        """加载 YAML 配置文件"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            raise

    @contextmanager
    def _temp_file(self, suffix: str):
        """上下文管理器，创建临时文件并自动删除"""
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        try:
            yield path
        finally:
            if os.path.exists(path):
                os.unlink(path)

    @staticmethod
    def _as_list(value: Any) -> List[Any]:
        """将值转换为列表，若为 None 则返回空列表"""
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _clean_rule(rule: str) -> str:
        """清除规则中的注释和首尾空白"""
        rule = rule.strip()
        if rule.startswith('#'):
            return ''
        parts = re.split(r'\s+#', rule)
        return parts[0].strip() if len(parts) > 1 else rule

    @staticmethod
    @lru_cache(maxsize=1024)
    def _get_ipcidr_version(rule: str) -> Optional[int]:
        """获取 IP/CIDR 的版本（4或6），无效则返回 None"""
        try:
            return ipaddress.ip_network(rule, strict=False).version
        except ValueError:
            return None

    def _validate_ipcidr_rule(self, rule: str) -> Optional[str]:
        return rule if self._get_ipcidr_version(rule) else None

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        domain = rule[2:] if rule.startswith('+.') else rule
        return rule if DOMAIN_PATTERN.match(domain) else None

    # -------------------- 规则获取与解析 --------------------
    def _fetch_rules_from_source(self, source: Dict, target_behavior: str) -> List[Any]:
        """从单个 source 获取规则列表"""
        rule_format = source.get('format', 'yaml')
        default_behavior = 'sing-box' if rule_format in ('json', 'srs') else 'classical'
        source_behavior = self._normalize_behavior(source.get('behavior', default_behavior))
        target_behavior = self._normalize_behavior(target_behavior)

        source_type = source.get('type')
        if source_type == 'http':
            url = source.get('url', '')
            raw_rules = self._fetch_http_rules(url, rule_format, source_behavior)
        elif source_type == 'file':
            path = source.get('path', '')
            raw_rules = self._read_local_rules(path, rule_format, source_behavior)
        else:
            return []

        # 预处理字符串规则：清理并转换 *. 为 +.
        converted = []
        for rule in raw_rules:
            if rule is None:
                continue
            if isinstance(rule, str):
                cleaned = self._clean_rule(rule)
                if cleaned.startswith('*.'):
                    cleaned = '+.' + cleaned[2:]
                rule = cleaned
            # 转换为目标格式
            transformed = self._transform(rule, source_behavior, target_behavior)
            if transformed:
                converted.extend(transformed)
        return converted

    def _fetch_http_rules(self, url: str, rule_format: str, behavior: str) -> List[Any]:
        """从 HTTP 获取规则"""
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            content = resp.text
            if rule_format == 'json':
                return self._parse_sing_box_source_to_list(content)
            if rule_format == 'srs':
                with self._temp_file('.srs') as tmp_srs:
                    with open(tmp_srs, 'wb') as f:
                        f.write(resp.content)
                    decompiled = self._decompile_srs_to_json_str(tmp_srs)
                    return self._parse_sing_box_source_to_list(decompiled)
            # 判断是否为 YAML
            content_type = resp.headers.get('content-type', '')
            is_yaml = (rule_format == 'yaml') or (
                rule_format not in ('mrs', 'text', 'json', 'srs') and
                ('yaml' in content_type or url.endswith(('.yml', '.yaml')))
            )
            if is_yaml:
                data = yaml.safe_load(content)
                return self._extract_yaml_rules(data, url)
            if rule_format == 'mrs':
                with self._temp_file('.mrs') as tmp_mrs:
                    with open(tmp_mrs, 'wb') as f:
                        f.write(resp.content)
                    return self._read_mrs_file(tmp_mrs, behavior)
            # 默认按文本处理
            return content.splitlines()
        except Exception as e:
            logger.error(f"获取在线规则失败 {url}: {e}")
            return []

    def _read_local_rules(self, path: str, rule_format: str, behavior: str) -> List[Any]:
        """从本地文件读取规则"""
        try:
            if rule_format == 'mrs':
                return self._read_mrs_file(path, behavior)
            if rule_format == 'srs':
                decompiled = self._decompile_srs_to_json_str(path)
                return self._parse_sing_box_source_to_list(decompiled)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if rule_format == 'json':
                    return self._parse_sing_box_source_to_list(content)
                if rule_format == 'yaml':
                    data = yaml.safe_load(content)
                    return self._extract_yaml_rules(data, path)
                return content.splitlines()
        except Exception as e:
            logger.error(f"读取本地规则失败 {path}: {e}")
            return []

    def _parse_sing_box_source_to_list(self, content: str) -> List[Dict[str, Any]]:
        """解析 sing-box JSON 源为规则列表"""
        try:
            data = json.loads(content.lstrip('\ufeff'))
            if isinstance(data, dict) and 'rules' in data and isinstance(data['rules'], list):
                return data['rules']
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError as e:
            logger.error(f"解析 sing-box JSON 失败: {e}")
            return []

    @staticmethod
    def _extract_yaml_rules(data: Any, source: str) -> List[str]:
        """从 YAML 中提取 payload 列表"""
        if isinstance(data, dict):
            payload = data.get('payload')
            return payload if isinstance(payload, list) else []
        if isinstance(data, list):
            return data
        return []

    # -------------------- 规则转换核心 --------------------
    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        """将单条规则从源行为转换为目标行为"""
        source_behavior = self._normalize_behavior(source_behavior)
        target_behavior = self._normalize_behavior(target_behavior)

        # 处理 dict 类型（原生 sing‑box 规则）
        if isinstance(rule, dict):
            if target_behavior == 'sing-box':
                return [rule]  # 无需转换
            # 转换为字符串再调用反向转换器
            transformer = self._transformers.get(('sing-box', target_behavior))
            if transformer:
                return transformer(json.dumps(rule))
            return []

        if not rule:
            return []
        if source_behavior == target_behavior:
            return [rule]

        transformer = self._transformers.get((source_behavior, target_behavior))
        if not transformer:
            return []
        result = transformer(rule)
        return result if isinstance(result, list) else [result] if result else []

    # -------------------- 格式间转换器（私有） --------------------
    # Classical ↔ Domain/IPCIDR
    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2:
            return None
        prefix = parts[0].strip()
        if prefix not in ('IP-CIDR', 'IP-CIDR6'):
            return None
        return self._validate_ipcidr_rule(parts[1].strip())

    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2:
            return None
        prefix, domain = parts[0].strip(), parts[1].strip()
        if not DOMAIN_PATTERN.match(domain):
            return None
        if prefix == 'DOMAIN':
            return domain
        if prefix == 'DOMAIN-SUFFIX':
            return '+.' + domain
        return None

    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        v = self._get_ipcidr_version(rule)
        if v == 4:
            return f"IP-CIDR,{rule}"
        if v == 6:
            return f"IP-CIDR6,{rule}"
        return None

    def _domain_to_classical(self, rule: str) -> Optional[str]:
        if rule.startswith('+.'):
            domain = rule[2:]
            return f"DOMAIN-SUFFIX,{domain}" if DOMAIN_PATTERN.match(domain) else None
        return f"DOMAIN,{rule}" if DOMAIN_PATTERN.match(rule) else None

    # Classical → Sing‑Box
    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple]:
        """将规则转换为 (field, value) 元组，用于 sing‑box"""
        if behavior == 'domain':
            if rule.startswith('+.'):
                return ('domain_suffix', rule[2:])
            return ('domain', rule)
        if behavior == 'ipcidr':
            return ('ip_cidr', rule)
        if behavior != 'classical':
            return None
        parts = [p.strip() for p in rule.split(',')]
        if len(parts) < 2:
            return None
        field = CLASSICAL_TO_SB.get(parts[0])
        if not field:
            return None
        value = parts[1]
        if field == 'port':
            value = int(value) if value.isdigit() else value
        elif field == 'network':
            value = value.lower()
        return (field, value)

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_classical_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'classical')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _domain_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_domain_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'domain')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _ipcidr_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_ipcidr_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'ipcidr')
        return json.dumps({item[0]: [item[1]]}) if item else None

    # Sing‑Box → Classical/Domain/IPCIDR
    def _parse_sing_box_rule(self, rule_str: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = json.loads(rule_str)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None

    def _iter_sing_box_rules(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """递归展开 logical 规则"""
        rules = [rule]
        if rule.get('type') == 'logical':
            for nested in self._as_list(rule.get('rules')):
                if isinstance(nested, dict):
                    rules.extend(self._iter_sing_box_rules(nested))
        return rules

    def _sing_box_to_domain(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed:
            return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            for d in self._as_list(item.get('domain')):
                result.append(str(d))
            for s in self._as_list(item.get('domain_suffix')):
                s = s[1:] if s.startswith('.') else s
                result.append(f"+.{s}")
        return result

    def _sing_box_to_ipcidr(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed:
            return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            for ip in self._as_list(item.get('ip_cidr')):
                result.append(str(ip))
        return result

    def _sing_box_to_classical(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed:
            return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            for d in self._as_list(item.get('domain')):
                result.append(f"DOMAIN,{d}")
            for s in self._as_list(item.get('domain_suffix')):
                s = s[1:] if s.startswith('.') else s
                result.append(f"DOMAIN-SUFFIX,{s}")
            for k in self._as_list(item.get('domain_keyword')):
                result.append(f"DOMAIN-KEYWORD,{k}")
            for r in self._as_list(item.get('domain_regex')):
                result.append(f"DOMAIN-REGEX,{r}")
            for ip in self._as_list(item.get('ip_cidr')):
                prefix = "IP-CIDR6" if ':' in str(ip) else "IP-CIDR"
                result.append(f"{prefix},{ip}")
            for p in self._as_list(item.get('port')):
                result.append(f"PORT,{p}")
            for n in self._as_list(item.get('network')):
                result.append(f"NETWORK,{str(n).lower()}")
        return result

    def _validate_classical_rule(self, rule: str) -> Optional[str]:
        """验证 classical 规则格式，返回规范化后的字符串或 None"""
        try:
            parts = [p.strip() for p in rule.split(',')]
            if len(parts) < 2:
                return None
            prefix, value = parts[0], parts[1]
            if prefix in ('DOMAIN', 'DOMAIN-SUFFIX'):
                return rule if DOMAIN_PATTERN.match(value) else None
            if prefix == 'IP-CIDR':
                return rule if self._get_ipcidr_version(value) == 4 else None
            if prefix == 'IP-CIDR6':
                return rule if self._get_ipcidr_version(value) == 6 else None
            if prefix in ('PORT', 'DST-PORT'):
                return rule if PORT_PATTERN.match(value) else None
            if prefix == 'NETWORK':
                return rule if value.lower() in ('tcp', 'udp') else None
            return rule
        except Exception:
            return None

    # -------------------- 规则合并与输出 --------------------
    def merge_rules(self) -> None:
        """主流程：合并所有上游规则并输出"""
        for config in self.config:
            if 'upstream' not in config or not config.get('path'):
                continue

            target_format = config.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'classical'
            target_behavior = self._normalize_behavior(config.get('behavior', default_behavior))

            # 收集所有规则
            raw_rules = []
            for source_config in config['upstream'].values():
                rules = self._fetch_rules_from_source(source_config, target_behavior)
                raw_rules.extend(rules)

            # 区分 dict 规则和字符串规则
            dict_rules = [r for r in raw_rules if isinstance(r, dict)]
            str_rules = [r for r in raw_rules if isinstance(r, str)]

            # 字符串规则去重并排序
            str_rules = sorted(set(str_rules))

            final_rules = []
            if target_behavior == 'sing-box':
                final_rules = self._compile_final_sing_box_list(str_rules, dict_rules)
            else:
                final_rules = str_rules

            output_file = config['path']
            self._write_rules(
                output_file,
                final_rules,
                target_format,
                target_behavior,
                config.get('version', SING_BOX_RULESET_VERSION)
            )

    def _compile_final_sing_box_list(self, converted_str_rules: List[str],
                                     original_dict_rules: List[Dict]) -> List[Dict]:
        """将字符串规则（JSON 片段）合并压缩，并与原始 dict 规则合并"""
        bucket = {key: [] for key in SING_BOX_LIST_FIELDS}
        passthrough_rules = []

        for rule_str in converted_str_rules:
            parsed = self._parse_sing_box_rule(rule_str)
            if not parsed:
                continue
            if self._can_compact_sing_box_rule(parsed):
                self._add_sing_box_rule_items(bucket, parsed)
            else:
                passthrough_rules.append(parsed)

        compacted = self._compact_sing_box_rules(bucket)
        all_rules = compacted + passthrough_rules + original_dict_rules

        # 去重（基于 JSON 序列化签名）
        seen = set()
        unique = []
        for r in all_rules:
            sig = json.dumps(r, ensure_ascii=False, sort_keys=True)
            if sig not in seen:
                seen.add(sig)
                unique.append(r)
        return unique

    def _can_compact_sing_box_rule(self, rule: Dict[str, Any]) -> bool:
        """判断一条 sing‑box 规则是否可被压缩（不含 logical 且所有值都是简单类型）"""
        if rule.get('type') == 'logical':
            return False
        for key, value in rule.items():
            if key not in SING_BOX_LIST_FIELDS:
                return False
            values = self._as_list(value)
            if values and not all(isinstance(v, (str, int)) for v in values):
                return False
        return True

    def _add_sing_box_rule_items(self, bucket: Dict[str, List[Any]], rule: Dict[str, Any]) -> None:
        """将规则中的字段值添加到对应的桶中"""
        for key in SING_BOX_LIST_FIELDS:
            if key in rule:
                raw = self._as_list(rule[key])
                if key == 'port':
                    cleaned = [int(v) if str(v).isdigit() else v for v in raw]
                elif key == 'network':
                    cleaned = [str(v).lower() for v in raw]
                else:
                    cleaned = raw
                bucket[key].extend(cleaned)

    def _compact_sing_box_rules(self, bucket: Dict[str, List[Any]]) -> List[Dict[str, List[Any]]]:
        """将桶中的值去重排序后生成独立的规则"""
        compacted = []
        for key in SING_BOX_LIST_FIELDS:
            values = bucket.get(key, [])
            if not values:
                continue
            unique = list(set(values))
            if key == 'port':
                has_range = any(isinstance(v, str) and not v.isdigit() for v in unique)
                if has_range:
                    sorted_vals = sorted(str(v) for v in unique)
                else:
                    sorted_vals = sorted(int(v) for v in unique)
            else:
                sorted_vals = sorted(unique, key=lambda x: str(x))
            compacted.append({key: sorted_vals})
        return compacted

    def _write_rules(self, output_path: str, rules: List[Any], rule_format: str,
                     behavior: str, version: int) -> None:
        """将规则写入文件，支持多种格式"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if rule_format == 'mrs':
            with self._temp_file('.tmp') as tmp:
                self._write_rules(tmp, rules, 'text', behavior, version)
                if self._convert_to_mrs(tmp, output_path, behavior):
                    logger.info(f"已生成 mrs 规则文件: {output_path}, 共 {len(rules)} 条")
            return

        if rule_format == 'srs':
            with self._temp_file('.json') as tmp_json:
                self._write_sing_box_source_direct(tmp_json, rules, version)
                if self._convert_to_srs(tmp_json, output_path):
                    logger.info(f"已生成 srs 二进制规则文件: {output_path}")
            return

        if rule_format == 'json':
            self._write_sing_box_source_direct(output_path, rules, version)
            logger.info(f"已生成 json 规则文件: {output_path}")
            return

        # YAML 或纯文本
        with open(output_path, 'w', encoding='utf-8') as f:
            if not output_path.endswith('.tmp'):
                f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 规则数量: {len(rules)}\n")
            if rule_format == 'yaml':
                yaml_str = yaml.dump({'payload': rules}, allow_unicode=True,
                                     indent=2, default_flow_style=False, sort_keys=False)
                f.write(yaml_str)
            else:
                for r in rules:
                    f.write(f"{r}\n")
        logger.info(f"已生成 {rule_format} 规则文件: {output_path}, 共 {len(rules)} 条")

    def _write_sing_box_source_direct(self, output_path: str, rules: List[Dict], version: int) -> None:
        """直接写入 sing‑box JSON 源文件"""
        data = {'version': version, 'rules': rules}
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')

    # -------------------- 二进制格式支持 --------------------
    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        """使用 mihomo 将 MRS 解包为文本"""
        if not self.mihomo_path:
            logger.warning("mihomo 未配置，无法读取 MRS")
            return []
        with self._temp_file('.txt') as tmp:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, tmp]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"mihomo 解包 MRS 失败: {result.stderr}")
                return []
            with open(tmp, 'r', encoding='utf-8') as f:
                return f.read().splitlines()

    def _decompile_srs_to_json_str(self, input_path: str) -> str:
        """使用 sing-box 将 SRS 反编译为 JSON 字符串"""
        if not self.sing_box_path:
            logger.warning("sing-box 未配置，无法反编译 SRS")
            return "{}"
        with self._temp_file('.json') as tmp:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', tmp, input_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"sing-box 反编译 SRS 失败: {result.stderr}")
                return "{}"
            with open(tmp, 'r', encoding='utf-8') as f:
                return f.read()

    def _convert_to_mrs(self, input_path: str, output_path: str, behavior: str) -> bool:
        """使用 mihomo 将文本规则编译为 MRS"""
        if not self.mihomo_path:
            logger.error("未找到 mihomo，无法编译 MRS")
            return False
        cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'text', input_path, output_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"mihomo 编译 MRS 失败: {result.stderr}")
            return False
        return True

    def _convert_to_srs(self, input_path: str, output_path: str) -> bool:
        """使用 sing-box 将 JSON 规则编译为 SRS"""
        if not self.sing_box_path:
            logger.error("未找到 sing-box，无法编译 SRS")
            return False
        cmd = [self.sing_box_path, 'rule-set', 'compile', '--output', output_path, input_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"sing-box 编译 SRS 失败: {result.stderr}")
            return False
        return True


def main():
    merger = RulesMerger('config.yaml')
    merger.merge_rules()


if __name__ == '__main__':
    main()
