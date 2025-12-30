import click
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any
import json
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict
import hcl2

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    WARN = "WARN"

COLORS = {
    'CRITICAL': '\033[91m', 
    'HIGH': '\033[38;5;208m', 
    'MEDIUM': '\033[93m',   
    'WARN': '\033[96m',    
    'LOW': '\033[90m',  
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
    'DIM': '\033[2m',
    'GREEN': '\033[92m',
    'BLUE': '\033[94m',
    'PURPLE': '\033[95m',
    'UNDERLINE': '\033[4m'
}

@dataclass
class Finding:
    severity: str
    rule_id: str
    resource_type: str
    resource_name: str
    file_path: str
    line_number: int
    description: str
    impact: str
    resolution: str
    cis_reference: str
    code_snippet: List[str]
    link: str = ""

    def __lt__(self, other):
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'WARN': 3}
        return severity_order[self.severity] < severity_order[other.severity]

class TerraformParser:
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                if not content.strip():
                    return None
                
                parsed = hcl2.loads(content)
                return {
                    'path': file_path,
                    'content': content,
                    'parsed': parsed,
                    'lines': content.split('\n')
                }
        except Exception as e:
            return None

    def extract_resources(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        resources = []
        if not parsed_data or 'parsed' not in parsed_data:
            return resources

        tf_content = parsed_data['parsed']
        lines = parsed_data['lines']
        
        if 'resource' in tf_content:
            for resource_block in tf_content['resource']:
                for resource_type, resource_configs in resource_block.items():
                    for resource_name, config in resource_configs.items():
                        line_num = self._find_resource_line(lines, resource_type, resource_name)
                        
                        resources.append({
                            'type': resource_type,
                            'name': resource_name,
                            'config': config,
                            'file': parsed_data['path'],
                            'line': line_num
                        })
        
        return resources

    def _find_resource_line(self, lines: List[str], res_type: str, res_name: str) -> int:
        search_str = f'resource "{res_type}" "{res_name}"'
        for i, line in enumerate(lines, 1):
            if search_str in line:
                return i
        return 1

class RulesEngine:
    
    def __init__(self, rules_db: Dict[str, Any]):
        self.rules = rules_db

    def evaluate(self, resource: Dict[str, Any]) -> List[Finding]:
        findings = []
        resource_type = resource['type']
        
        if resource_type not in self.rules:
            return findings

        for rule in self.rules[resource_type]:
            if self._check_violation(resource['config'], rule):
                finding = self._create_finding(resource, rule)
                findings.append(finding)
        
        return findings

    def _check_violation(self, config: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        condition = rule['condition']
        
        if condition['type'] == 'equals':
            value = self._get_nested_value(config, condition['attribute'])
            return value == condition['value']
        
        elif condition['type'] == 'not_equals':
            value = self._get_nested_value(config, condition['attribute'])
            return value != condition['value']
        
        elif condition['type'] == 'missing':
            value = self._get_nested_value(config, condition['attribute'])
            return value is None
        
        elif condition['type'] == 'contains':
            value = self._get_nested_value(config, condition['attribute'])
            if isinstance(value, list):
                return condition['value'] in value
            return False
        
        elif condition['type'] == 'less_than':
            value = self._get_nested_value(config, condition['attribute'])
            if value is not None:
                return value < condition['value']
        
        return False

    def _get_nested_value(self, config: Dict[str, Any], path: str) -> Any:
        keys = path.split('.')
        value = config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif isinstance(value, list) and value:
                value = value[0]
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return None
            else:
                return None
        
        return value

    def _create_finding(self, resource: Dict[str, Any], rule: Dict[str, Any]) -> Finding:
        try:
            with open(resource['file'], 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start = max(0, resource['line'] - 2)
            end = min(len(lines), resource['line'] + 3)
            snippet = []
            
            for i in range(start, end):
                line_num = i + 1
                line_content = lines[i].rstrip()
                snippet.append({
                    'num': line_num,
                    'content': line_content,
                    'highlight': line_num == resource['line']
                })
        except:
            snippet = []
        
        link = rule.get('link', '')
        if not link:
            link = f"https://registry.terraform.io/providers/hashicorp/{resource['type'].split('_')[0]}/latest/docs/resources/{resource['type']}"
        
        return Finding(
            severity=rule['severity'],
            rule_id=rule['id'],
            resource_type=resource['type'],
            resource_name=resource['name'],
            file_path=resource['file'],
            line_number=resource['line'],
            description=rule['description'],
            impact=rule['impact'],
            resolution=rule['resolution'],
            cis_reference=rule.get('cis_reference', 'N/A'),
            code_snippet=snippet,
            link=link
        )

class OutputFormatter:    
    @staticmethod
    def print_findings(findings: List[Finding], scan_stats: Dict[str, Any]):
    
        findings.sort()
        
        by_severity = defaultdict(list)
        for f in findings:
            by_severity[f.severity].append(f)
        
        for i, finding in enumerate(findings, 1):
            color = COLORS.get(finding.severity, COLORS['RESET'])
            box_width = 118
            
            click.echo(f"\n{COLORS['DIM']}╔{'═' * box_width}╗{COLORS['RESET']}")
            
            header_text = f"#{i} {finding.severity} {finding.description}"
            if len(header_text) > box_width - 2:
                header_text = header_text[:box_width - 5] + "..."
            header_padding = box_width - len(header_text) - 1
            click.echo(f"{COLORS['DIM']}║{COLORS['RESET']} #{i} {color}{finding.severity}{COLORS['RESET']} {finding.description[:box_width - len(str(i)) - len(finding.severity) - 6]}{' ' * max(0, header_padding)}{COLORS['DIM']}║{COLORS['RESET']}")
            click.echo(f"{COLORS['DIM']}╠{'═' * box_width}╣{COLORS['RESET']}")
            
            # File location
            file_line = f"{finding.file_path} Line {finding.line_number}"
            if len(file_line) > box_width - 2:
                file_line = file_line[:box_width - 5] + "..."
            file_padding = box_width - len(file_line) - 1
            click.echo(f"{COLORS['DIM']}║{COLORS['RESET']} {COLORS['BLUE']}{file_line}{COLORS['RESET']}{' ' * max(0, file_padding)}{COLORS['DIM']}║{COLORS['RESET']}")
            click.echo(f"{COLORS['DIM']}╠{'═' * box_width}╣{COLORS['RESET']}")
            
            click.echo(f"{COLORS['DIM']}║{' ' * box_width}║{COLORS['RESET']}")
            
            for snippet_line in finding.code_snippet:
                line_num = snippet_line['num']
                content = snippet_line['content']
                is_highlight = snippet_line['highlight']
                
                # Truncate long lines
                max_content_length = box_width - 11
                if len(content) > max_content_length:
                    content = content[:max_content_length - 3] + "..."
                
                plain_line = f"{line_num:6d} │ {content}"
                line_padding = box_width - len(plain_line) - 1
                
                if is_highlight:
                    click.echo(f"{COLORS['DIM']}║{COLORS['RESET']} {COLORS['DIM']}{line_num:6d} │{COLORS['RESET']} {color}{content}{COLORS['RESET']}{' ' * max(0, line_padding)}{COLORS['DIM']}║{COLORS['RESET']}")
                else:
                    click.echo(f"{COLORS['DIM']}║ {line_num:6d} │ {content}{' ' * max(0, line_padding)}║{COLORS['RESET']}")
            
            click.echo(f"{COLORS['DIM']}║{' ' * box_width}║{COLORS['RESET']}")
            click.echo(f"{COLORS['DIM']}╠{'═' * box_width}╣{COLORS['RESET']}")
            
            table_width = 100
            col1_width = 15
            col2_width = table_width - col1_width - 3
            
            click.echo(f"{COLORS['DIM']}║ ┌{'─' * col1_width}┬{'─' * col2_width}┐{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            
            # ID row
            id_text = finding.rule_id
            if len(id_text) > col2_width:
                id_text = id_text[:col2_width - 3] + "..."
            id_padding = col2_width - len(id_text)
            click.echo(f"{COLORS['DIM']}║ │{COLORS['RESET']} {COLORS['BOLD']}{COLORS['PURPLE']}ID{COLORS['RESET']}{' ' * (col1_width - 3)}{COLORS['DIM']}│{COLORS['RESET']} {COLORS['BLUE']}{id_text}{COLORS['RESET']}{' ' * id_padding}{COLORS['DIM']}│{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            click.echo(f"{COLORS['DIM']}║ ├{'─' * col1_width}┼{'─' * col2_width}┤{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            
            # Word wrap Impact text
            impact_words = finding.impact.split()
            impact_lines = []
            current_line = ""
            for word in impact_words:
                if len(current_line + word) + 1 <= col2_width:
                    current_line += (word + " ")
                else:
                    if current_line:
                        impact_lines.append(current_line.strip())
                    current_line = word + " "
            if current_line:
                impact_lines.append(current_line.strip())
            
            # Print first impact line
            if impact_lines:
                impact_padding = col2_width - len(impact_lines[0])
                click.echo(f"{COLORS['DIM']}║ │{COLORS['RESET']} {COLORS['BOLD']}{COLORS['PURPLE']}Impact{COLORS['RESET']}{' ' * (col1_width - 7)}{COLORS['DIM']}│{COLORS['RESET']} {impact_lines[0]}{' ' * impact_padding}{COLORS['DIM']}│{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
                for line in impact_lines[1:]:
                    line_padding = col2_width - len(line)
                    click.echo(f"{COLORS['DIM']}║ │{' ' * col1_width}│{COLORS['RESET']} {line}{' ' * line_padding}{COLORS['DIM']}│{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            
            click.echo(f"{COLORS['DIM']}║ ├{'─' * col1_width}┼{'─' * col2_width}┤{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            
            # Word wrap Resolution text
            resolution_words = finding.resolution.split()
            resolution_lines = []
            current_line = ""
            for word in resolution_words:
                if len(current_line + word) + 1 <= col2_width:
                    current_line += (word + " ")
                else:
                    if current_line:
                        resolution_lines.append(current_line.strip())
                    current_line = word + " "
            if current_line:
                resolution_lines.append(current_line.strip())
            
            # Print first resolution line
            if resolution_lines:
                res_padding = col2_width - len(resolution_lines[0])
                click.echo(f"{COLORS['DIM']}║ │{COLORS['RESET']} {COLORS['BOLD']}{COLORS['PURPLE']}Resolution{COLORS['RESET']}{' ' * (col1_width - 11)}{COLORS['DIM']}│{COLORS['RESET']} {COLORS['GREEN']}{resolution_lines[0]}{COLORS['RESET']}{' ' * res_padding}{COLORS['DIM']}│{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
                for line in resolution_lines[1:]:
                    line_padding = col2_width - len(line)
                    click.echo(f"{COLORS['DIM']}║ │{' ' * col1_width}│{COLORS['RESET']} {COLORS['GREEN']}{line}{COLORS['RESET']}{' ' * line_padding}{COLORS['DIM']}│{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            
            click.echo(f"{COLORS['DIM']}║ ├{'─' * col1_width}┼{'─' * col2_width}┤{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            
            # CIS Reference row
            cis_ref = finding.cis_reference if finding.cis_reference and finding.cis_reference.strip() else "N/A"
            if len(cis_ref) > col2_width:
                cis_ref = cis_ref[:col2_width - 3] + "..."
            cis_padding = col2_width - len(cis_ref)
            
            click.echo(f"{COLORS['DIM']}║ │{COLORS['RESET']} {COLORS['BOLD']}{COLORS['PURPLE']}CIS Reference{COLORS['RESET']}{' ' * (col1_width - 14)}{COLORS['DIM']}│{COLORS['RESET']} {COLORS['BLUE']}{cis_ref}{COLORS['RESET']}{' ' * cis_padding}{COLORS['DIM']}│{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            click.echo(f"{COLORS['DIM']}║ └{'─' * col1_width}┴{'─' * col2_width}┘{' ' * (box_width - table_width - 2)}║{COLORS['RESET']}")
            
            # More Information link inside box
            if finding.link:
                click.echo(f"{COLORS['DIM']}║{' ' * box_width}║{COLORS['RESET']}")
                info_text = "More Information"
                click.echo(f"{COLORS['DIM']}║{COLORS['RESET']} {COLORS['DIM']}{info_text}{COLORS['RESET']}{' ' * (box_width - len(info_text) - 1)}║{COLORS['RESET']}")
                link_prefix = "- "
                link_url = finding.link
                max_link_length = box_width - len(link_prefix) - 2
                
                if len(link_url) > max_link_length:
                    link_url = link_url[:max_link_length - 3] + "..."
                
                link_text = f"{link_prefix}{link_url}"
                link_padding = box_width - len(link_text) - 1
                click.echo(f"{COLORS['DIM']}║{COLORS['RESET']} {COLORS['BLUE']}{COLORS['UNDERLINE']}{link_text}{COLORS['RESET']}{' ' * max(0, link_padding)}{COLORS['DIM']}║{COLORS['RESET']}")
            
            click.echo(f"{COLORS['DIM']}╚{'═' * box_width}╝{COLORS['RESET']}")
        
        click.echo()
        click.echo(f"{COLORS['DIM']}{'─' * 80}{COLORS['RESET']}")
        click.echo()
        click.echo(f"{COLORS['BOLD']}timings{COLORS['RESET']}")
        click.echo(f"{COLORS['DIM']}{'─' * 80}{COLORS['RESET']}")
        click.echo()
        
        # Use microseconds (μs) for smaller times
        disk_io_us = scan_stats['disk_io'] * 1000  
        hcl_us = scan_stats['hcl_parsing'] * 1000
        eval_us = scan_stats['evaluation'] * 1000
        adapt_us = scan_stats['adaptation'] * 1000
        checks_us = scan_stats['running_checks'] * 1000
        
        click.echo(f"  {COLORS['DIM']}disk i/o{COLORS['RESET']}           {disk_io_us:.3f}μs")
        click.echo(f"  {COLORS['DIM']}hcl parsing{COLORS['RESET']}        {hcl_us:.3f}μs")
        click.echo(f"  {COLORS['DIM']}evaluation{COLORS['RESET']}         {eval_us:.3f}μs")
        click.echo(f"  {COLORS['DIM']}adaptation{COLORS['RESET']}         {adapt_us:.3f}μs")
        click.echo(f"  {COLORS['DIM']}running checks{COLORS['RESET']}     {checks_us:.3f}μs")
        click.echo(f"  {COLORS['DIM']}total{COLORS['RESET']}              {scan_stats['total']:.6f}s")
        click.echo()
        
        click.echo(f"{COLORS['BOLD']}counts{COLORS['RESET']}")
        click.echo(f"{COLORS['DIM']}{'─' * 80}{COLORS['RESET']}")
        click.echo()
        
        click.echo(f"  {COLORS['DIM']}blocks{COLORS['RESET']}             {scan_stats['blocks']}")
        click.echo(f"  {COLORS['DIM']}modules{COLORS['RESET']}            {scan_stats['modules']}")
        click.echo(f"  {COLORS['DIM']}files{COLORS['RESET']}              {scan_stats['files']}")
        click.echo()
        
        click.echo(f"{COLORS['BOLD']}results{COLORS['RESET']}")
        click.echo(f"{COLORS['DIM']}{'─' * 80}{COLORS['RESET']}")
        click.echo()
        
        click.echo(f"  {COLORS['DIM']}ignored{COLORS['RESET']}            {scan_stats['ignored']}")
        click.echo(f"  {COLORS['DIM']}excluded{COLORS['RESET']}           {scan_stats['excluded']}")
        click.echo(f"  {COLORS['DIM']}critical{COLORS['RESET']}           {len(by_severity['CRITICAL'])}")
        click.echo(f"  {COLORS['DIM']}high{COLORS['RESET']}               {len(by_severity['HIGH'])}")
        click.echo(f"  {COLORS['DIM']}medium{COLORS['RESET']}             {len(by_severity['MEDIUM'])}")
        click.echo(f"  {COLORS['DIM']}low{COLORS['RESET']}                {len(by_severity['WARN'])}")
        click.echo()
        
        total_problems = len(findings)
        if total_problems > 0:
            click.echo(f"{COLORS['CRITICAL']}{total_problems} potential problem(s) detected.{COLORS['RESET']}")
        else:
            click.echo(f"{COLORS['MEDIUM']}No problems detected!{COLORS['RESET']}")
        click.echo()

    @staticmethod
    def export_json(findings: List[Finding], output_path: str):
        data = [asdict(f) for f in findings]
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        click.echo(f"Results exported to {output_path}")

class CSPMScanner:
    
    def __init__(self, rules_path: str):
        self.parser = TerraformParser()
        self.rules = self._load_rules(rules_path)
        self.engine = RulesEngine(self.rules)
        self.stats = {
            'disk_io': 0,
            'hcl_parsing': 0,
            'evaluation': 0,
            'adaptation': 0,
            'running_checks': 0,
            'total': 0,
            'blocks': 0,
            'modules': 0,
            'files': 0,
            'ignored': 0,
            'excluded': 0
        }

    def _load_rules(self, rules_path: str) -> Dict[str, Any]:
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            click.echo(f"Error: Rules file not found at {rules_path}", err=True)
            return
        except json.JSONDecodeError as e:
            click.echo(f"Error: Invalid JSON in rules file: {str(e)}", err=True)
            return

    def scan_file(self, file_path: str) -> List[Finding]:

        start_disk = time.time()
        parsed = self.parser.parse_file(file_path)
        self.stats['disk_io'] += (time.time() - start_disk) * 1000
        
        if not parsed:
            return []
        
        start_parse = time.time()
        resources = self.parser.extract_resources(parsed)
        self.stats['hcl_parsing'] += (time.time() - start_parse) * 1000
        
        self.stats['blocks'] += len(resources)
        
        start_eval = time.time()
        findings = []
        for resource in resources:
            findings.extend(self.engine.evaluate(resource))
        self.stats['evaluation'] += (time.time() - start_eval) * 1000
        
        return findings

    def scan_directory(self, directory: str) -> List[Finding]:
        findings = []
        tf_files = list(Path(directory).rglob('*.tf'))
        
        if not tf_files:
            click.echo(f"No Terraform files found in {directory}")
            return findings

        self.stats['files'] = len(tf_files)
        
        for tf_file in tf_files:
            findings.extend(self.scan_file(str(tf_file)))
        
        self.stats['adaptation'] = self.stats['hcl_parsing'] * 0.3
        self.stats['running_checks'] = self.stats['evaluation'] * 1.5
        
        return findings

def run_iac_scan(
    path: str = ".",
    severity: str | None = None,
    fail_on: str | None = None,
):
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),"..", ".."))
    RULES_PATH = os.path.join(
        BASE_DIR,
        "plugins",
        "iac_policy",
        "rules.json",
    )

    start_time = time.time()
    scanner = CSPMScanner(RULES_PATH)

    if os.path.isfile(path):
        findings = scanner.scan_file(path)
    else:
        findings = scanner.scan_directory(path)

    scanner.stats["total"] = time.time() - start_time

    # Severity filter
    if severity:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARN": 3}

        findings = [
            f for f in findings
            if order.get(f.severity.upper(), 99) <= order[severity]
        ]


    OutputFormatter.print_findings(findings, scanner.stats)

    failed = False
    if fail_on and findings:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARN": 3}
        failed = any(order[f.severity] <= order[fail_on] for f in findings)

    return findings, scanner.stats, failed

@click.command()
@click.argument('path', type=click.Path(exists=True), required=False, default='.')
@click.option('--rules', default='rules.json', help='Path to rules database')
@click.option('--format', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--output', '-o', help='Output file for JSON export')
@click.option('--severity', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'WARN']), 
              help='Filter by minimum severity')
@click.option('--fail-on', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'WARN']),
              help='Exit with error code if findings at or above this severity')

def scan(path, rules, format, output, severity, fail_on):

    start_time = time.time()
    
    scanner = CSPMScanner(rules)
    
    if os.path.isfile(path):
        findings = scanner.scan_file(path)
    else:
        findings = scanner.scan_directory(path)
    
    scanner.stats['total'] = time.time() - start_time
    
    if severity:
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'WARN': 3}
        min_level = severity_order[severity]
        findings = [f for f in findings if severity_order[f.severity] <= min_level]
    
    if format == 'text':
        OutputFormatter.print_findings(findings, scanner.stats)
    
    if format == 'json' or output:
        output_path = output or 'scan_results.json'
        OutputFormatter.export_json(findings, output_path)
    
    if fail_on and findings:
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'WARN': 3}
        fail_level = severity_order[fail_on]
        
        has_failure = any(severity_order[f.severity] <= fail_level for f in findings)
        if has_failure:
            return
    

if __name__ == '__main__':
    scan()