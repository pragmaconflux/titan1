"""YARA rule generation from detected IOCs and patterns."""

from typing import List, Dict
import re


class YARARuleGenerator:
    """Generate YARA rules from analysis results."""

    @staticmethod
    def generate_from_iocs(iocs: Dict[str, List[str]], case_name: str = "TitanCase") -> str:
        """Generate YARA rule from extracted IOCs."""
        
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', case_name)[:50]
        
        strings_section = []
        conditions = []
        
        # Add URL strings
        if iocs.get('urls'):
            for i, url in enumerate(iocs['urls'][:5]):  # Limit to 5
                safe_url = url.replace('\\', '\\\\').replace('"', '\\"')
                strings_section.append(f'    $url_{i} = "{safe_url}"')
                conditions.append(f'$url_{i}')
        
        # Add domain strings
        if iocs.get('domains'):
            for i, domain in enumerate(iocs['domains'][:5]):
                if '.' in domain:
                    strings_section.append(f'    $domain_{i} = "{domain}"')
                    conditions.append(f'$domain_{i}')
        
        # Add IP strings (with wildcards for partial matches)
        if iocs.get('ips'):
            for i, ip in enumerate(iocs['ips'][:5]):
                strings_section.append(f'    $ip_{i} = "{ip}"')
                conditions.append(f'$ip_{i}')
        
        # Add email strings
        if iocs.get('emails'):
            for i, email in enumerate(iocs['emails'][:3]):
                strings_section.append(f'    $email_{i} = "{email}"')
                conditions.append(f'$email_{i}')
        
        # Build rule
        if not conditions:
            return "# No IOCs found to generate YARA rule"
        
        condition_str = ' or '.join(conditions)
        
        rule = f'''rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule from Titan Decoder"
        author = "Titan Decoder Engine"
        case = "{case_name}"
    strings:
{chr(10).join(strings_section)}
    condition:
        {condition_str}
}}'''
        
        return rule

    @staticmethod
    def generate_from_patterns(patterns: List[str], case_name: str = "TitanCase") -> str:
        """Generate YARA rule from suspicious patterns."""
        
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', case_name)[:50]
        strings_section = []
        conditions = []
        
        for i, pattern in enumerate(patterns[:10]):
            # Convert pattern to YARA-compatible format
            safe_pattern = pattern.replace('\\', '\\\\').replace('"', '\\"')
            strings_section.append(f'    $pattern_{i} = "{safe_pattern}"')
            conditions.append(f'$pattern_{i}')
        
        if not conditions:
            return "# No patterns found"
        
        condition_str = ' or '.join(conditions)
        
        rule = f'''rule {rule_name}_Patterns {{
    meta:
        description = "Pattern-based YARA rule from Titan Decoder"
        author = "Titan Decoder Engine"
    strings:
{chr(10).join(strings_section)}
    condition:
        {condition_str}
}}'''
        
        return rule

    @staticmethod
    def generate_behavior_rule(iocs: Dict, apis: List[str], case_name: str = "TitanCase") -> str:
        """Generate behavioral detection rule."""
        
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', case_name)[:50]
        
        # Network behavior
        network_iocs = iocs.get('urls', []) + iocs.get('domains', [])
        
        # Create rule with behaviors
        behaviors = []
        
        if network_iocs:
            behaviors.append('        // Network communication attempts')
            for i, ioc in enumerate(network_iocs[:3]):
                behaviors.append(f'        // {ioc}')
        
        if apis:
            behaviors.append('        // Suspicious API calls')
            for api in apis[:5]:
                behaviors.append(f'        // {api}')
        
        behavior_str = '\n'.join(behaviors) if behaviors else '        // Generic behavior'
        
        rule = f'''rule {rule_name}_Behavior {{
    meta:
        description = "Behavioral detection rule from Titan Decoder"
        author = "Titan Decoder Engine"
        case = "{case_name}"
    condition:
{behavior_str}
}}'''
        
        return rule


class OutputFormatter:
    """Format analysis results for various output types."""

    @staticmethod
    def to_html(report: Dict, case_name: str = "Analysis Report") -> str:
        """Generate HTML report."""
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Titan Decoder - {case_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .metadata {{ background: #f9f9f9; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }}
        .node {{ background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 4px; }}
        .ioc {{ color: #d9534f; font-weight: bold; }}
        .detection {{ background: #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Titan Decoder Analysis Report</h1>
        <div class="metadata">
            <strong>Case:</strong> {case_name}<br>
            <strong>Tool:</strong> {report.get('meta', {}).get('tool', 'Titan Decoder')}<br>
            <strong>Version:</strong> {report.get('meta', {}).get('version', '2.0')}<br>
            <strong>Nodes Generated:</strong> {report.get('node_count', 0)}
        </div>
        
        <h2>Summary</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Total Nodes</td>
                <td>{report.get('node_count', 0)}</td>
            </tr>
            <tr>
                <td>IOCs Found</td>
                <td>{sum(len(v) for v in report.get('iocs', {}).values())}</td>
            </tr>
        </table>
        
        <h2>IOCs Detected</h2>
        <div id="iocs">
'''
        
        iocs = report.get('iocs', {})
        for ioc_type, values in iocs.items():
            if values:
                html += f'<h3>{ioc_type.upper()}</h3><ul>'
                for v in values[:20]:  # Limit display
                    html += f'<li><span class="ioc">{v}</span></li>'
                html += '</ul>'
        
        html += '''
        </div>
        
        <h2>Extraction Tree</h2>
        <div id="tree">
'''
        
        for node in report.get('nodes', [])[:10]:  # Limit display
            html += f'''        <div class="node">
            <strong>Node {node.get('id')}</strong> - {node.get('method')}
            <br>Decoder: {node.get('decoder_used', 'N/A')}
            <br>Content: {node.get('content_preview', '')[:100]}
        </div>
'''
        
        html += '''
        </div>
    </div>
</body>
</html>'''
        
        return html

    @staticmethod
    def to_splunk_json(report: Dict) -> List[Dict]:
        """Convert report to Splunk-compatible JSON lines."""
        
        events = []
        
        # Main event
        events.append({
            'event_type': 'titan_analysis_summary',
            'node_count': report.get('node_count', 0),
            'total_iocs': sum(len(v) for v in report.get('iocs', {}).values()),
            'analysis_time': report.get('meta', {}).get('timestamp', 'unknown'),
        })
        
        # IOC events
        for ioc_type, values in report.get('iocs', {}).items():
            for ioc in values:
                events.append({
                    'event_type': 'ioc_detected',
                    'ioc_type': ioc_type,
                    'ioc_value': ioc,
                })
        
        # Node events
        for node in report.get('nodes', []):
            events.append({
                'event_type': 'extraction_node',
                'node_id': node.get('id'),
                'decoder': node.get('decoder_used'),
                'entropy': node.get('entropy'),
                'content_type': node.get('content_type'),
            })
        
        return events

    @staticmethod
    def to_markdown(report: Dict, case_name: str = "Case Analysis") -> str:
        """Convert report to Markdown format."""
        
        md = f'''# {case_name}

## Summary

- **Tool**: {report.get('meta', {}).get('tool', 'Titan Decoder')}
- **Version**: {report.get('meta', {}).get('version', '2.0')}
- **Nodes Generated**: {report.get('node_count', 0)}
- **Total IOCs**: {sum(len(v) for v in report.get('iocs', {}).values())}

## IOCs Detected

'''
        
        iocs = report.get('iocs', {})
        for ioc_type, values in iocs.items():
            if values:
                md += f'### {ioc_type.upper()}\n\n'
                for v in values[:20]:
                    md += f'- {v}\n'
                md += '\n'
        
        md += '''## Extraction Tree

| Node | Decoder | Type | Preview |
|------|---------|------|---------|
'''
        
        for node in report.get('nodes', [])[:15]:
            preview = node.get('content_preview', 'N/A')[:50]
            md += f'''| {node.get('id')} | {node.get('decoder_used', 'N/A')} | {node.get('content_type', 'Unknown')} | {preview} |
'''
        
        return md
