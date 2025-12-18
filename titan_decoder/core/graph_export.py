"""
Graph visualization and export for Titan Decoder Engine.

This module provides functionality to export analysis trees/graphs
in various formats for visualization and analysis.
"""

from typing import Dict, Any, List
import json
from pathlib import Path


class GraphExporter:
    """Exports analysis graphs in various formats."""

    def __init__(self, nodes: List[Dict[str, Any]]):
        self.nodes = nodes
        self.node_map = {node['id']: node for node in nodes}

    def to_json(self, include_metadata: bool = True) -> str:
        """Export graph as JSON."""
        graph_data = {
            'nodes': self.nodes,
            'edges': self._build_edges(),
        }

        if include_metadata:
            graph_data['metadata'] = {
                'total_nodes': len(self.nodes),
                'max_depth': max((n.get('depth', 0) for n in self.nodes), default=0),
                'node_types': self._count_node_types(),
            }

        return json.dumps(graph_data, indent=2, default=str)

    def to_dot(self, title: str = "Titan Analysis Graph") -> str:
        """Export graph as Graphviz DOT format."""
        lines = [f'digraph "{title}" {{']
        lines.append('  rankdir=TB;')
        lines.append('  node [shape=box, style=filled];')

        # Add nodes
        for node in self.nodes:
            node_id = node['id']
            method = node.get('method', 'UNKNOWN')
            score = node.get('decode_score', 0)
            content_type = node.get('content_type', 'Unknown')
            length = node.get('decoded_length', node.get('source_length', 0))

            # Color coding based on content type and score
            color = self._get_node_color(content_type, score, node.get('pruned', False))

            label = f"{method}\\n{node_id}: {content_type}\\n{length} bytes\\nScore: {score:.3f}"
            lines.append(f'  {node_id} [label="{label}", fillcolor="{color}"];')

        # Add edges
        for edge in self._build_edges():
            source, target = edge['source'], edge['target']
            label = edge.get('label', '')
            style = 'dashed' if edge.get('type') == 'pruned' else 'solid'
            lines.append(f'  {source} -> {target} [label="{label}", style="{style}"];')

        lines.append('}')
        return '\n'.join(lines)

    def to_mermaid(self, title: str = "Titan Analysis Flow") -> str:
        """Export graph as Mermaid flowchart format."""
        lines = ['---', f'title: {title}', '---', 'flowchart TD']

        # Add nodes
        for node in self.nodes:
            node_id = node['id']
            method = node.get('method', 'UNKNOWN')
            content_type = node.get('content_type', 'Unknown')
            score = node.get('decode_score', 0)

            # Mermaid node styling
            node_type = self._get_mermaid_node_type(content_type, score, node.get('pruned', False))
            label = f"{method}<br/>{content_type}<br/>Score: {score:.3f}"
            lines.append(f'    {node_id}{node_type}["{label}"]')

        # Add edges
        for edge in self._build_edges():
            source, target = edge['source'], edge['target']
            label = edge.get('label', '')
            link_type = '-->' if not edge.get('type') == 'pruned' else '-.->'
            lines.append(f'    {source} {link_type} {target}')
            if label:
                lines[-1] += f'["{label}"]'

        return '\n'.join(lines)

    def save_json(self, filepath: Path, include_metadata: bool = True):
        """Save graph as JSON file."""
        with open(filepath, 'w') as f:
            f.write(self.to_json(include_metadata))

    def save_dot(self, filepath: Path, title: str = "Titan Analysis Graph"):
        """Save graph as DOT file."""
        with open(filepath, 'w') as f:
            f.write(self.to_dot(title))

    def save_mermaid(self, filepath: Path, title: str = "Titan Analysis Flow"):
        """Save graph as Mermaid markdown file."""
        with open(filepath, 'w') as f:
            f.write(self.to_mermaid(title))

    def _build_edges(self) -> List[Dict[str, Any]]:
        """Build edges from node relationships."""
        edges = []

        for node in self.nodes:
            parent_id = node.get('parent')
            if parent_id is not None:
                edge_type = 'pruned' if node.get('pruned', False) else 'decoded'
                edges.append({
                    'source': parent_id,
                    'target': node['id'],
                    'label': node.get('decoder_used', ''),
                    'type': edge_type
                })

        return edges

    def _count_node_types(self) -> Dict[str, int]:
        """Count different types of nodes."""
        types = {}
        for node in self.nodes:
            node_type = node.get('method', 'UNKNOWN')
            types[node_type] = types.get(node_type, 0) + 1
        return types

    def _get_node_color(self, content_type: str, score: float, pruned: bool) -> str:
        """Get Graphviz node color based on content type and score."""
        if pruned:
            return "#cccccc"  # Gray for pruned

        if content_type == "Text":
            if score > 0.5:
                return "#90EE90"  # Light green for good text
            else:
                return "#FFFFE0"  # Light yellow for text
        elif content_type == "Binary":
            if score > 0.3:
                return "#87CEEB"  # Light blue for good binary
            else:
                return "#DDA0DD"  # Plum for binary
        else:
            return "#F0F8FF"  # Alice blue for unknown

    def _get_mermaid_node_type(self, content_type: str, score: float, pruned: bool) -> str:
        """Get Mermaid node type styling."""
        if pruned:
            return '(["Pruned")'

        if content_type == "Text":
            return '(["Text")' if score > 0.5 else '(("Text"))'
        elif content_type == "Binary":
            return '(["Binary")' if score > 0.3 else '(("Binary"))'
        else:
            return '(("Unknown"))'