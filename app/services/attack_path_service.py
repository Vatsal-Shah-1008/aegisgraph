from typing import Dict, Any, List

class AttackPathService:
    @staticmethod
    def analyze_graph_topology(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Applies Graph Theory algorithms to identify high-centrality bridge nodes,
        crown jewels, and calculate transitive multi-hop compromise paths.
        """
        adjacency: Dict[str, List[str]] = {}
        node_degrees: Dict[str, int] = {}

        for n in nodes:
            nid = n["id"]
            adjacency[nid] = []
            node_degrees[nid] = 0

        for e in edges:
            src = e["source"]
            tgt = e["target"]
            if src in adjacency and tgt in adjacency:
                adjacency[src].append(tgt)
                node_degrees[src] = node_degrees.get(src, 0) + 1
                node_degrees[tgt] = node_degrees.get(tgt, 0) + 1

        # 1. Degree Centrality (Most Connected "Bridge" Assets)
        sorted_centrality = sorted(node_degrees.items(), key=lambda x: x[1], reverse=True)
        crown_jewels = []
        for nid, deg in sorted_centrality[:3]:
            matching_node = next((n for n in nodes if n["id"] == nid), None)
            if matching_node:
                crown_jewels.append({
                    "id": nid,
                    "label": matching_node.get("label", nid),
                    "type": matching_node.get("type", "unknown"),
                    "connections": deg,
                    "centrality_score": round(deg / max(1, len(nodes) - 1), 3)
                })

        # 2. Transitive Multi-Hop Attack Path Tracing
        # Find paths starting from entry nodes (domain/subdomain) leading to sensitive nodes (open_port/cloud_bucket)
        attack_paths = []
        for n in nodes:
            if n.get("risk") in ["critical", "warning"]:
                # Path finding from root
                target_id = n["id"]
                path = [n.get("label", target_id)]
                
                # Reverse trace to origin
                current = target_id
                visited = {current}
                while True:
                    parent_edge = next((e for e in edges if e["target"] == current and e["source"] not in visited), None)
                    if parent_edge:
                        parent_node = next((pn for pn in nodes if pn["id"] == parent_edge["source"]), None)
                        if parent_node:
                            path.insert(0, parent_node.get("label", parent_edge["source"]))
                            visited.add(parent_edge["source"])
                            current = parent_edge["source"]
                            continue
                    break

                if len(path) > 1:
                    attack_paths.append({
                        "entry_point": path[0],
                        "target_asset": path[-1],
                        "hops": len(path) - 1,
                        "path_chain": " ──(transitive)──> ".join(path),
                        "risk_level": "CRITICAL" if n.get("risk") == "critical" else "HIGH"
                    })

        return {
            "total_graph_nodes": len(nodes),
            "total_graph_edges": len(edges),
            "centrality_analysis": crown_jewels,
            "transitive_attack_paths": attack_paths[:5]
        }
