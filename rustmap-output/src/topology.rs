// ---------------------------------------------------------------------------
// Network topology graph generation
// ---------------------------------------------------------------------------
//
// Builds a graph from scan results (hosts + traceroute data) and exports it
// in DOT (Graphviz), GraphML, or JSON format.

use std::collections::HashMap;
use std::net::IpAddr;

use rustmap_types::{HostStatus, PortState, ScanResult};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Scanner,
    Router,
    Target,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyNode {
    pub id: String,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub node_type: NodeType,
    pub open_ports: Vec<u16>,
    pub os_info: Option<String>,
    pub services: HashMap<u16, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyEdge {
    pub from: String,
    pub to: String,
    pub ttl: u8,
    pub rtt_ms: Option<f64>,
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyGraph {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

impl TopologyGraph {
    /// Build a topology graph from a completed scan result.
    pub fn from_scan_result(result: &ScanResult) -> Self {
        let mut node_map: HashMap<String, TopologyNode> = HashMap::new();
        let mut edge_map: HashMap<(String, String), TopologyEdge> = HashMap::new();

        // Create scanner node
        node_map.insert(
            "scanner".into(),
            TopologyNode {
                id: "scanner".into(),
                ip: None,
                hostname: None,
                node_type: NodeType::Scanner,
                open_ports: vec![],
                os_info: None,
                services: HashMap::new(),
            },
        );

        for host_result in &result.hosts {
            if !matches!(host_result.host_status, HostStatus::Up | HostStatus::Unknown) {
                continue;
            }

            let target_ip = host_result.host.ip;
            let target_id = target_ip.to_string();

            // Collect open ports and services
            let mut open_ports = Vec::new();
            let mut services = HashMap::new();
            for port in &host_result.ports {
                if matches!(port.state, PortState::Open | PortState::OpenFiltered) {
                    open_ports.push(port.number);
                    if let Some(ref svc) = port.service {
                        services.insert(port.number, svc.clone());
                    }
                }
            }

            // OS info
            let os_info = host_result.os_fingerprint.as_ref().and_then(|os| {
                match (&os.os_family, &os.os_generation) {
                    (Some(fam), Some(ver)) => Some(format!("{fam} {ver}")),
                    (Some(fam), None) => Some(fam.clone()),
                    _ => None,
                }
            });

            // Create target node
            node_map.insert(
                target_id.clone(),
                TopologyNode {
                    id: target_id.clone(),
                    ip: Some(target_ip),
                    hostname: host_result.host.hostname.clone(),
                    node_type: NodeType::Target,
                    open_ports,
                    os_info,
                    services,
                },
            );

            // Process traceroute hops
            if let Some(ref trace) = host_result.traceroute {
                let mut prev_id = "scanner".to_string();

                for hop in &trace.hops {
                    let hop_id = if let Some(ip) = hop.ip {
                        let id = ip.to_string();

                        // Don't create a router node for the target itself
                        if id != target_id {
                            node_map.entry(id.clone()).or_insert_with(|| TopologyNode {
                                id: id.clone(),
                                ip: Some(ip),
                                hostname: hop.hostname.clone(),
                                node_type: NodeType::Router,
                                open_ports: vec![],
                                os_info: None,
                                services: HashMap::new(),
                            });
                        }

                        id
                    } else {
                        // Unknown hop — keyed by target + TTL to avoid collisions
                        let id = format!("unknown-{target_id}-ttl-{}", hop.ttl);
                        node_map.entry(id.clone()).or_insert_with(|| TopologyNode {
                            id: id.clone(),
                            ip: None,
                            hostname: None,
                            node_type: NodeType::Unknown,
                            open_ports: vec![],
                            os_info: None,
                            services: HashMap::new(),
                        });
                        id
                    };

                    let rtt_ms = hop.rtt.map(|d| d.as_secs_f64() * 1000.0);

                    // Merge duplicate edges (same from→to) by incrementing weight
                    let edge_key = (prev_id.clone(), hop_id.clone());
                    match edge_map.get_mut(&edge_key) {
                        Some(existing) => {
                            existing.weight += 1;
                            if let Some(rtt) = rtt_ms {
                                existing.rtt_ms = Some(
                                    existing
                                        .rtt_ms
                                        .map_or(rtt, |prev| if rtt < prev { rtt } else { prev }),
                                );
                            }
                        }
                        None => {
                            edge_map.insert(edge_key, TopologyEdge {
                                from: prev_id.clone(),
                                to: hop_id.clone(),
                                ttl: hop.ttl,
                                rtt_ms,
                                weight: 1,
                            });
                        }
                    }

                    prev_id = hop_id;
                }

                // Edge from last hop to target (if last hop isn't the target)
                if prev_id != target_id {
                    let edge_key = (prev_id.clone(), target_id.clone());
                    match edge_map.get_mut(&edge_key) {
                        Some(existing) => {
                            existing.weight += 1;
                        }
                        None => {
                            edge_map.insert(edge_key, TopologyEdge {
                                from: prev_id,
                                to: target_id,
                                ttl: 0,
                                rtt_ms: None,
                                weight: 1,
                            });
                        }
                    }
                }
            } else {
                // No traceroute — direct edge from scanner to target
                let edge_key = ("scanner".to_string(), target_id.clone());
                edge_map.entry(edge_key).or_insert_with(|| TopologyEdge {
                    from: "scanner".into(),
                    to: target_id,
                    ttl: 0,
                    rtt_ms: None,
                    weight: 1,
                });
            }
        }

        let nodes: Vec<_> = node_map.into_values().collect();
        let edges: Vec<_> = edge_map.into_values().collect();
        TopologyGraph { nodes, edges }
    }
}

// ---------------------------------------------------------------------------
// DOT (Graphviz) output
// ---------------------------------------------------------------------------

pub fn format_dot(graph: &TopologyGraph) -> String {
    let mut out = String::from("digraph topology {\n");
    out.push_str("    rankdir=LR;\n");
    out.push_str("    node [fontname=\"Helvetica\"];\n");
    out.push_str("    edge [fontname=\"Helvetica\", fontsize=10];\n\n");

    for node in &graph.nodes {
        let (shape, fill) = match node.node_type {
            NodeType::Scanner => ("diamond", "#4a90d9"),
            NodeType::Router => ("ellipse", "#f5d76e"),
            NodeType::Target => ("box", "#7ec87e"),
            NodeType::Unknown => ("point", "#cccccc"),
        };

        let label = if node.node_type == NodeType::Unknown {
            format!("*ttl {}", dot_escape(&node.id))
        } else {
            let mut parts = Vec::new();
            if let Some(ref ip) = node.ip {
                parts.push(ip.to_string());
            } else if node.node_type == NodeType::Scanner {
                parts.push("Scanner".into());
            }
            if let Some(ref host) = node.hostname {
                parts.push(dot_escape(host));
            }
            if !node.open_ports.is_empty() {
                let port_str: Vec<String> =
                    node.open_ports.iter().map(|p| p.to_string()).collect();
                parts.push(format!("ports: {}", port_str.join(",")));
            }
            if let Some(ref os) = node.os_info {
                parts.push(dot_escape(os));
            }
            parts.join("\\n")
        };

        let id = dot_escape(&node.id);
        out.push_str(&format!(
            "    \"{id}\" [label=\"{label}\", shape={shape}, style=filled, fillcolor=\"{fill}\"];\n"
        ));
    }

    out.push('\n');

    for edge in &graph.edges {
        let from = dot_escape(&edge.from);
        let to = dot_escape(&edge.to);

        let mut label_parts = Vec::new();
        if edge.ttl > 0 {
            label_parts.push(format!("ttl:{}", edge.ttl));
        }
        if let Some(rtt) = edge.rtt_ms {
            label_parts.push(format!("{:.1}ms", rtt));
        }
        if edge.weight > 1 {
            label_parts.push(format!("x{}", edge.weight));
        }

        let label = dot_escape(&label_parts.join(" "));
        if label.is_empty() {
            out.push_str(&format!("    \"{from}\" -> \"{to}\";\n"));
        } else {
            out.push_str(&format!(
                "    \"{from}\" -> \"{to}\" [label=\"{label}\"];\n"
            ));
        }
    }

    out.push_str("}\n");
    out
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('{', "\\{")
     .replace('}', "\\}")
     .replace('|', "\\|")
     .replace('<', "\\<")
     .replace('>', "\\>")
}

// ---------------------------------------------------------------------------
// GraphML output
// ---------------------------------------------------------------------------

pub fn format_graphml(graph: &TopologyGraph) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\"\n\
         \x20        xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n\
         \x20        xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\">\n",
    );

    // Key declarations
    out.push_str("  <key id=\"ip\" for=\"node\" attr.name=\"ip\" attr.type=\"string\"/>\n");
    out.push_str(
        "  <key id=\"hostname\" for=\"node\" attr.name=\"hostname\" attr.type=\"string\"/>\n",
    );
    out.push_str("  <key id=\"type\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n");
    out.push_str(
        "  <key id=\"open_ports\" for=\"node\" attr.name=\"open_ports\" attr.type=\"string\"/>\n",
    );
    out.push_str("  <key id=\"os\" for=\"node\" attr.name=\"os\" attr.type=\"string\"/>\n");
    out.push_str(
        "  <key id=\"services\" for=\"node\" attr.name=\"services\" attr.type=\"string\"/>\n",
    );
    out.push_str("  <key id=\"ttl\" for=\"edge\" attr.name=\"ttl\" attr.type=\"int\"/>\n");
    out.push_str(
        "  <key id=\"rtt_ms\" for=\"edge\" attr.name=\"rtt_ms\" attr.type=\"double\"/>\n",
    );
    out.push_str(
        "  <key id=\"weight\" for=\"edge\" attr.name=\"weight\" attr.type=\"int\"/>\n",
    );

    out.push_str("  <graph id=\"topology\" edgedefault=\"directed\">\n");

    // Nodes
    for node in &graph.nodes {
        let id = xml_escape(&node.id);
        out.push_str(&format!("    <node id=\"{id}\">\n"));

        let type_str = match node.node_type {
            NodeType::Scanner => "scanner",
            NodeType::Router => "router",
            NodeType::Target => "target",
            NodeType::Unknown => "unknown",
        };
        out.push_str(&format!(
            "      <data key=\"type\">{type_str}</data>\n"
        ));

        if let Some(ref ip) = node.ip {
            out.push_str(&format!(
                "      <data key=\"ip\">{}</data>\n",
                xml_escape(&ip.to_string())
            ));
        }
        if let Some(ref host) = node.hostname {
            out.push_str(&format!(
                "      <data key=\"hostname\">{}</data>\n",
                xml_escape(host)
            ));
        }
        if !node.open_ports.is_empty() {
            let ports: Vec<String> =
                node.open_ports.iter().map(|p| p.to_string()).collect();
            out.push_str(&format!(
                "      <data key=\"open_ports\">{}</data>\n",
                ports.join(",")
            ));
        }
        if let Some(ref os) = node.os_info {
            out.push_str(&format!(
                "      <data key=\"os\">{}</data>\n",
                xml_escape(os)
            ));
        }
        if !node.services.is_empty() {
            let svc_str: Vec<String> = node
                .services
                .iter()
                .map(|(port, svc)| format!("{port}/{}", xml_escape(svc)))
                .collect();
            out.push_str(&format!(
                "      <data key=\"services\">{}</data>\n",
                svc_str.join(",")
            ));
        }

        out.push_str("    </node>\n");
    }

    // Edges
    for (i, edge) in graph.edges.iter().enumerate() {
        let from = xml_escape(&edge.from);
        let to = xml_escape(&edge.to);
        out.push_str(&format!(
            "    <edge id=\"e{i}\" source=\"{from}\" target=\"{to}\">\n"
        ));
        out.push_str(&format!(
            "      <data key=\"ttl\">{}</data>\n",
            edge.ttl
        ));
        if let Some(rtt) = edge.rtt_ms {
            out.push_str(&format!(
                "      <data key=\"rtt_ms\">{rtt:.2}</data>\n"
            ));
        }
        out.push_str(&format!(
            "      <data key=\"weight\">{}</data>\n",
            edge.weight
        ));
        out.push_str("    </edge>\n");
    }

    out.push_str("  </graph>\n");
    out.push_str("</graphml>\n");
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

pub fn format_json_graph(graph: &TopologyGraph) -> String {
    serde_json::to_string_pretty(graph).expect("TopologyGraph serialization should not fail")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use rustmap_types::{
        Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanResult, ScanType,
        TracerouteHop, TracerouteResult,
    };

    use super::*;

    fn empty_scan() -> ScanResult {
        ScanResult {
            hosts: vec![],
            scan_type: ScanType::TcpConnect,
            total_duration: Duration::from_millis(100),
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    fn host_no_traceroute(ip: &str) -> HostScanResult {
        HostScanResult {
            host: Host {
                ip: ip.parse().unwrap(),
                hostname: None,
                geo_info: None,
            },
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("http".into()),
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            }],
            scan_duration: Duration::from_millis(50),
            host_status: HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        }
    }

    fn host_with_traceroute(
        ip: &str,
        hops: Vec<(u8, Option<&str>, Option<f64>)>,
    ) -> HostScanResult {
        let trace_hops: Vec<TracerouteHop> = hops
            .into_iter()
            .map(|(ttl, hop_ip, rtt)| TracerouteHop {
                ttl,
                ip: hop_ip.map(|s| s.parse::<IpAddr>().unwrap()),
                hostname: None,
                rtt: rtt.map(|ms| Duration::from_secs_f64(ms / 1000.0)),
            })
            .collect();

        HostScanResult {
            host: Host {
                ip: ip.parse().unwrap(),
                hostname: None,
                geo_info: None,
            },
            ports: vec![Port {
                number: 22,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("ssh".into()),
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            }],
            scan_duration: Duration::from_millis(50),
            host_status: HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: Some(TracerouteResult {
                target: Host {
                    ip: ip.parse().unwrap(),
                    hostname: None,
                    geo_info: None,
                },
                hops: trace_hops,
                port: 80,
                protocol: "tcp".into(),
            }),
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        }
    }

    #[test]
    fn test_graph_from_empty_scan() {
        let result = empty_scan();
        let graph = TopologyGraph::from_scan_result(&result);

        assert_eq!(graph.nodes.len(), 1); // Scanner only
        assert_eq!(graph.edges.len(), 0);
        assert!(graph.nodes.iter().any(|n| n.node_type == NodeType::Scanner));
    }

    #[test]
    fn test_graph_single_host_no_traceroute() {
        let mut result = empty_scan();
        result.hosts.push(host_no_traceroute("192.168.1.1"));

        let graph = TopologyGraph::from_scan_result(&result);

        assert_eq!(graph.nodes.len(), 2); // Scanner + target
        assert_eq!(graph.edges.len(), 1); // Direct edge
        assert!(graph.nodes.iter().any(|n| n.node_type == NodeType::Target));

        let edge = &graph.edges[0];
        assert_eq!(edge.from, "scanner");
        assert_eq!(edge.to, "192.168.1.1");
        assert_eq!(edge.ttl, 0);
    }

    #[test]
    fn test_graph_single_host_with_traceroute() {
        let mut result = empty_scan();
        result.hosts.push(host_with_traceroute(
            "10.0.0.5",
            vec![
                (1, Some("192.168.1.1"), Some(1.0)),
                (2, Some("10.0.0.1"), Some(5.0)),
                (3, Some("10.0.0.5"), Some(8.0)),
            ],
        ));

        let graph = TopologyGraph::from_scan_result(&result);

        // Scanner + 2 routers + 1 target = 4 nodes
        assert_eq!(graph.nodes.len(), 4);
        assert_eq!(
            graph
                .nodes
                .iter()
                .filter(|n| n.node_type == NodeType::Router)
                .count(),
            2
        );

        // scanner→192.168.1.1, 192.168.1.1→10.0.0.1, 10.0.0.1→10.0.0.5
        assert_eq!(graph.edges.len(), 3);
    }

    #[test]
    fn test_graph_deduplicates_shared_routers() {
        let mut result = empty_scan();
        // Two targets sharing the same first hop router
        result.hosts.push(host_with_traceroute(
            "10.0.0.5",
            vec![
                (1, Some("192.168.1.1"), Some(1.0)),
                (2, Some("10.0.0.5"), Some(5.0)),
            ],
        ));
        result.hosts.push(host_with_traceroute(
            "10.0.0.6",
            vec![
                (1, Some("192.168.1.1"), Some(1.5)),
                (2, Some("10.0.0.6"), Some(6.0)),
            ],
        ));

        let graph = TopologyGraph::from_scan_result(&result);

        // Scanner + 1 shared router + 2 targets = 4 nodes
        assert_eq!(graph.nodes.len(), 4);

        // The shared router node should appear once
        let router_count = graph
            .nodes
            .iter()
            .filter(|n| n.id == "192.168.1.1")
            .count();
        assert_eq!(router_count, 1);

        // scanner→192.168.1.1 edge should have weight=2 (merged from two traceroutes)
        let scanner_to_router = graph
            .edges
            .iter()
            .find(|e| e.from == "scanner" && e.to == "192.168.1.1")
            .unwrap();
        assert_eq!(scanner_to_router.weight, 2);
        // Should keep minimum RTT
        assert!((scanner_to_router.rtt_ms.unwrap() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_graph_unknown_hops() {
        let mut result = empty_scan();
        result.hosts.push(host_with_traceroute(
            "10.0.0.5",
            vec![
                (1, Some("192.168.1.1"), Some(1.0)),
                (2, None, None), // Unknown hop
                (3, Some("10.0.0.5"), Some(10.0)),
            ],
        ));

        let graph = TopologyGraph::from_scan_result(&result);

        let unknown_nodes: Vec<_> = graph
            .nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Unknown)
            .collect();
        assert_eq!(unknown_nodes.len(), 1);
        assert!(unknown_nodes[0].id.starts_with("unknown-"));
    }

    #[test]
    fn test_dot_output_structure() {
        let mut result = empty_scan();
        result.hosts.push(host_no_traceroute("192.168.1.1"));

        let graph = TopologyGraph::from_scan_result(&result);
        let dot = format_dot(&graph);

        assert!(dot.starts_with("digraph topology {"));
        assert!(dot.contains("\"scanner\""));
        assert!(dot.contains("\"192.168.1.1\""));
        assert!(dot.contains("->"));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn test_graphml_well_formed() {
        let mut result = empty_scan();
        result.hosts.push(host_no_traceroute("192.168.1.1"));

        let graph = TopologyGraph::from_scan_result(&result);
        let graphml = format_graphml(&graph);

        assert!(graphml.starts_with("<?xml"));
        assert!(graphml.contains("<graphml"));
        assert!(graphml.contains("<node id="));
        assert!(graphml.contains("<edge id="));
        assert!(graphml.contains("</graphml>"));
    }

    #[test]
    fn test_json_graph_round_trips() {
        let mut result = empty_scan();
        result.hosts.push(host_with_traceroute(
            "10.0.0.5",
            vec![
                (1, Some("192.168.1.1"), Some(1.0)),
                (2, Some("10.0.0.5"), Some(5.0)),
            ],
        ));

        let graph = TopologyGraph::from_scan_result(&result);
        let json = format_json_graph(&graph);

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let nodes = parsed["nodes"].as_array().unwrap();
        let edges = parsed["edges"].as_array().unwrap();

        assert_eq!(nodes.len(), graph.nodes.len());
        assert_eq!(edges.len(), graph.edges.len());
    }
}
