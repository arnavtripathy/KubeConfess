import re
import json
import os
 
 
# ── Colour scheme ─────────────────────────────────────────────────────────────
 
NODE_COLOURS = {
    "Pod":                "#e74c3c",
    "ServiceAccount":     "#e67e22",
    "Role":               "#f39c12",
    "ClusterRole":        "#c0392b",
    "RoleBinding":        "#3498db",
    "ClusterRoleBinding": "#9b59b6",
    "Secret":             "#2ecc71",
    "Permission":         "#95a5a6",
    "Namespace":          "#1abc9c",
}
 
SEVERITY_BORDER = {
    "CRITICAL": "#ff0000",
    "HIGH":     "#ff6600",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#00cc00",
    "NONE":     "#444444",
}
 
SEVERITY_SIZE = {
    "CRITICAL": 32,
    "HIGH":     26,
    "MEDIUM":   20,
    "LOW":      16,
    "NONE":     14,
}
 
 
# ── Parsing ───────────────────────────────────────────────────────────────────
 
def extract_graph(reply: str) -> dict | None:
    """Extract graph JSON block from Claude's response."""
    match = re.search(r"```graph\s*(.*?)```", reply, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(1).strip())
        if "nodes" in data and "edges" in data:
            return data
        return None
    except json.JSONDecodeError:
        return None
 
 
def strip_graph_block(reply: str) -> str:
    """Remove graph block from response before displaying to user."""
    return re.sub(
        r"```graph\s*.*?```", "", reply, flags=re.DOTALL
    ).strip()
 
 
# ── D3.js renderer ────────────────────────────────────────────────────────────
 
def render_graph(graph: dict, output: str = "/tmp/attack_graph.html") -> str | None:
    """
    Render graph data as a self-contained D3.js HTML file.
    No external dependencies — D3 loaded from CDN with offline fallback embedded.
    Works in-cluster and externally.
    """
    if not graph.get("nodes"):
        return None
 
    # enrich nodes with colour/size metadata
    nodes = []
    for node in graph["nodes"]:
        node_type = node.get("type", "Unknown")
        severity  = node.get("severity", "NONE")
        nodes.append({
            "id":       node["id"],
            "label":    node.get("label", node["id"]),
            "type":     node_type,
            "severity": severity,
            "color":    NODE_COLOURS.get(node_type, "#ffffff"),
            "border":   SEVERITY_BORDER.get(severity, "#444444"),
            "size":     SEVERITY_SIZE.get(severity, 14),
        })
 
    edges = []
    for edge in graph.get("edges", []):
        edges.append({
            "source": edge["from"],
            "target": edge["to"],
            "label":  edge.get("label", ""),
        })
 
    nodes_json = json.dumps(nodes, indent=2)
    edges_json = json.dumps(edges, indent=2)
 
    legend_items = "\n".join(
        f'<div class="legend-item">'
        f'<span class="legend-dot" style="background:{colour}"></span>'
        f'<span>{node_type}</span>'
        f'</div>'
        for node_type, colour in NODE_COLOURS.items()
    )
 
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>KubeConfess — Attack Graph</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
 
    body {{
      background: #0d1117;
      color: #e6edf3;
      font-family: 'Courier New', monospace;
      overflow: hidden;
      height: 100vh;
      width: 100vw;
    }}
 
    /* ── Header ── */
    #header {{
      position: fixed;
      top: 0; left: 0; right: 0;
      height: 48px;
      background: #161b22;
      border-bottom: 1px solid #30363d;
      display: flex;
      align-items: center;
      padding: 0 20px;
      gap: 16px;
      z-index: 100;
    }}
 
    #header h1 {{
      font-size: 13px;
      font-weight: bold;
      color: #58a6ff;
      letter-spacing: 2px;
      text-transform: uppercase;
    }}
 
    #header .tag {{
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid;
    }}
 
    #header .tag.critical {{
      color: #ff4444;
      border-color: #ff4444;
      background: rgba(255,68,68,0.1);
    }}
 
    #node-count {{
      font-size: 11px;
      color: #8b949e;
      margin-left: auto;
    }}
 
    /* ── Canvas ── */
    #canvas {{
      position: fixed;
      top: 48px;
      left: 0;
      right: 280px;
      bottom: 0;
    }}
 
    svg {{
      width: 100%;
      height: 100%;
    }}
 
    /* ── Edges ── */
    .link {{
      stroke: #30363d;
      stroke-width: 1.5;
      stroke-opacity: 0.8;
      marker-end: url(#arrow);
    }}
 
    .link:hover {{
      stroke: #58a6ff;
      stroke-opacity: 1;
    }}
 
    .link-label {{
      fill: #8b949e;
      font-size: 9px;
      font-family: 'Courier New', monospace;
      pointer-events: none;
    }}
 
    /* ── Nodes ── */
    .node circle {{
      stroke-width: 2;
      cursor: pointer;
      transition: stroke-width 0.2s;
    }}
 
    .node circle:hover {{
      stroke-width: 4;
      stroke: #ffffff !important;
    }}
 
    .node text {{
      font-size: 11px;
      fill: #e6edf3;
      pointer-events: none;
      text-anchor: middle;
      dominant-baseline: middle;
      font-family: 'Courier New', monospace;
    }}
 
    .node .node-label {{
      font-size: 10px;
      fill: #8b949e;
      dominant-baseline: hanging;
    }}
 
    /* ── Sidebar ── */
    #sidebar {{
      position: fixed;
      top: 48px;
      right: 0;
      width: 280px;
      bottom: 0;
      background: #161b22;
      border-left: 1px solid #30363d;
      overflow-y: auto;
      padding: 16px;
    }}
 
    #sidebar h2 {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #58a6ff;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid #30363d;
    }}
 
    /* ── Legend ── */
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
      font-size: 11px;
      color: #8b949e;
    }}
 
    .legend-dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }}
 
    /* ── Node detail panel ── */
    #detail {{
      margin-top: 20px;
    }}
 
    #detail h2 {{
      color: #58a6ff;
    }}
 
    #detail-content {{
      display: none;
    }}
 
    #detail-content .detail-row {{
      margin-bottom: 8px;
      font-size: 11px;
    }}
 
    #detail-content .detail-key {{
      color: #8b949e;
      display: block;
      margin-bottom: 2px;
    }}
 
    #detail-content .detail-value {{
      color: #e6edf3;
      word-break: break-all;
    }}
 
    #detail-content .severity-badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: bold;
    }}
 
    /* ── Severity colours ── */
    .sev-CRITICAL {{ background: rgba(255,68,68,0.2);  color: #ff4444; border: 1px solid #ff4444; }}
    .sev-HIGH     {{ background: rgba(255,102,0,0.2);  color: #ff6600; border: 1px solid #ff6600; }}
    .sev-MEDIUM   {{ background: rgba(255,204,0,0.2);  color: #ffcc00; border: 1px solid #ffcc00; }}
    .sev-LOW      {{ background: rgba(0,204,0,0.2);    color: #00cc00; border: 1px solid #00cc00; }}
    .sev-NONE     {{ background: rgba(68,68,68,0.2);   color: #888888; border: 1px solid #444444; }}
 
    /* ── Controls ── */
    #controls {{
      margin-top: 20px;
      padding-top: 16px;
      border-top: 1px solid #30363d;
    }}
 
    #controls h2 {{
      margin-bottom: 10px;
    }}
 
    .ctrl-btn {{
      display: block;
      width: 100%;
      padding: 6px 10px;
      margin-bottom: 6px;
      background: #21262d;
      border: 1px solid #30363d;
      border-radius: 4px;
      color: #e6edf3;
      font-size: 11px;
      font-family: 'Courier New', monospace;
      cursor: pointer;
      text-align: left;
    }}
 
    .ctrl-btn:hover {{
      background: #30363d;
      border-color: #58a6ff;
    }}
 
    /* ── Tooltip ── */
    #tooltip {{
      position: fixed;
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 8px 12px;
      font-size: 11px;
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.15s;
      z-index: 200;
      max-width: 220px;
    }}
 
    #tooltip .tt-title {{
      font-weight: bold;
      color: #e6edf3;
      margin-bottom: 4px;
    }}
 
    #tooltip .tt-type {{
      color: #8b949e;
    }}
  </style>
</head>
<body>
 
  <!-- Header -->
  <div id="header">
    <h1>⬡ KubeConfess // Attack Graph</h1>
    <div class="tag critical">LIVE</div>
    <span id="node-count"></span>
  </div>
 
  <!-- Canvas -->
  <div id="canvas">
    <svg id="graph-svg">
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8"
                refX="20" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#30363d"/>
        </marker>
        <marker id="arrow-hover" markerWidth="8" markerHeight="8"
                refX="20" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#58a6ff"/>
        </marker>
      </defs>
    </svg>
  </div>
 
  <!-- Sidebar -->
  <div id="sidebar">
    <h2>Node Types</h2>
    <div id="legend">
      {legend_items}
    </div>
 
    <div id="detail">
      <h2>Selected Node</h2>
      <div id="detail-content">
        <div class="detail-row">
          <span class="detail-key">Label</span>
          <span class="detail-value" id="d-label"></span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Type</span>
          <span class="detail-value" id="d-type"></span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Severity</span>
          <span class="detail-value" id="d-severity"></span>
        </div>
        <div class="detail-row">
          <span class="detail-key">ID</span>
          <span class="detail-value" id="d-id" style="font-size:9px; color:#8b949e"></span>
        </div>
      </div>
      <div id="detail-empty" style="font-size:11px; color:#8b949e">
        Click a node to inspect
      </div>
    </div>
 
    <div id="controls">
      <h2>Controls</h2>
      <button class="ctrl-btn" onclick="resetZoom()">⟳ Reset zoom</button>
      <button class="ctrl-btn" onclick="reheat()">⚡ Reheat physics</button>
      <button class="ctrl-btn" onclick="pinAll()">📌 Pin all nodes</button>
      <button class="ctrl-btn" onclick="unpinAll()">⊙ Unpin all nodes</button>
    </div>
  </div>
 
  <!-- Tooltip -->
  <div id="tooltip">
    <div class="tt-title" id="tt-label"></div>
    <div class="tt-type" id="tt-type"></div>
  </div>
 
  <script>
    // ── Data ────────────────────────────────────────────────────────────────
    const rawNodes = {nodes_json};
    const rawEdges = {edges_json};
 
    // D3 needs node objects indexed by id
    const nodeMap = {{}};
    rawNodes.forEach(n => nodeMap[n.id] = n);
 
    const nodes = rawNodes.map(n => ({{ ...n }}));
    const links = rawEdges.map(e => ({{
      source: e.source,
      target: e.target,
      label:  e.label,
    }}));
 
    document.getElementById("node-count").textContent =
      `${{nodes.length}} nodes  ·  ${{links.length}} edges`;
 
    // ── SVG setup ────────────────────────────────────────────────────────────
    const svg    = d3.select("#graph-svg");
    const canvas = document.getElementById("canvas");
 
    const width  = () => canvas.clientWidth;
    const height = () => canvas.clientHeight;
 
    const g = svg.append("g");
 
    // zoom
    const zoom = d3.zoom()
      .scaleExtent([0.1, 4])
      .on("zoom", e => g.attr("transform", e.transform));
    svg.call(zoom);
 
    // ── Force simulation ──────────────────────────────────────────────────────
    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links)
        .id(d => d.id)
        .distance(200)
        .strength(0.4)
      )
      .force("charge", d3.forceManyBody()
        .strength(-600)
        .distanceMax(500)
      )
      .force("center",  d3.forceCenter(width() / 2, height() / 2))
      .force("collide",  d3.forceCollide().radius(d => d.size + 20))
      .alphaDecay(0.015);
 
    // ── Draw edges ────────────────────────────────────────────────────────────
    const linkGroup = g.append("g").attr("class", "links");
 
    const linkLine = linkGroup.selectAll("line")
      .data(links)
      .enter()
      .append("line")
      .attr("class", "link");
 
    const linkLabel = linkGroup.selectAll("text")
      .data(links)
      .enter()
      .append("text")
      .attr("class", "link-label")
      .text(d => d.label);
 
    // ── Draw nodes ────────────────────────────────────────────────────────────
    const nodeGroup = g.append("g").attr("class", "nodes");
 
    const node = nodeGroup.selectAll(".node")
      .data(nodes)
      .enter()
      .append("g")
      .attr("class", "node")
      .call(
        d3.drag()
          .on("start", dragStart)
          .on("drag",  dragging)
          .on("end",   dragEnd)
      )
      .on("click", onNodeClick)
      .on("mouseover", onNodeHover)
      .on("mouseout",  onNodeOut);
 
    // outer glow ring for CRITICAL/HIGH
    node.filter(d => ["CRITICAL", "HIGH"].includes(d.severity))
      .append("circle")
      .attr("r", d => d.size + 6)
      .attr("fill", "none")
      .attr("stroke", d => d.border)
      .attr("stroke-width", 1)
      .attr("stroke-opacity", 0.4);
 
    // main circle
    node.append("circle")
      .attr("r", d => d.size)
      .attr("fill",   d => d.color)
      .attr("stroke", d => d.border)
      .attr("stroke-width", d =>
        ["CRITICAL", "HIGH"].includes(d.severity) ? 3 : 1.5
      );
 
    // icon letter
    node.append("text")
      .attr("dy", "0.35em")
      .attr("font-size", d => Math.max(d.size * 0.7, 10))
      .attr("font-weight", "bold")
      .attr("fill", "rgba(0,0,0,0.6)")
      .text(d => d.type[0]);
 
    // label below node
    node.append("text")
      .attr("class", "node-label")
      .attr("dy", d => d.size + 14)
      .attr("font-size", 10)
      .attr("fill", "#8b949e")
      .text(d => d.label.length > 20 ? d.label.slice(0, 18) + "…" : d.label);
 
    // ── Tick ──────────────────────────────────────────────────────────────────
    sim.on("tick", () => {{
      linkLine
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);
 
      linkLabel
        .attr("x", d => (d.source.x + d.target.x) / 2)
        .attr("y", d => (d.source.y + d.target.y) / 2);
 
      node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
    }});
 
    // ── Drag ──────────────────────────────────────────────────────────────────
    function dragStart(event, d) {{
      if (!event.active) sim.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }}
    function dragging(event, d) {{
      d.fx = event.x;
      d.fy = event.y;
    }}
    function dragEnd(event, d) {{
      if (!event.active) sim.alphaTarget(0);
    }}
 
    // ── Node click — show detail panel ────────────────────────────────────────
    function onNodeClick(event, d) {{
      event.stopPropagation();
 
      document.getElementById("detail-content").style.display = "block";
      document.getElementById("detail-empty").style.display   = "none";
 
      document.getElementById("d-label").textContent = d.label;
      document.getElementById("d-type").textContent  = d.type;
      document.getElementById("d-id").textContent    = d.id;
 
      const badge = document.getElementById("d-severity");
      badge.textContent  = d.severity;
      badge.className    = `detail-value severity-badge sev-${{d.severity}}`;
 
      // highlight connected edges
      linkLine.attr("stroke", l =>
        l.source.id === d.id || l.target.id === d.id
          ? "#58a6ff" : "#30363d"
      ).attr("stroke-width", l =>
        l.source.id === d.id || l.target.id === d.id ? 2.5 : 1.5
      );
    }}
 
    svg.on("click", () => {{
      linkLine.attr("stroke", "#30363d").attr("stroke-width", 1.5);
      document.getElementById("detail-content").style.display = "none";
      document.getElementById("detail-empty").style.display   = "block";
    }});
 
    // ── Tooltip ───────────────────────────────────────────────────────────────
    const tooltip = document.getElementById("tooltip");
 
    function onNodeHover(event, d) {{
      document.getElementById("tt-label").textContent = d.label;
      document.getElementById("tt-type").textContent  = `${{d.type}} · ${{d.severity}}`;
      tooltip.style.opacity = 1;
      tooltip.style.left    = (event.clientX + 12) + "px";
      tooltip.style.top     = (event.clientY - 10) + "px";
    }}
 
    function onNodeOut() {{
      tooltip.style.opacity = 0;
    }}
 
    // ── Controls ──────────────────────────────────────────────────────────────
    function resetZoom() {{
      svg.transition().duration(500)
        .call(zoom.transform, d3.zoomIdentity);
    }}
 
    function reheat() {{
      sim.alpha(0.5).restart();
    }}
 
    function pinAll() {{
      nodes.forEach(d => {{ d.fx = d.x; d.fy = d.y; }});
    }}
 
    function unpinAll() {{
      nodes.forEach(d => {{ d.fx = null; d.fy = null; }});
      sim.alpha(0.3).restart();
    }}
 
    // initial zoom to fit
    window.addEventListener("load", () => {{
      setTimeout(() => {{
        const bounds  = g.node().getBBox();
        const w       = width();
        const h       = height();
        const scale   = 0.8 / Math.max(bounds.width / w, bounds.height / h);
        const tx      = (w - scale * (bounds.x * 2 + bounds.width))  / 2;
        const ty      = (h - scale * (bounds.y * 2 + bounds.height)) / 2;
        svg.transition().duration(800)
          .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
      }}, 1500);
    }});
  </script>
</body>
</html>"""
 
    with open(output, "w") as f:
        f.write(html)
 
    return output