class ThreatGraph {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');
        this.nodes = [];
        this.links = [];
        this.nodeMap = new Map();
        this.width = this.canvas.clientWidth || 800;
        this.height = this.canvas.clientHeight || 560;
        this.hoveredNode = null;
        this.draggedNode = null;
        this.selectedNode = null;
        this.onNodeSelected = null;
        this.zoom = 1.0;

        this.initCanvas();
        this.setupEvents();
        this.animate = this.animate.bind(this);
        requestAnimationFrame(this.animate);
    }

    initCanvas() {
        const dpr = window.devicePixelRatio || 1;
        this.width = this.canvas.parentElement.clientWidth || 800;
        this.height = this.canvas.parentElement.clientHeight || 640;
        this.canvas.width = this.width * dpr;
        this.canvas.height = this.height * dpr;
        this.ctx.resetTransform ? this.ctx.resetTransform() : this.ctx.setTransform(1, 0, 0, 1, 0, 0);
        this.ctx.scale(dpr, dpr);
    }

    setupEvents() {
        window.addEventListener('resize', () => {
            this.initCanvas();
        });

        let startX = 0, startY = 0;
        let didDrag = false;

        this.canvas.addEventListener('mousemove', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            if (Math.abs(e.clientX - startX) > 5 || Math.abs(e.clientY - startY) > 5) {
                didDrag = true;
            }

            if (this.draggedNode) {
                this.draggedNode.x = x;
                this.draggedNode.y = y;
                this.draggedNode.vx = 0;
                this.draggedNode.vy = 0;
                return;
            }

            this.hoveredNode = this.nodes.find(n => {
                const dx = n.x - x;
                const dy = n.y - y;
                return Math.sqrt(dx * dx + dy * dy) < (n.radius + 8);
            });
            this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'default';
        });

        this.canvas.addEventListener('mousedown', (e) => {
            startX = e.clientX;
            startY = e.clientY;
            didDrag = false;
            if (this.hoveredNode) {
                this.draggedNode = this.hoveredNode;
            }
        });

        this.canvas.addEventListener('mouseup', (e) => {
            if (!didDrag && this.hoveredNode) {
                this.selectedNode = this.hoveredNode;
                if (this.onNodeSelected) {
                    this.onNodeSelected(this.selectedNode);
                }
            }
            this.draggedNode = null;
        });
    }

    zoomIn() {
        this.nodes.forEach(n => {
            const cx = this.width / 2;
            const cy = this.height / 2;
            n.x = cx + (n.x - cx) * 1.2;
            n.y = cy + (n.y - cy) * 1.2;
        });
    }

    zoomOut() {
        this.nodes.forEach(n => {
            const cx = this.width / 2;
            const cy = this.height / 2;
            n.x = cx + (n.x - cx) * 0.82;
            n.y = cy + (n.y - cy) * 0.82;
        });
    }

    resetView() {
        const cx = this.width / 2;
        const cy = this.height / 2;
        this.nodes.forEach((n, idx) => {
            const angle = (idx / Math.max(1, this.nodes.length)) * Math.PI * 2;
            const dist = n.type === 'domain' ? 0 : 140 + (idx % 3) * 50;
            n.x = cx + Math.cos(angle) * dist;
            n.y = cy + Math.sin(angle) * dist;
            n.vx = 0;
            n.vy = 0;
        });
    }

    addNodesAndEdges(newNodes, newEdges) {
        // Filter out noisy clutter nodes (e.g. cloudflare nameservers)
        const filteredNodes = newNodes.filter(n => {
            if (n.type === 'nameserver') return false; // Hide third-party DNS clutter
            if (n.label && n.label.includes('.ns.cloudflare.com')) return false;
            return true;
        });

        const cx = this.width / 2;
        const cy = this.height / 2;

        filteredNodes.forEach((n, idx) => {
            if (!this.nodeMap.has(n.id)) {
                // Distribute initial positions radially around center
                const angle = (idx / Math.max(1, filteredNodes.length)) * Math.PI * 2;
                const dist = n.type === 'domain' ? 0 : 130 + (idx % 3) * 45;
                
                const nodeObj = {
                    ...n,
                    x: cx + Math.cos(angle) * dist,
                    y: cy + Math.sin(angle) * dist,
                    vx: 0,
                    vy: 0,
                    radius: n.type === 'domain' ? 16 : (n.risk === 'critical' ? 13 : 10)
                };
                this.nodes.push(nodeObj);
                this.nodeMap.set(n.id, nodeObj);
            }
        });

        newEdges.forEach(e => {
            const sourceNode = this.nodeMap.get(e.source);
            const targetNode = this.nodeMap.get(e.target);
            if (sourceNode && targetNode) {
                const exists = this.links.some(l => 
                    (l.source.id === sourceNode.id && l.target.id === targetNode.id)
                );
                if (!exists) {
                    this.links.push({
                        source: sourceNode,
                        target: targetNode,
                        label: e.label,
                        threat: !!e.threat
                    });
                }
            }
        });
    }

    clear() {
        this.nodes = [];
        this.links = [];
        this.nodeMap.clear();
        this.hoveredNode = null;
        this.draggedNode = null;
    }

    stepPhysics() {
        const repulsion = 4500; // Strong repulsion for spacious layout
        const linkDistance = 140; // Wide distance so labels never overlap
        const damping = 0.82;

        const cx = this.width / 2;
        const cy = this.height / 2;

        // 1. Repulsion & Collision Avoidance
        for (let i = 0; i < this.nodes.length; i++) {
            for (let j = i + 1; j < this.nodes.length; j++) {
                const n1 = this.nodes[i];
                const n2 = this.nodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;

                // Strong collision push if closer than 80px
                const minDist = n1.radius + n2.radius + 60;
                if (dist < minDist) {
                    const overlap = minDist - dist;
                    const fx = (dx / dist) * overlap * 0.15;
                    const fy = (dy / dist) * overlap * 0.15;
                    n1.vx -= fx;
                    n1.vy -= fy;
                    n2.vx += fx;
                    n2.vy += fy;
                } else if (dist < 350) {
                    const force = repulsion / (dist * dist);
                    const fx = (dx / dist) * force;
                    const fy = (dy / dist) * force;
                    n1.vx -= fx;
                    n1.vy -= fy;
                    n2.vx += fx;
                    n2.vy += fy;
                }
            }
        }

        // 2. Link Spring Force
        this.links.forEach(l => {
            const dx = l.target.x - l.source.x;
            const dy = l.target.y - l.source.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = (dist - linkDistance) * 0.025;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;

            l.source.vx += fx;
            l.source.vy += fy;
            l.target.vx -= fx;
            l.target.vy -= fy;
        });

        // 3. Central Gravity & Position Update
        this.nodes.forEach(n => {
            if (n === this.draggedNode) return;

            // Anchor root domain near center
            const gravity = n.type === 'domain' ? 0.02 : 0.003;
            n.vx += (cx - n.x) * gravity;
            n.vy += (cy - n.y) * gravity;

            n.vx *= damping;
            n.vy *= damping;
            n.x += n.vx;
            n.y += n.vy;

            // Strict screen boundary constraints
            n.x = Math.max(70, Math.min(this.width - 70, n.x));
            n.y = Math.max(50, Math.min(this.height - 50, n.y));
        });
    }

    getNodeColor(type, risk) {
        if (risk === 'critical') return '#ef4444';
        switch (type) {
            case 'domain': return '#06b6d4';
            case 'subdomain': return '#38bdf8';
            case 'ip': return '#a855f7';
            case 'ssl_cert': return '#10b981';
            case 'cloud_bucket': return '#f59e0b';
            case 'open_port': return '#ec4899';
            default: return '#64748b';
        }
    }

    drawRoundedRect(x, y, w, h, r) {
        this.ctx.beginPath();
        this.ctx.moveTo(x + r, y);
        this.ctx.lineTo(x + w - r, y);
        this.ctx.quadraticCurveTo(x + w, y, x + w, y + r);
        this.ctx.lineTo(x + w, y + h - r);
        this.ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
        this.ctx.lineTo(x + r, y + h);
        this.ctx.quadraticCurveTo(x, y + h, x, y + h - r);
        this.ctx.lineTo(x, y + r);
        this.ctx.quadraticCurveTo(x, y, x + r, y);
        this.ctx.closePath();
    }

    animate() {
        this.ctx.clearRect(0, 0, this.width, this.height);
        this.stepPhysics();

        // 1. Draw Links
        this.links.forEach(l => {
            this.ctx.beginPath();
            this.ctx.moveTo(l.source.x, l.source.y);
            this.ctx.lineTo(l.target.x, l.target.y);
            this.ctx.strokeStyle = l.threat ? 'rgba(239, 68, 68, 0.85)' : 'rgba(51, 65, 85, 0.45)';
            this.ctx.lineWidth = l.threat ? 2.4 : 1.2;
            if (l.threat) {
                this.ctx.setLineDash([5, 4]);
            } else {
                this.ctx.setLineDash([]);
            }
            this.ctx.stroke();
        });

        // 2. Draw Nodes
        this.nodes.forEach(n => {
            const color = this.getNodeColor(n.type, n.risk);
            const isHovered = (n === this.hoveredNode);
            const isSelected = (n === this.selectedNode);

            // Selection Indicator Ring
            if (isSelected) {
                this.ctx.beginPath();
                this.ctx.arc(n.x, n.y, n.radius + 7, 0, Math.PI * 2);
                this.ctx.strokeStyle = '#38bdf8';
                this.ctx.lineWidth = 2;
                this.ctx.setLineDash([3, 3]);
                this.ctx.stroke();
                this.ctx.setLineDash([]);
            }

            // Glowing Outer Halo
            this.ctx.save();
            this.ctx.shadowColor = color;
            this.ctx.shadowBlur = (isHovered || isSelected) ? 20 : 10;

            this.ctx.beginPath();
            this.ctx.arc(n.x, n.y, n.radius + (isHovered ? 4 : 0), 0, Math.PI * 2);
            this.ctx.fillStyle = color;
            this.ctx.fill();
            this.ctx.restore();

            // 3. Draw Clean Background Pill Behind Text (Prevents Any Label Overlapping!)
            let labelText = n.label || '';
            if (labelText.length > 22) labelText = labelText.substring(0, 20) + '..';

            this.ctx.font = isHovered ? 'bold 11px -apple-system, sans-serif' : '10px -apple-system, sans-serif';
            const textWidth = this.ctx.measureText(labelText).width;
            const pillW = textWidth + 12;
            const pillH = 18;
            const pillX = n.x - pillW / 2;
            const pillY = n.y + n.radius + 6;

            // Draw Dark Pill Background
            this.ctx.fillStyle = isHovered ? 'rgba(15, 23, 42, 0.95)' : 'rgba(11, 17, 30, 0.85)';
            this.drawRoundedRect(pillX, pillY, pillW, pillH, 4);
            this.ctx.fill();

            this.ctx.strokeStyle = isHovered ? color : 'rgba(51, 65, 85, 0.7)';
            this.ctx.lineWidth = 1;
            this.ctx.stroke();

            // Draw Text
            this.ctx.fillStyle = isHovered ? '#fff' : '#cbd5e1';
            this.ctx.textAlign = 'center';
            this.ctx.textBaseline = 'middle';
            this.ctx.fillText(labelText, n.x, pillY + pillH / 2);
        });

        requestAnimationFrame(this.animate);
    }
}
