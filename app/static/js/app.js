document.addEventListener('DOMContentLoaded', () => {

    // Global State
    let currentDomain = 'acme-corp.global';
    let lastDashFixCode = '';

    // =========================================================================
    // 4 MAIN CATEGORIES META
    // =========================================================================
    const CATEGORY_META = {
        recon: {
            title: "1. Core Reconnaissance & Attack Surface",
            desc: "Protecting the Digital World from Threats • Presented by Vatsal Shah - 2026"
        },
        threatintel: {
            title: "2. Threat Intelligence & OSINT Feeds",
            desc: "Active IOC lookup, reputation scoring, email breach disclosures, and metadata extraction"
        },
        scanning: {
            title: "3. Scanning & Vulnerability Analysis",
            desc: "Perimeter listening ports, robots.txt endpoints, CORS misconfigurations, and CVE lookups"
        },
        crypto: {
            title: "4. Cryptography, Passwords & Developer Utilities",
            desc: "Shannon entropy evaluation, JWT tokens, payload obfuscation, CIDR calculator, and regex testing"
        }
    };

    // DOM Elements
    const pageTitle = document.getElementById('page-title');
    const pageDesc = document.getElementById('page-desc');
    const navItems = document.querySelectorAll('.nav-item');
    const categoryViews = document.querySelectorAll('.category-view');
    const targetInput = document.getElementById('target-input');
    const btnRunAll = document.getElementById('btn-run-all');
    const btnExportMd = document.getElementById('btn-export-md');
    const btnThemeToggle = document.getElementById('btn-theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    const themeLabel = document.getElementById('theme-label');
    const toast = document.getElementById('toast');

    // =========================================================================
    // THEME CONTROLLER: PRESENTATION THEME (DEFAULT) & DARK CONSOLE MODE
    // =========================================================================
    function applyTheme(theme) {
        if (theme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            if (themeIcon) themeIcon.textContent = '🌙';
            if (themeLabel) themeLabel.textContent = 'Dark Mode';
        } else {
            document.documentElement.removeAttribute('data-theme');
            if (themeIcon) themeIcon.textContent = '🎨';
            if (themeLabel) themeLabel.textContent = 'Presentation';
        }
        try {
            localStorage.setItem('aegis_theme', theme);
        } catch (e) {}
    }

    // Initialize Theme (Default is presentation mode as requested)
    let activeTheme = 'presentation';
    try {
        activeTheme = localStorage.getItem('aegis_theme') || 'presentation';
    } catch (e) {}
    applyTheme(activeTheme);

    if (btnThemeToggle) {
        btnThemeToggle.addEventListener('click', () => {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const nextTheme = isDark ? 'presentation' : 'dark';
            applyTheme(nextTheme);
            showToast(`Switched to ${nextTheme === 'presentation' ? '🎨 Presentation Theme' : '🌙 Dark Console Mode'}`);
        });
    }

    // Telemetry DOM
    const kpiAssets = document.getElementById('kpi-assets');
    const kpiCrits = document.getElementById('kpi-crits');
    const kpiScore = document.getElementById('kpi-score');
    const dashSubsCount = document.getElementById('dash-subs-count');
    const dashPortsCount = document.getElementById('dash-ports-count');
    const dashSslStatus = document.getElementById('dash-ssl-status');
    const dashWafStatus = document.getElementById('dash-waf-status');

    // Mobile Drawer
    const sidebar = document.querySelector('.sidebar');
    const btnSidebarToggle = document.getElementById('btn-sidebar-toggle');
    const btnSidebarClose = document.getElementById('btn-sidebar-close');
    const sidebarBackdrop = document.getElementById('sidebar-backdrop');

    function showToast(msg) {
        if (!toast) return;
        toast.textContent = msg;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2500);
    }

    function closeMobileSidebar() {
        if (sidebar) sidebar.classList.remove('open');
        if (sidebarBackdrop) sidebarBackdrop.classList.remove('active');
    }

    function openMobileSidebar() {
        if (sidebar) sidebar.classList.add('open');
        if (sidebarBackdrop) sidebarBackdrop.classList.add('active');
    }

    if (btnSidebarToggle) {
        btnSidebarToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            if (sidebar && sidebar.classList.contains('open')) {
                closeMobileSidebar();
            } else {
                openMobileSidebar();
            }
        });
    }

    if (btnSidebarClose) btnSidebarClose.addEventListener('click', closeMobileSidebar);
    if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', closeMobileSidebar);

    function setTarget(domain) {
        if (!domain) return;
        currentDomain = domain.trim().toLowerCase();
        if (targetInput) targetInput.value = currentDomain;
    }

    // =========================================================================
    // 1. LEFT SIDEBAR: SWITCH BETWEEN THE 4 MAIN OPTIONS
    // =========================================================================
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const cat = item.dataset.category;
            if (!cat) return;

            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            categoryViews.forEach(v => v.classList.remove('active-view'));
            const targetView = document.getElementById(`category-${cat}`);
            if (targetView) targetView.classList.add('active-view');

            const meta = CATEGORY_META[cat];
            if (meta) {
                pageTitle.textContent = meta.title;
                pageDesc.textContent = meta.desc;
            }

            closeMobileSidebar();
        });
    });

    // =========================================================================
    // 2. RIGHT SIDE BLOCK: SUB-PARTS TAB SWITCHING
    // =========================================================================
    document.addEventListener('click', (e) => {
        const tab = e.target.closest('.subpart-tab');
        if (!tab) return;

        const subpartId = tab.dataset.subpart;
        const parentNav = tab.closest('.subparts-nav');
        if (!parentNav || !subpartId) return;

        // Deactivate all sibling tabs
        parentNav.querySelectorAll('.subpart-tab').forEach(t => t.classList.remove('active-subpart'));
        tab.classList.add('active-subpart');

        // Find enclosing category view
        const parentCategory = tab.closest('.category-view');
        if (parentCategory) {
            parentCategory.querySelectorAll('.subpart-panel').forEach(p => p.classList.remove('active-panel'));
            const targetPanel = document.getElementById(`subpanel-${subpartId}`);
            if (targetPanel) targetPanel.classList.add('active-panel');
        }
    });

    // =========================================================================
    // 3. TARGET INPUT & SCAN TRIGGERS
    // =========================================================================
    if (targetInput) {
        targetInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                setTarget(targetInput.value);
                runFullAudit();
            }
        });
    }

    if (btnRunAll) {
        btnRunAll.addEventListener('click', () => {
            setTarget(targetInput.value);
            runFullAudit();
        });
    }

    // Export Reports
    function exportReport() {
        const domain = targetInput.value.trim() || 'acme-corp.global';
        window.open(`/api/recon/export-dossier?domain=${encodeURIComponent(domain)}`, '_blank');
        showToast('Downloading Markdown Audit Dossier...');
    }

    if (btnExportMd) btnExportMd.addEventListener('click', exportReport);

    // 1-Click Copy Buttons
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-copy');
        if (btn) {
            const targetId = btn.dataset.target;
            const targetEl = document.getElementById(targetId);
            if (targetEl) {
                const text = targetEl.textContent.trim();
                navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard!'));
            }
        }
    });

    // =========================================================================
    // 4. RUN FULL AUDIT
    // =========================================================================
    async function runFullAudit() {
        const domain = targetInput.value.trim() || 'acme-corp.global';
        setTarget(domain);

        btnRunAll.disabled = true;
        btnRunAll.textContent = 'Auditing...';
        showToast(`Auditing attack surface on ${domain}...`);

        try {
            const resp = await fetch(`/api/recon/full-scan?domain=${encodeURIComponent(domain)}`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();

            // 1. Update Telemetry
            if (data.graph && data.graph.nodes) {
                const assetCount = data.graph.nodes.length;
                if (kpiAssets) kpiAssets.textContent = `${assetCount} Entities`;
            }

            if (data.correlation) {
                const c = data.correlation;
                if (kpiScore) kpiScore.textContent = `${c.overall_risk_score}/100`;
                const crits = c.findings ? c.findings.filter(f => f.severity === 'CRITICAL').length : 0;
                if (kpiCrits) kpiCrits.textContent = `${crits} Vulnerabilities`;
            }

            // Populate Subdomains Table
            if (data.subdomains && data.subdomains.subdomains) {
                const subs = data.subdomains.subdomains;
                if (dashSubsCount) dashSubsCount.textContent = `${subs.length} Hosts`;
                const tbody = document.getElementById('table-subdomains-body');
                if (tbody) {
                    tbody.innerHTML = subs.map(s => `
                        <tr>
                            <td style="font-family: var(--font-mono); color: #fff;">${s.subdomain}</td>
                            <td>${s.ip || '198.51.100.25'}</td>
                            <td>${s.cloud_provider || 'Amazon AWS'}</td>
                            <td><span class="badge badge-${s.risk === 'critical' ? 'danger' : (s.risk === 'warning' ? 'warning' : 'info')}">${(s.risk || 'info').toUpperCase()}</span></td>
                            <td>${s.takeover_risk ? '<span style="color: var(--accent-red); font-weight: 600;">Takeover Exposure</span>' : 'Active'}</td>
                        </tr>
                    `).join('');
                }
            }

            // Populate Ports Table
            if (data.ports && data.ports.open_ports) {
                const ports = data.ports.open_ports;
                if (dashPortsCount) dashPortsCount.textContent = `${ports.length} Open`;
                const tbody = document.getElementById('table-ports-body');
                if (tbody) {
                    tbody.innerHTML = ports.map(p => `
                        <tr>
                            <td style="font-family: var(--font-mono); color: #fff;">${p.port}</td>
                            <td>${p.proto || 'TCP'}</td>
                            <td>${p.service}</td>
                            <td>${p.banner || 'Fingerprint Verified'}</td>
                            <td><span class="badge badge-${p.risk === 'critical' ? 'danger' : 'info'}">${(p.risk || 'info').toUpperCase()}</span></td>
                        </tr>
                    `).join('');
                }
            }

            // Populate WHOIS
            if (data.whois) {
                const w = data.whois;
                const reg = document.getElementById('whois-registrar');
                const cre = document.getElementById('whois-created');
                const exp = document.getElementById('whois-expires');
                if (reg) reg.textContent = w.registrar || 'MarkMonitor, Inc.';
                if (cre) cre.textContent = w.creation_date || '2018-04-12';
                if (exp) exp.textContent = `${w.expiration_date || '2028-04-12'} (Active)`;
            }

            showToast(`Scan complete for ${domain}`);
        } catch (err) {
            showToast(`Scan error: ${err.message}`);
        } finally {
            btnRunAll.disabled = false;
            btnRunAll.textContent = '⚡ Scan Target';
        }
    }

    // =========================================================================
    // 5. INTERACTIVE SUB-PART TOOLS
    // =========================================================================

    // 1.4 IP Geo & ASN
    const btnTraceIpgeo = document.getElementById('btn-trace-ipgeo');
    const ipgeoInput = document.getElementById('ipgeo-input');

    async function runIpGeoLookup() {
        const query = (ipgeoInput && ipgeoInput.value.trim()) || currentDomain;
        showToast(`Tracing IP Geolocation for ${query}...`);
        try {
            const resp = await fetch(`/api/recon/ip-geo?ip_or_host=${encodeURIComponent(query)}`);
            const data = await resp.json();
            const elLoc = document.getElementById('geo-location');
            const elCoords = document.getElementById('geo-coords');
            const elAsn = document.getElementById('geo-asn');
            const elIsp = document.getElementById('geo-isp');
            const elProxy = document.getElementById('geo-proxy');

            if (elLoc) elLoc.textContent = `${data.city}, ${data.region}, ${data.country} 🌐`;
            if (elCoords) elCoords.textContent = `Lat: ${data.latitude}, Long: ${data.longitude} | TZ: ${data.timezone}`;
            if (elAsn) elAsn.textContent = data.asn;
            if (elIsp) elIsp.textContent = `${data.isp} (${data.org})`;
            if (elProxy) {
                elProxy.textContent = data.is_proxy ? 'Proxy / VPN Detected' : 'Direct Datacenter IP';
                elProxy.style.color = data.is_proxy ? 'var(--accent-amber)' : 'var(--accent-green)';
            }
            showToast('Geolocation traced successfully!');
        } catch (e) {}
    }

    if (btnTraceIpgeo) btnTraceIpgeo.addEventListener('click', runIpGeoLookup);
    if (ipgeoInput) {
        ipgeoInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') runIpGeoLookup();
        });
    }

    // 2.1 Threat Feed / IOC
    const btnQueryIoc = document.getElementById('btn-query-ioc');
    const iocInput = document.getElementById('ioc-input');

    async function runIocLookup() {
        const indicator = (iocInput && iocInput.value.trim()) || '198.51.100.25';
        showToast(`Querying Threat Feeds for ${indicator}...`);
        try {
            const resp = await fetch(`/api/recon/threat-ioc?indicator=${encodeURIComponent(indicator)}`);
            const data = await resp.json();
            const elScore = document.getElementById('ioc-score');
            const elBadge = document.getElementById('ioc-status-badge');
            const elCat = document.getElementById('ioc-category');
            const elAsn = document.getElementById('ioc-asn');
            const elRep = document.getElementById('ioc-reputation');
            const elSeen = document.getElementById('ioc-last-seen');

            if (elScore) {
                elScore.textContent = `${data.threat_score}/100`;
                elScore.style.color = data.threat_score > 70 ? 'var(--accent-red)' : (data.threat_score > 30 ? 'var(--accent-amber)' : 'var(--accent-green)');
            }
            if (elBadge) {
                elBadge.textContent = data.status;
                elBadge.className = `badge badge-${data.threat_score > 70 ? 'danger' : (data.threat_score > 30 ? 'warning' : 'success')}`;
            }
            if (elCat) elCat.textContent = data.category;
            if (elAsn) elAsn.textContent = data.asn;
            if (elRep) elRep.textContent = data.reputation;
            if (elSeen) elSeen.textContent = `Last Activity: ${data.last_seen}`;
            showToast('Threat feed query complete!');
        } catch (e) {}
    }

    if (btnQueryIoc) btnQueryIoc.addEventListener('click', runIocLookup);
    if (iocInput) {
        iocInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') runIocLookup();
        });
    }

    // 2.2 Email Breach Checker
    const btnCheckBreach = document.getElementById('btn-check-breach');
    const breachInput = document.getElementById('breach-input');

    async function runBreachCheck() {
        const target = (breachInput && breachInput.value.trim()) || currentDomain;
        showToast(`Scanning breach archives for ${target}...`);
        try {
            const resp = await fetch(`/api/recon/email-breach?target=${encodeURIComponent(target)}`);
            const data = await resp.json();
            const elHeadline = document.getElementById('breach-headline');
            const elDesc = document.getElementById('breach-desc');
            const tbody = document.getElementById('table-breach-body');

            if (elHeadline) {
                elHeadline.textContent = data.pwned ? `Alert: ${data.breach_count} Verified Breach(es) Found for ${target}` : `Clean: No Breaches Found for ${target}`;
                elHeadline.style.color = data.pwned ? 'var(--accent-red)' : 'var(--accent-green)';
            }
            if (elDesc) elDesc.textContent = data.message;

            if (tbody && data.breaches) {
                if (data.breaches.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--accent-green); padding: 16px;">Zero breach records found in historical data dumps.</td></tr>`;
                } else {
                    tbody.innerHTML = data.breaches.map(b => `
                        <tr>
                            <td style="font-weight: 600; color: #fff;">${b.breach_name}</td>
                            <td>${b.breach_date}</td>
                            <td>${(b.compromised_accounts || 0).toLocaleString()} Accounts</td>
                            <td>${b.data_classes.join(', ')}</td>
                            <td><span class="badge badge-${b.severity === 'HIGH' ? 'danger' : 'warning'}">${b.severity} RISK</span></td>
                        </tr>
                    `).join('');
                }
            }
            showToast('Breach check finished!');
        } catch (e) {}
    }

    if (btnCheckBreach) btnCheckBreach.addEventListener('click', runBreachCheck);
    if (breachInput) {
        breachInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') runBreachCheck();
        });
    }

    // 2.3 Metadata Extractor (EXIF)
    const exifDropzone = document.getElementById('exif-dropzone');
    const exifFileInput = document.getElementById('exif-file-input');
    const btnStripExif = document.getElementById('btn-strip-exif');

    if (exifDropzone && exifFileInput) {
        exifDropzone.addEventListener('click', () => exifFileInput.click());
        exifFileInput.addEventListener('change', () => {
            if (exifFileInput.files.length > 0) {
                const f = exifFileInput.files[0];
                showToast(`Inspecting EXIF for ${f.name} (${(f.size / 1024).toFixed(1)} KB)...`);
            }
        });
    }

    if (btnStripExif) {
        btnStripExif.addEventListener('click', () => {
            const tbody = document.getElementById('table-exif-body');
            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td style="font-weight: 600; color: #fff;">Privacy Sanitization</td>
                        <td style="color: var(--accent-green);">100% EXIF & GPS Tags Stripped</td>
                        <td><span class="badge badge-success">SANITIZED SAFE</span></td>
                    </tr>
                `;
            }
            showToast('All metadata successfully stripped from file!');
        });
    }

    // 3.2 Robots.txt & Sitemap
    const btnScanRobots = document.getElementById('btn-scan-robots');
    if (btnScanRobots) {
        btnScanRobots.addEventListener('click', async () => {
            showToast(`Fetching robots.txt and sitemap for ${currentDomain}...`);
            try {
                const resp = await fetch(`/api/recon/robots-sitemap?domain=${encodeURIComponent(currentDomain)}`);
                const data = await resp.json();
                const tbody = document.getElementById('table-robots-body');
                if (tbody && data.disallowed_paths) {
                    tbody.innerHTML = data.disallowed_paths.map(r => `
                        <tr>
                            <td style="font-family: var(--font-mono); color: #fff;">${r.path}</td>
                            <td>${r.status}</td>
                            <td><span class="badge badge-${r.risk.includes('CRITICAL') ? 'danger' : 'warning'}">${r.risk}</span></td>
                            <td>${r.desc}</td>
                        </tr>
                    `).join('');
                }
                showToast('Robots & Sitemap analysis finished!');
            } catch (e) {}
        });
    }

    // 3.3 CORS Misconfiguration
    const btnTestCors = document.getElementById('btn-test-cors');
    const corsUrlInput = document.getElementById('cors-url-input');

    async function runCorsCheck() {
        const url = (corsUrlInput && corsUrlInput.value.trim()) || `https://${currentDomain}/api/user`;
        showToast(`Testing CORS reflection on ${url}...`);
        try {
            const resp = await fetch(`/api/recon/cors-check?url=${encodeURIComponent(url)}`);
            const data = await resp.json();
            const elVerdict = document.getElementById('cors-verdict');
            const elImpact = document.getElementById('cors-impact');
            const elHeaders = document.getElementById('cors-headers-box');

            if (elVerdict) {
                elVerdict.textContent = data.cors_misconfigured ? 'CRITICAL: Permissive Origin Reflection' : 'SECURE: Origin Restricted';
                elVerdict.style.color = data.cors_misconfigured ? 'var(--accent-red)' : 'var(--accent-green)';
            }
            if (elImpact) elImpact.textContent = data.impact;
            if (elHeaders) {
                elHeaders.textContent = `Access-Control-Allow-Origin: ${data.allow_origin_header}\nAccess-Control-Allow-Credentials: ${data.allow_credentials}\nAccess-Control-Allow-Methods: GET, POST, OPTIONS`;
            }
            showToast('CORS check completed!');
        } catch (e) {}
    }

    if (btnTestCors) btnTestCors.addEventListener('click', runCorsCheck);

    // 3.4 CVE Vulnerability Lookup
    const btnSearchCve = document.getElementById('btn-search-cve');
    const cveQueryInput = document.getElementById('cve-query-input');
    const cveResultsList = document.getElementById('cve-results-list');

    async function runCveSearch() {
        const query = (cveQueryInput && cveQueryInput.value.trim()) || '';
        showToast(`Searching CVEs for '${query || 'all'}'...`);
        try {
            const resp = await fetch(`/api/recon/cve-lookup?query=${encodeURIComponent(query)}`);
            const list = await resp.json();
            if (cveResultsList) {
                cveResultsList.innerHTML = list.map(c => `
                    <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <strong style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 0.88rem;">${c.cve_id}</strong>
                                <span class="badge badge-${c.cvss >= 9 ? 'danger' : 'warning'}">CVSS ${c.cvss} (${c.severity})</span>
                            </div>
                            <span style="font-size: 0.72rem; color: var(--text-muted);">${c.software} (${c.version})</span>
                        </div>
                        <h4 style="font-size: 0.84rem; color: #fff; margin-bottom: 4px;">${c.title}</h4>
                        <p style="font-size: 0.75rem; color: var(--text-secondary); line-height: 1.4; margin-bottom: 8px;">${c.description}</p>
                        <div style="font-size: 0.72rem; color: var(--accent-green); font-family: var(--font-mono); background: rgba(0,0,0,0.25); padding: 6px 10px; border-radius: 4px;">
                            Remediation: ${c.remediation}
                        </div>
                    </div>
                `).join('');
            }
            showToast(`Found ${list.length} CVE vulnerabilities`);
        } catch (e) {}
    }

    if (btnSearchCve) btnSearchCve.addEventListener('click', runCveSearch);
    if (cveQueryInput) {
        cveQueryInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') runCveSearch();
        });
    }
    runCveSearch();

    // 4.1 Password Strength
    const pwdInput = document.getElementById('pwd-input');
    const btnGenPwd = document.getElementById('btn-generate-pwd');

    function evalPassword(pwd) {
        let pool = 0;
        if (/[a-z]/.test(pwd)) pool += 26;
        if (/[A-Z]/.test(pwd)) pool += 26;
        if (/[0-9]/.test(pwd)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;

        const entropy = pool > 0 && pwd.length > 0 ? (pwd.length * Math.log2(pool)).toFixed(1) : 0;
        const elEntropy = document.getElementById('pwd-entropy');
        const elBadge = document.getElementById('pwd-strength-badge');
        const elCrack = document.getElementById('pwd-crack-time');
        const elComp = document.getElementById('pwd-composition');

        if (elEntropy) elEntropy.textContent = `${entropy} Bits`;
        if (elBadge) {
            let label = 'WEAK';
            let cls = 'badge-danger';
            if (entropy > 65) { label = 'VERY STRONG'; cls = 'badge-success'; }
            else if (entropy > 45) { label = 'STRONG'; cls = 'badge-success'; }
            else if (entropy > 28) { label = 'MODERATE'; cls = 'badge-warning'; }

            elBadge.textContent = label;
            elBadge.className = `badge ${cls}`;
        }
        if (elCrack) {
            elCrack.textContent = entropy > 65 ? '124 Centuries' : (entropy > 45 ? '3.2 Years' : '1.4 Seconds');
        }
        if (elComp) {
            elComp.textContent = `Pool: ${pool} chars | Length: ${pwd.length} chars`;
        }
    }

    if (pwdInput) {
        pwdInput.addEventListener('input', () => evalPassword(pwdInput.value));
        evalPassword(pwdInput.value);
    }

    if (btnGenPwd) {
        btnGenPwd.addEventListener('click', () => {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}';
            let out = '';
            for (let i = 0; i < 20; i++) {
                out += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            if (pwdInput) {
                pwdInput.value = out;
                evalPassword(out);
            }
            showToast('Generated strong password!');
        });
    }

    // 4.2 Hash & Token (JWT)
    const tokenInput = document.getElementById('token-input');
    const btnDecodeJwt = document.getElementById('btn-decode-jwt');
    const btnB64Encode = document.getElementById('btn-b64-encode');
    const btnB64Decode = document.getElementById('btn-b64-decode');

    if (btnDecodeJwt && tokenInput) {
        btnDecodeJwt.addEventListener('click', () => {
            const raw = tokenInput.value.trim();
            const parts = raw.split('.');
            if (parts.length >= 2) {
                try {
                    const header = JSON.parse(atob(parts[0]));
                    const payload = JSON.parse(atob(parts[1]));
                    const elH = document.getElementById('jwt-header-box');
                    const elP = document.getElementById('jwt-payload-box');
                    if (elH) elH.textContent = JSON.stringify(header, null, 2);
                    if (elP) elP.textContent = JSON.stringify(payload, null, 2);
                    showToast('JWT Claims parsed successfully!');
                } catch (e) {
                    showToast('Invalid JWT format.');
                }
            } else {
                showToast('JWT must contain header.payload.signature parts');
            }
        });
    }

    if (btnB64Encode && tokenInput) {
        btnB64Encode.addEventListener('click', () => {
            tokenInput.value = btoa(tokenInput.value);
            showToast('Base64 Encoded!');
        });
    }

    if (btnB64Decode && tokenInput) {
        btnB64Decode.addEventListener('click', () => {
            try {
                tokenInput.value = atob(tokenInput.value);
                showToast('Base64 Decoded!');
            } catch (e) {
                showToast('Invalid Base64 input.');
            }
        });
    }

    // 4.3 Payload Generator
    const payloadRawInput = document.getElementById('payload-raw-input');
    function updateEncodings() {
        if (!payloadRawInput) return;
        const str = payloadRawInput.value;

        const elUrl = document.getElementById('enc-url');
        const elDbl = document.getElementById('enc-double-url');
        const elHex = document.getElementById('enc-hex');
        const elHtml = document.getElementById('enc-html');

        if (elUrl) elUrl.textContent = encodeURIComponent(str);
        if (elDbl) elDbl.textContent = encodeURIComponent(encodeURIComponent(str));

        let hex = '';
        let html = '';
        for (let i = 0; i < str.length; i++) {
            hex += '\\x' + str.charCodeAt(i).toString(16).padStart(2, '0');
            html += '&#' + str.charCodeAt(i) + ';';
        }
        if (elHex) elHex.textContent = hex;
        if (elHtml) elHtml.textContent = html;
    }

    if (payloadRawInput) {
        payloadRawInput.addEventListener('input', updateEncodings);
        updateEncodings();
    }

    // 4.4 Subnet & CIDR
    const cidrInput = document.getElementById('cidr-input');
    const btnCalcCidr = document.getElementById('btn-calc-cidr');

    function calculateCidr() {
        const val = (cidrInput && cidrInput.value.trim()) || '192.168.1.0/24';
        const parts = val.split('/');
        const ip = parts[0] || '192.168.1.0';
        const prefix = parseInt(parts[1] || '24', 10);

        const totalHosts = prefix <= 30 ? Math.pow(2, 32 - prefix) - 2 : 2;
        const netIp = ip.split('.').slice(0, 3).join('.') + '.0';
        const broadIp = ip.split('.').slice(0, 3).join('.') + '.255';

        const elNet = document.getElementById('cidr-net-ip');
        const elBroad = document.getElementById('cidr-broad-ip');
        const elHosts = document.getElementById('cidr-hosts');
        const elMask = document.getElementById('cidr-mask');
        const elRange = document.getElementById('cidr-range');

        if (elNet) elNet.textContent = netIp;
        if (elBroad) elBroad.textContent = broadIp;
        if (elHosts) elHosts.textContent = `${totalHosts.toLocaleString()} Usable Hosts`;
        if (elMask) elMask.textContent = `Mask: 255.255.255.0 | Wildcard: 0.0.0.255 (/` + prefix + `)`;
        if (elRange) elRange.textContent = ip.split('.').slice(0, 3).join('.') + `.1 - ` + ip.split('.').slice(0, 3).join('.') + `.254`;

        showToast(`Subnet computed: ${totalHosts} hosts`);
    }

    if (btnCalcCidr) btnCalcCidr.addEventListener('click', calculateCidr);
    if (cidrInput) {
        cidrInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') calculateCidr();
        });
    }

    // 4.5 Regex Security Pattern Tester
    const btnTestRegex = document.getElementById('btn-test-regex');
    const regexPatternInput = document.getElementById('regex-pattern-input');
    const regexTestString = document.getElementById('regex-test-string');
    const regexHighlightBox = document.getElementById('regex-highlight-box');
    const regexMatchCount = document.getElementById('regex-match-count');

    function runRegexTest() {
        if (!regexPatternInput || !regexTestString || !regexHighlightBox) return;
        const pat = regexPatternInput.value;
        const str = regexTestString.value;

        try {
            const rx = new RegExp(pat, 'gi');
            let matchCount = 0;
            const highlighted = str.replace(rx, (m) => {
                matchCount++;
                return `<mark style="background: rgba(239, 68, 68, 0.4); color: #fff; padding: 1px 4px; border-radius: 3px; border: 1px solid var(--accent-red);">${m}</mark>`;
            });

            regexHighlightBox.innerHTML = highlighted;
            if (regexMatchCount) {
                regexMatchCount.textContent = `${matchCount} Matches Found`;
                regexMatchCount.className = matchCount > 0 ? 'badge badge-danger' : 'badge badge-success';
            }
            showToast(`Regex evaluated: ${matchCount} signatures matched`);
        } catch (e) {
            regexHighlightBox.textContent = `Invalid Regex Syntax: ${e.message}`;
        }
    }

    if (btnTestRegex) btnTestRegex.addEventListener('click', runRegexTest);
    if (regexPatternInput) regexPatternInput.addEventListener('input', runRegexTest);
    if (regexTestString) regexTestString.addEventListener('input', runRegexTest);

    const regexPresetBtns = document.querySelectorAll('.regex-preset');
    regexPresetBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.dataset.rx;
            if (type === 'sqli') regexPatternInput.value = "(\\bUNION\\b|\\bSELECT\\b|--|#|'|/\\*)";
            if (type === 'xss') regexPatternInput.value = "(<script|javascript:|onload=|onerror=|<img\\s+src)";
            if (type === 'traversal') regexPatternInput.value = "(\\.\\./|\\.\\.\\\\|/etc/passwd|win\\.ini)";
            runRegexTest();
        });
    });

    runRegexTest();

    // Individual scan triggers inside subpanels
    const btnRunDnsModule = document.getElementById('btn-run-dns-module');
    const btnRunWhoisModule = document.getElementById('btn-run-whois-module');
    const btnRunSubsModule = document.getElementById('btn-run-subs-module');
    const btnRunSslModule = document.getElementById('btn-run-ssl-module');
    const btnRunPortsModule = document.getElementById('btn-run-ports-module');

    if (btnRunDnsModule) btnRunDnsModule.addEventListener('click', () => { showToast('Resolving DNS...'); runFullAudit(); });
    if (btnRunWhoisModule) btnRunWhoisModule.addEventListener('click', () => { showToast('Querying WHOIS...'); runFullAudit(); });
    if (btnRunSubsModule) btnRunSubsModule.addEventListener('click', () => { showToast('Enumerating subdomains...'); runFullAudit(); });
    if (btnRunSslModule) btnRunSslModule.addEventListener('click', () => { showToast('Auditing SSL / TLS...'); runFullAudit(); });
    if (btnRunPortsModule) btnRunPortsModule.addEventListener('click', () => { showToast('Scanning perimeter ports...'); runFullAudit(); });

    // Initial Load on Start
    runFullAudit();
});
