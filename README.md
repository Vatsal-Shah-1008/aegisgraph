# AegisGraph: Cyber Security Console & Attack Surface Intelligence

> **Cyber Security: Protecting the Digital World from Threats**  
> *Presented by Vatsal Shah — 2026*

An enterprise-grade External Attack Surface Management (EASM), OSINT, and digital defense console. Features a minimalist high-contrast editorial presentation UI, real-time threat intelligence feeds, perimeter vulnerability scanning, and cryptographic security utilities.

---

## ⚡ Main Modules

1. **Core Reconnaissance:**
   - **DNS & IP Lookup:** Complete DNS resolution (A, AAAA, MX, NS, TXT) and authoritative nameservers.
   - **WHOIS Intel:** Registrar verification, creation/expiry timestamps, and contact masking.
   - **Subdomain Enumeration:** Passive crt.sh certificate transparency harvesting.
   - **IP Geolocation & ASN:** Physical server coordinates, ISP, and Autonomous System Numbers.
   - **Headers & SSL Analyzer:** TLS 1.3 certificate status and defensive HTTP headers audit (HSTS, CSP, X-Frame-Options).

2. **Threat Intelligence & OSINT:**
   - **Threat Feed / IOC Lookup:** IP/domain/hash reputation against threat intelligence feeds.
   - **Email Breach Checker:** Real-time compromise verification across disclosed credential breaches.
   - **Metadata Extractor (EXIF):** Forensic extraction of camera models, timestamps, and GPS leaks.

3. **Scanning & Vulnerability Analysis:**
   - **Port Scanner & Service Prober:** Non-intrusive TCP socket reachability for open ports and services.
   - **Robots.txt & Sitemap Finder:** Discovery of sensitive unindexed paths and administrative endpoints.
   - **CORS Misconfiguration Checker:** Identification of overly permissive origin headers (`Access-Control-Allow-Origin: *`).
   - **CVE Vulnerability Lookup:** Common Vulnerabilities and Exposures database query for software versions.

4. **Cryptography, Passwords & Developer Utilities:**
   - **Password Strength & Entropy:** Shannon entropy evaluation and brute-force cracking estimates.
   - **Hash & Token Analyzer:** MD5, SHA-256, SHA-512 calculation, Base64 encode/decode, and JWT token parsing.
   - **Payload Generator:** Attack vector payload encoding (URL, Hex, HTML Entities, Base64).
   - **Subnet & CIDR Calculator:** Network mask, broadcast IP, and usable host count computation.
   - **Regex Security Tester:** Live pattern matching against SQL injection and XSS signatures.

---

## 🚀 Local Quickstart

### 1. Prerequisites
- Python 3.10+
- Git

### 2. Setup
```bash
# Clone the repository
git clone https://github.com/Vatsal-Shah-1008/aegisgraph.git
cd aegisgraph

# Create and activate virtual environment
python -m venv venv

# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Console
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Open **`http://localhost:8000`** in your browser.

---

## 🌐 Deploy to Production & Connect Custom Domain

### Option 1: 1-Click Free Cloud Deployment (Render.com) — *Recommended*
1. Push this repository to your **GitHub** (`Vatsal-Shah-1008/aegisgraph`).
2. Go to [Render.com](https://render.com) and click **New +** $\rightarrow$ **Web Service**.
3. Select your `aegisgraph` GitHub repository.
4. Settings:
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Click **Deploy Web Service**. You will immediately get a free live URL:  
   `https://aegisgraph.onrender.com`

#### Connecting Your Custom Domain on Render:
1. In your Render Dashboard, go to **Settings** $\rightarrow$ **Custom Domains** $\rightarrow$ **Add Custom Domain**.
2. Enter your domain (e.g. `cyber.yourdomain.com` or `yourdomain.com`).
3. Add the DNS records shown by Render in your Domain Registrar (GoDaddy, Namecheap, Cloudflare):
   - **CNAME:** `cyber` $\rightarrow$ `aegisgraph.onrender.com` (for subdomains)
   - OR **A Record:** `@` $\rightarrow$ `216.24.57.1` (for root domain)
4. Render automatically provisions a free **Let's Encrypt SSL/TLS Certificate** within 5 minutes.

---

### Option 2: VPS / Linux Server (Ubuntu/Debian) with Docker & Nginx
1. Point your domain's DNS `A` record to your VPS IP address.
2. Clone and start:
   ```bash
   git clone https://github.com/Vatsal-Shah-1008/aegisgraph.git /opt/aegisgraph
   cd /opt/aegisgraph
   docker compose up -d --build
   ```
3. Secure with Certbot:
   ```bash
   sudo apt install -y certbot
   sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
   ```

---

## 📜 License
MIT License. Created by [Vatsal Shah](https://github.com/Vatsal-Shah-1008).
