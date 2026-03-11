/**
 * dashboard/src/pages/index.jsx
 * ==============================
 * Main Dashboard — AI Bug Bounty Autonomous Scanner
 * 
 * Features:
 * - Real-time scan progress via WebSocket
 * - Interactive vulnerability table with filtering
 * - Risk visualization charts
 * - Attack surface map
 * - Start/stop scan controls
 */

import React, { useState, useEffect, useRef, useCallback } from "react";

// ── Mock data for demo ──────────────────────────────────────────────────────
const MOCK_VULNS = [
  { id: "v1", type: "SQL Injection", severity: "critical", title: "Error-based SQLi in 'id' parameter", url: "/api/users?id=1", param: "id", cvss: 9.8, confidence: 0.95, discovered: "2024-01-15 14:23" },
  { id: "v2", type: "XSS", severity: "high", title: "Reflected XSS in search parameter", url: "/search?q=test", param: "q", cvss: 7.4, confidence: 0.90, discovered: "2024-01-15 14:31" },
  { id: "v3", type: "IDOR", severity: "high", title: "Path-based IDOR — user profile access", url: "/users/1234/profile", param: "(path)", cvss: 7.1, confidence: 0.75, discovered: "2024-01-15 14:45" },
  { id: "v4", type: "Broken Authentication", severity: "critical", title: "Default credentials accepted (admin:admin)", url: "/admin/login", param: "username", cvss: 9.1, confidence: 0.98, discovered: "2024-01-15 14:52" },
  { id: "v5", type: "XSS", severity: "high", title: "DOM XSS in comment field", url: "/posts/45/comments", param: "comment", cvss: 6.9, confidence: 0.82, discovered: "2024-01-15 15:01" },
  { id: "v6", type: "API Misconfiguration", severity: "medium", title: "Missing auth on /api/v1/admin endpoint", url: "/api/v1/admin/users", param: "-", cvss: 5.3, confidence: 0.88, discovered: "2024-01-15 15:10" },
  { id: "v7", type: "Insecure Cookie", severity: "medium", title: "Session cookie missing HttpOnly + Secure flags", url: "/login", param: "(header)", cvss: 4.8, confidence: 0.92, discovered: "2024-01-15 15:15" },
  { id: "v8", type: "SQL Injection", severity: "high", title: "Time-based blind SQLi in 'order' param", url: "/products?order=name", param: "order", cvss: 8.2, confidence: 0.80, discovered: "2024-01-15 15:22" },
];

const MOCK_ENDPOINTS = [
  { method: "GET",  url: "/",                    status: 200, api: false },
  { method: "POST", url: "/login",               status: 200, api: false },
  { method: "GET",  url: "/users",               status: 200, api: false },
  { method: "GET",  url: "/api/v1/users",        status: 200, api: true  },
  { method: "POST", url: "/api/v1/auth/token",   status: 200, api: true  },
  { method: "GET",  url: "/api/v1/admin/users",  status: 200, api: true  },
  { method: "GET",  url: "/search",              status: 200, api: false },
  { method: "GET",  url: "/products",            status: 200, api: false },
  { method: "POST", url: "/api/v2/upload",       status: 200, api: true  },
  { method: "GET",  url: "/admin",               status: 302, api: false },
];

const MOCK_RECON = {
  subdomains: ["api.example.com", "dev.example.com", "staging.example.com", "admin.example.com", "mail.example.com"],
  technologies: ["WordPress 6.4", "PHP 8.1", "MySQL 8.0", "Apache 2.4", "jQuery 3.7", "Bootstrap 5"],
  ips: ["104.21.45.123", "172.67.145.89"],
  headers: { "X-Frame-Options": "MISSING ⚠️", "HSTS": "MISSING ⚠️", "CSP": "MISSING ⚠️", "Server": "Apache/2.4" }
};

// ── Color helpers ──────────────────────────────────────────────────────────
const SEV_STYLES = {
  critical: { bg: "rgba(255,61,87,.15)", border: "#FF3D57", text: "#FF3D57", label: "CRITICAL" },
  high:     { bg: "rgba(255,112,67,.15)", border: "#FF7043", text: "#FF7043", label: "HIGH" },
  medium:   { bg: "rgba(255,193,7,.12)", border: "#FFC107", text: "#FFC107", label: "MEDIUM" },
  low:      { bg: "rgba(0,229,255,.1)", border: "#00E5FF", text: "#00E5FF", label: "LOW" },
  info:     { bg: "rgba(200,200,200,.08)", border: "#888", text: "#aaa", label: "INFO" },
};

const METHOD_STYLES = {
  GET:    { bg: "rgba(0,229,255,.12)", color: "#00E5FF" },
  POST:   { bg: "rgba(0,255,157,.12)", color: "#00FF9D" },
  PUT:    { bg: "rgba(255,112,67,.12)", color: "#FF7043" },
  DELETE: { bg: "rgba(255,61,87,.12)", color: "#FF3D57" },
  PATCH:  { bg: "rgba(168,85,247,.12)", color: "#A855F7" },
};

// ── CSS injected at runtime ─────────────────────────────────────────────────
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&family=Inter:wght@300;400;500;600&display=swap');
  * { box-sizing:border-box; margin:0; padding:0; }
  ::-webkit-scrollbar { width:6px; height:6px; }
  ::-webkit-scrollbar-track { background:#0C1220; }
  ::-webkit-scrollbar-thumb { background:#1C2940; border-radius:3px; }
  ::-webkit-scrollbar-thumb:hover { background:#2A3A58; }
  body { background:#070B14; color:#C9D8F0; font-family:'Inter',sans-serif; min-height:100vh; }
  @keyframes pulse-glow { 0%,100%{opacity:1;} 50%{opacity:.4;} }
  @keyframes slide-in { from{opacity:0;transform:translateY(12px);} to{opacity:1;transform:translateY(0);} }
  @keyframes spin-slow { from{transform:rotate(0deg);} to{transform:rotate(360deg);} }
  .animate-slide-in { animation: slide-in .3s ease forwards; }
  .card { background:#111827; border:1px solid #1C2940; border-radius:12px; }
  .card-hover { transition:border-color .2s, transform .2s; }
  .card-hover:hover { border-color:#00E5FF40; transform:translateY(-1px); }
  .glow-cyan { box-shadow:0 0 20px rgba(0,229,255,.15); }
`;

// ── Sub-components ─────────────────────────────────────────────────────────

function SevBadge({ severity }) {
  const s = SEV_STYLES[severity] || SEV_STYLES.info;
  return (
    <span style={{
      display:"inline-block", padding:"2px 10px", borderRadius:20,
      fontSize:11, fontWeight:700, letterSpacing:".06em",
      background:s.bg, border:`1px solid ${s.border}`, color:s.text,
      fontFamily:"'JetBrains Mono',monospace",
    }}>{s.label}</span>
  );
}

function MethodBadge({ method }) {
  const s = METHOD_STYLES[method] || { bg:"rgba(200,200,200,.1)", color:"#aaa" };
  return (
    <span style={{
      display:"inline-block", padding:"1px 8px", borderRadius:4,
      fontSize:10, fontWeight:700, fontFamily:"'JetBrains Mono',monospace",
      background:s.bg, color:s.color, minWidth:52, textAlign:"center",
    }}>{method}</span>
  );
}

function StatCard({ label, value, color = "#00E5FF", icon }) {
  return (
    <div className="card card-hover" style={{ padding:"20px 24px", textAlign:"center" }}>
      <div style={{ fontSize:36, fontWeight:700, color, fontFamily:"'Syne',sans-serif", lineHeight:1 }}>{value}</div>
      <div style={{ fontSize:11, color:"#5C7090", textTransform:"uppercase", letterSpacing:".1em", marginTop:8 }}>{label}</div>
    </div>
  );
}

function ProgressRing({ pct, size=80, stroke=6, color="#00E5FF" }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - pct / 100);
  return (
    <svg width={size} height={size} style={{ transform:"rotate(-90deg)" }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1C2940" strokeWidth={stroke} />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={stroke}
        strokeDasharray={circ} strokeDashoffset={offset}
        style={{ transition:"stroke-dashoffset .4s ease", strokeLinecap:"round" }} />
    </svg>
  );
}

function ScanControls({ scanning, onStart, onStop, target, setTarget }) {
  return (
    <div className="card" style={{ padding:24, marginBottom:24 }}>
      <div style={{ display:"flex", gap:12, flexWrap:"wrap", alignItems:"center" }}>
        <div style={{ flex:1, minWidth:280 }}>
          <div style={{ fontSize:11, color:"#5C7090", textTransform:"uppercase", letterSpacing:".1em", marginBottom:6 }}>Target Domain</div>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="example.com or https://target.com"
            disabled={scanning}
            style={{
              width:"100%", background:"#0C1220", border:"1px solid #1C2940",
              borderRadius:8, padding:"10px 14px", color:"#C9D8F0",
              fontFamily:"'JetBrains Mono',monospace", fontSize:13,
              outline:"none", transition:"border-color .2s",
            }}
            onFocus={e => e.target.style.borderColor = "#00E5FF"}
            onBlur={e => e.target.style.borderColor = "#1C2940"}
          />
        </div>
        <div style={{ display:"flex", gap:10, alignItems:"flex-end" }}>
          <button
            onClick={scanning ? onStop : onStart}
            style={{
              background: scanning ? "rgba(255,61,87,.15)" : "rgba(0,229,255,.15)",
              border: `1px solid ${scanning ? "#FF3D57" : "#00E5FF"}`,
              color: scanning ? "#FF3D57" : "#00E5FF",
              borderRadius:8, padding:"10px 24px", cursor:"pointer",
              fontFamily:"'Syne',sans-serif", fontWeight:600, fontSize:14,
              transition:"all .2s", letterSpacing:".04em",
            }}
          >
            {scanning ? "⏹ Stop Scan" : "▶ Start Scan"}
          </button>
        </div>
        {scanning && (
          <div style={{ display:"flex", alignItems:"center", gap:8, color:"#00E5FF", fontSize:13 }}>
            <span style={{ animation:"pulse-glow 1.5s infinite", display:"inline-block", width:8, height:8, background:"#00E5FF", borderRadius:"50%" }} />
            Scanning…
          </div>
        )}
      </div>
    </div>
  );
}

// ── Charts ─────────────────────────────────────────────────────────────────

function SeverityDonut({ vulns }) {
  const counts = { critical:0, high:0, medium:0, low:0 };
  vulns.forEach(v => { if(counts[v.severity]!==undefined) counts[v.severity]++ });
  const data = [
    { label:"Critical", count:counts.critical, color:"#FF3D57" },
    { label:"High",     count:counts.high,     color:"#FF7043" },
    { label:"Medium",   count:counts.medium,   color:"#FFC107" },
    { label:"Low",      count:counts.low,      color:"#00E5FF" },
  ].filter(d => d.count > 0);

  const total = vulns.length;
  let cumulative = 0;
  const size = 140, cx = 70, cy = 70, r = 50, strokeW = 18;
  const circ = 2 * Math.PI * r;

  return (
    <div style={{ display:"flex", alignItems:"center", gap:24 }}>
      <svg width={size} height={size}>
        {data.map((d, i) => {
          const frac = d.count / total;
          const offset = circ * (1 - frac);
          const rotate = -90 + (cumulative / total) * 360;
          cumulative += d.count;
          return (
            <circle key={i} cx={cx} cy={cy} r={r} fill="none"
              stroke={d.color} strokeWidth={strokeW}
              strokeDasharray={`${circ * frac} ${circ * (1-frac)}`}
              strokeDashoffset={circ * 0.25}
              transform={`rotate(${rotate - 90 - (cumulative - d.count)/total*360} ${cx} ${cy})`}
              style={{ strokeLinecap:"round", transition:"all .4s" }}
            />
          );
        })}
        <text x={cx} y={cy-6} textAnchor="middle" fill="#FFF" fontSize={22} fontWeight={700} fontFamily="Syne">{total}</text>
        <text x={cx} y={cy+12} textAnchor="middle" fill="#5C7090" fontSize={10} fontFamily="Inter">FINDINGS</text>
      </svg>
      <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
        {data.map(d => (
          <div key={d.label} style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ width:8, height:8, borderRadius:"50%", background:d.color, flexShrink:0 }} />
            <span style={{ fontSize:12, color:"#C9D8F0", minWidth:56 }}>{d.label}</span>
            <span style={{ fontSize:13, fontWeight:600, color:d.color, fontFamily:"'JetBrains Mono',monospace" }}>{d.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function CVSSBar({ score, maxScore = 10 }) {
  const pct = (score / maxScore) * 100;
  const color = score >= 9 ? "#FF3D57" : score >= 7 ? "#FF7043" : score >= 4 ? "#FFC107" : "#00E5FF";
  return (
    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
      <div style={{ flex:1, height:6, background:"#1C2940", borderRadius:3, overflow:"hidden" }}>
        <div style={{ width:`${pct}%`, height:"100%", background:color, borderRadius:3, transition:"width .4s" }} />
      </div>
      <span style={{ fontSize:12, color, fontFamily:"'JetBrains Mono',monospace", fontWeight:600, minWidth:28 }}>{score.toFixed(1)}</span>
    </div>
  );
}

// ── Main Dashboard ─────────────────────────────────────────────────────────

export default function Dashboard() {
  const [target, setTarget] = useState("demo.example.com");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentModule, setCurrentModule] = useState("");
  const [vulns, setVulns] = useState([]);
  const [endpoints, setEndpoints] = useState([]);
  const [recon, setRecon] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [sevFilter, setSevFilter] = useState("all");
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [log, setLog] = useState([]);
  const progressRef = useRef(null);

  // Inject global CSS
  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = GLOBAL_CSS;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  const addLog = useCallback((msg, type = "info") => {
    const colors = { info:"#00E5FF", success:"#00FF9D", warn:"#FFC107", error:"#FF3D57" };
    setLog(prev => [...prev.slice(-50), { msg, color: colors[type], ts: new Date().toLocaleTimeString() }]);
  }, []);

  // Simulate scan
  const startScan = useCallback(() => {
    if (!target) return;
    setScanning(true);
    setProgress(0);
    setVulns([]);
    setEndpoints([]);
    setRecon(null);
    setLog([]);
    addLog(`Starting scan on ${target}`, "info");

    const phases = [
      { module:"Reconnaissance", pct:20, duration:1800,
        action: () => { setRecon(MOCK_RECON); addLog(`Found ${MOCK_RECON.subdomains.length} subdomains`, "success"); } },
      { module:"Web Crawler", pct:38, duration:2000,
        action: () => { setEndpoints(MOCK_ENDPOINTS); addLog(`Crawled ${MOCK_ENDPOINTS.length} endpoints`, "success"); } },
      { module:"AI Attack Planning", pct:45, duration:1000,
        action: () => addLog("Generated 6 attack vectors", "success") },
      { module:"SQL Injection Tests", pct:60, duration:2200,
        action: () => { setVulns(v => [...v, ...MOCK_VULNS.filter(x => x.type.includes("SQL"))]); addLog("SQLi: 2 vulnerabilities found!", "warn"); } },
      { module:"XSS Scanner", pct:72, duration:1800,
        action: () => { setVulns(v => [...v, ...MOCK_VULNS.filter(x => x.type === "XSS")]); addLog("XSS: 2 vulnerabilities found!", "warn"); } },
      { module:"Auth & IDOR Tests", pct:85, duration:2000,
        action: () => { setVulns(v => [...v, ...MOCK_VULNS.filter(x => !x.type.includes("SQL") && x.type !== "XSS")]); addLog("Auth/IDOR: 4 findings!", "warn"); } },
      { module:"Risk Scoring", pct:93, duration:800,
        action: () => addLog("Risk scoring complete", "success") },
      { module:"Generating Reports", pct:100, duration:600,
        action: () => { addLog("Scan complete! Reports saved.", "success"); } },
    ];

    let elapsed = 0;
    phases.forEach(phase => {
      setTimeout(() => {
        setCurrentModule(phase.module);
        setProgress(phase.pct);
        phase.action();
        if (phase.pct === 100) setScanning(false);
      }, elapsed);
      elapsed += phase.duration;
    });
  }, [target, addLog]);

  const stopScan = () => {
    setScanning(false);
    addLog("Scan stopped by user.", "warn");
    clearInterval(progressRef.current);
  };

  const filteredVulns = sevFilter === "all" ? vulns : vulns.filter(v => v.severity === sevFilter);
  const critCount = vulns.filter(v => v.severity === "critical").length;
  const highCount = vulns.filter(v => v.severity === "high").length;
  const medCount = vulns.filter(v => v.severity === "medium").length;
  const lowCount = vulns.filter(v => v.severity === "low").length;

  const TAB_STYLE = (active) => ({
    padding:"8px 16px", borderRadius:8, border:"none", cursor:"pointer",
    fontSize:13, fontWeight:600, fontFamily:"'Syne',sans-serif",
    background: active ? "rgba(0,229,255,.15)" : "transparent",
    color: active ? "#00E5FF" : "#5C7090",
    transition:"all .2s", letterSpacing:".04em",
  });

  return (
    <div style={{ minHeight:"100vh", background:"#070B14" }}>
      {/* ── Top Navigation ── */}
      <nav style={{
        background:"#0C1220", borderBottom:"1px solid #1C2940",
        padding:"0 24px", display:"flex", alignItems:"center",
        justifyContent:"space-between", height:56, position:"sticky", top:0, zIndex:100,
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ fontSize:18, fontWeight:800, color:"#00E5FF", fontFamily:"'Syne',sans-serif", letterSpacing:".02em" }}>
            🔍 BugBounty<span style={{ color:"#00FF9D" }}>AI</span>
          </div>
          <span style={{ fontSize:10, color:"#5C7090", background:"#1C2940", padding:"2px 8px", borderRadius:10 }}>v1.0.0</span>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          {["overview","vulnerabilities","endpoints","recon","console"].map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} style={TAB_STYLE(activeTab === tab)}>
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          {scanning && (
            <div style={{ display:"flex", alignItems:"center", gap:6, fontSize:12, color:"#00E5FF" }}>
              <span style={{ animation:"pulse-glow 1s infinite", display:"inline-block", width:6, height:6, background:"#00E5FF", borderRadius:"50%" }} />
              {currentModule}
            </div>
          )}
          <div style={{ width:64, height:8, background:"#1C2940", borderRadius:4, overflow:"hidden" }}>
            <div style={{ width:`${progress}%`, height:"100%", background:"linear-gradient(90deg,#00E5FF,#00FF9D)", transition:"width .4s" }} />
          </div>
          <span style={{ fontSize:12, color:"#00E5FF", fontFamily:"'JetBrains Mono',monospace" }}>{progress}%</span>
        </div>
      </nav>

      <div style={{ maxWidth:1280, margin:"0 auto", padding:"24px 24px" }}>
        {/* ── Scan Controls ── */}
        <ScanControls scanning={scanning} onStart={startScan} onStop={stopScan} target={target} setTarget={setTarget} />

        {/* ── Ethics Banner ── */}
        <div style={{
          background:"rgba(255,112,67,.08)", border:"1px solid rgba(255,112,67,.25)",
          borderRadius:10, padding:"10px 16px", marginBottom:24,
          fontSize:12, color:"#FF7043", display:"flex", alignItems:"center", gap:8,
        }}>
          ⚠️ <strong>Authorized use only.</strong> For bug bounty programs, penetration testing, or systems you own.
        </div>

        {/* ────────────────────────── OVERVIEW TAB ────────────────────────── */}
        {activeTab === "overview" && (
          <div className="animate-slide-in">
            {/* Stats row */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))", gap:16, marginBottom:24 }}>
              <StatCard label="Total Findings" value={vulns.length} color="#C9D8F0" />
              <StatCard label="Critical" value={critCount} color="#FF3D57" />
              <StatCard label="High" value={highCount} color="#FF7043" />
              <StatCard label="Medium" value={medCount} color="#FFC107" />
              <StatCard label="Low" value={lowCount} color="#00E5FF" />
              <StatCard label="Endpoints" value={endpoints.length} color="#00FF9D" />
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16, marginBottom:24 }}>
              {/* Severity donut */}
              <div className="card" style={{ padding:24 }}>
                <div style={{ fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif", marginBottom:16 }}>Severity Distribution</div>
                {vulns.length > 0 ? <SeverityDonut vulns={vulns} /> : (
                  <div style={{ color:"#5C7090", fontSize:13, textAlign:"center", padding:32 }}>Run a scan to see results</div>
                )}
              </div>

              {/* Scan progress */}
              <div className="card" style={{ padding:24, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
                <div style={{ position:"relative", width:80, height:80, marginBottom:12 }}>
                  <ProgressRing pct={progress} color={progress === 100 ? "#00FF9D" : "#00E5FF"} />
                  <div style={{ position:"absolute", inset:0, display:"flex", alignItems:"center", justifyContent:"center", fontSize:16, fontWeight:700, color:"#FFF", fontFamily:"'Syne',sans-serif" }}>{progress}%</div>
                </div>
                <div style={{ fontSize:13, color:"#C9D8F0", textAlign:"center" }}>{scanning ? currentModule : progress === 100 ? "Scan Complete ✅" : "Ready"}</div>
                <div style={{ fontSize:11, color:"#5C7090", marginTop:4 }}>{target || "No target set"}</div>
              </div>

              {/* Top CVSS */}
              <div className="card" style={{ padding:24 }}>
                <div style={{ fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif", marginBottom:16 }}>Top CVSS Scores</div>
                <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                  {[...vulns].sort((a,b) => b.cvss - a.cvss).slice(0, 4).map(v => (
                    <div key={v.id}>
                      <div style={{ fontSize:11, color:"#C9D8F0", marginBottom:4, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.title}</div>
                      <CVSSBar score={v.cvss} />
                    </div>
                  ))}
                  {vulns.length === 0 && <div style={{ color:"#5C7090", fontSize:13 }}>No data yet</div>}
                </div>
              </div>
            </div>

            {/* Recent findings */}
            <div className="card" style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif", marginBottom:16 }}>Recent Findings</div>
              {vulns.length === 0 ? (
                <div style={{ color:"#5C7090", textAlign:"center", padding:32, fontSize:13 }}>No vulnerabilities found yet. Start a scan.</div>
              ) : (
                <table style={{ width:"100%", borderCollapse:"collapse" }}>
                  <thead>
                    <tr style={{ borderBottom:"1px solid #1C2940" }}>
                      {["Severity","Type","Title","URL","CVSS"].map(h => (
                        <th key={h} style={{ padding:"8px 12px", textAlign:"left", fontSize:11, color:"#5C7090", textTransform:"uppercase", letterSpacing:".08em" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[...vulns].slice(0, 6).map(v => (
                      <tr key={v.id} style={{ borderBottom:"1px solid #111827", cursor:"pointer", transition:"background .15s" }}
                        onClick={() => { setSelectedVuln(v); setActiveTab("vulnerabilities"); }}
                        onMouseEnter={e => e.currentTarget.style.background="#141E35"}
                        onMouseLeave={e => e.currentTarget.style.background="transparent"}
                      >
                        <td style={{ padding:"10px 12px" }}><SevBadge severity={v.severity} /></td>
                        <td style={{ padding:"10px 12px", fontSize:12, color:"#C9D8F0" }}>{v.type}</td>
                        <td style={{ padding:"10px 12px", fontSize:13, color:"#FFF", maxWidth:260, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v.title}</td>
                        <td style={{ padding:"10px 12px", fontSize:12, color:"#00E5FF", fontFamily:"'JetBrains Mono',monospace" }}>{v.url}</td>
                        <td style={{ padding:"10px 12px" }}><CVSSBar score={v.cvss} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* ──────────────── VULNERABILITIES TAB ──────────────── */}
        {activeTab === "vulnerabilities" && (
          <div className="animate-slide-in">
            <div style={{ display:"flex", gap:10, marginBottom:20, flexWrap:"wrap" }}>
              {["all","critical","high","medium","low"].map(sev => (
                <button key={sev} onClick={() => setSevFilter(sev)} style={{
                  padding:"6px 16px", borderRadius:20, border:"1px solid",
                  borderColor: sevFilter === sev ? SEV_STYLES[sev]?.border || "#00E5FF" : "#1C2940",
                  background: sevFilter === sev ? SEV_STYLES[sev]?.bg || "rgba(0,229,255,.1)" : "transparent",
                  color: sevFilter === sev ? SEV_STYLES[sev]?.text || "#00E5FF" : "#5C7090",
                  cursor:"pointer", fontSize:12, fontWeight:600, fontFamily:"'Syne',sans-serif",
                  transition:"all .2s",
                }}>
                  {sev.toUpperCase()} {sev !== "all" && `(${vulns.filter(v => v.severity === sev).length})`}
                </button>
              ))}
            </div>

            <div style={{ display:"flex", gap:20 }}>
              {/* Vuln list */}
              <div style={{ flex:1 }}>
                {filteredVulns.length === 0 ? (
                  <div className="card" style={{ padding:48, textAlign:"center", color:"#5C7090" }}>
                    {vulns.length === 0 ? "Start a scan to discover vulnerabilities." : "No vulnerabilities match this filter."}
                  </div>
                ) : (
                  filteredVulns.map(v => (
                    <div key={v.id} className="card card-hover" onClick={() => setSelectedVuln(selectedVuln?.id === v.id ? null : v)}
                      style={{ padding:20, marginBottom:12, cursor:"pointer", borderColor: selectedVuln?.id === v.id ? "#00E5FF40" : "#1C2940" }}>
                      <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:8 }}>
                        <SevBadge severity={v.severity} />
                        <span style={{ fontSize:11, color:"#5C7090", fontFamily:"'JetBrains Mono',monospace" }}>{v.type}</span>
                        <span style={{ marginLeft:"auto", fontSize:13, fontWeight:700, color: v.cvss >= 9 ? "#FF3D57" : v.cvss >= 7 ? "#FF7043" : "#FFC107", fontFamily:"'JetBrains Mono',monospace" }}>CVSS {v.cvss.toFixed(1)}</span>
                      </div>
                      <div style={{ fontSize:15, fontWeight:600, color:"#FFF", marginBottom:6 }}>{v.title}</div>
                      <div style={{ fontSize:12, color:"#00E5FF", fontFamily:"'JetBrains Mono',monospace" }}>{v.url}</div>

                      {selectedVuln?.id === v.id && (
                        <div style={{ marginTop:16, paddingTop:16, borderTop:"1px solid #1C2940" }}>
                          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                            {[
                              ["Parameter", v.param, "#A855F7"],
                              ["Confidence", `${Math.round(v.confidence * 100)}%`, "#00FF9D"],
                              ["Discovered", v.discovered, "#C9D8F0"],
                              ["CWE", "CWE-89", "#FFC107"],
                            ].map(([label, val, color]) => (
                              <div key={label}>
                                <div style={{ fontSize:10, color:"#5C7090", textTransform:"uppercase", letterSpacing:".08em", marginBottom:4 }}>{label}</div>
                                <div style={{ fontSize:13, color, fontFamily:"'JetBrains Mono',monospace" }}>{val}</div>
                              </div>
                            ))}
                          </div>
                          <div style={{ background:"#0C1220", borderRadius:8, padding:"12px 16px", fontFamily:"'JetBrains Mono',monospace", fontSize:12, color:"#00FF9D" }}>
                            # Proof of Concept<br/>
                            $ curl -G "{v.url}" --data-urlencode "{v.param}=' OR 1=1--"
                          </div>
                          <div style={{ background:"rgba(0,255,157,.05)", border:"1px solid rgba(0,255,157,.2)", borderRadius:8, padding:14, marginTop:12 }}>
                            <div style={{ fontSize:11, fontWeight:600, color:"#00FF9D", textTransform:"uppercase", letterSpacing:".08em", marginBottom:8 }}>✅ Remediation</div>
                            <div style={{ fontSize:13, color:"#C9D8F0" }}>Use parameterized queries. Implement input validation. Apply WAF rules. Enable least-privilege DB accounts.</div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* ──────────────── ENDPOINTS TAB ──────────────── */}
        {activeTab === "endpoints" && (
          <div className="animate-slide-in">
            <div className="card">
              <div style={{ padding:"16px 20px", borderBottom:"1px solid #1C2940", fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif" }}>
                Attack Surface Map — {endpoints.length} endpoints discovered
              </div>
              {endpoints.length === 0 ? (
                <div style={{ padding:48, textAlign:"center", color:"#5C7090" }}>Run a scan to discover endpoints.</div>
              ) : (
                endpoints.map((ep, i) => (
                  <div key={i} style={{ display:"flex", alignItems:"center", gap:12, padding:"12px 20px", borderBottom:"1px solid #0C1220", transition:"background .15s" }}
                    onMouseEnter={e => e.currentTarget.style.background="#141E35"}
                    onMouseLeave={e => e.currentTarget.style.background="transparent"}
                  >
                    <MethodBadge method={ep.method} />
                    <span style={{ flex:1, fontFamily:"'JetBrains Mono',monospace", fontSize:13, color:"#C9D8F0" }}>{ep.url}</span>
                    <span style={{ fontSize:12, color: ep.status === 200 ? "#00FF9D" : ep.status >= 300 ? "#FFC107" : "#FF3D57" }}>{ep.status}</span>
                    {ep.api && <span style={{ fontSize:10, padding:"2px 8px", background:"rgba(168,85,247,.15)", color:"#A855F7", border:"1px solid #A855F7", borderRadius:10, fontWeight:700 }}>API</span>}
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* ──────────────── RECON TAB ──────────────── */}
        {activeTab === "recon" && (
          <div className="animate-slide-in">
            {!recon ? (
              <div className="card" style={{ padding:48, textAlign:"center", color:"#5C7090" }}>Run a scan to see reconnaissance results.</div>
            ) : (
              <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))", gap:20 }}>
                <div className="card" style={{ padding:24 }}>
                  <div style={{ fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif", marginBottom:16 }}>🌐 Subdomains ({recon.subdomains.length})</div>
                  {recon.subdomains.map(s => (
                    <div key={s} style={{ padding:"6px 0", borderBottom:"1px solid #1C2940", fontFamily:"'JetBrains Mono',monospace", fontSize:12, color:"#00E5FF" }}>{s}</div>
                  ))}
                </div>
                <div className="card" style={{ padding:24 }}>
                  <div style={{ fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif", marginBottom:16 }}>🛠️ Technologies</div>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
                    {recon.technologies.map(t => (
                      <span key={t} style={{ padding:"4px 12px", background:"rgba(0,229,255,.1)", color:"#00E5FF", border:"1px solid rgba(0,229,255,.3)", borderRadius:16, fontSize:12 }}>{t}</span>
                    ))}
                  </div>
                </div>
                <div className="card" style={{ padding:24 }}>
                  <div style={{ fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif", marginBottom:16 }}>🔒 Security Headers</div>
                  {Object.entries(recon.headers).map(([k, v]) => (
                    <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"8px 0", borderBottom:"1px solid #1C2940" }}>
                      <span style={{ fontSize:12, color:"#C9D8F0" }}>{k}</span>
                      <span style={{ fontSize:12, color: v.includes("MISSING") ? "#FF3D57" : "#00FF9D", fontFamily:"'JetBrains Mono',monospace" }}>{v}</span>
                    </div>
                  ))}
                </div>
                <div className="card" style={{ padding:24 }}>
                  <div style={{ fontSize:13, fontWeight:600, color:"#FFF", fontFamily:"'Syne',sans-serif", marginBottom:16 }}>📡 IP Addresses</div>
                  {recon.ips.map(ip => (
                    <div key={ip} style={{ padding:"6px 0", fontFamily:"'JetBrains Mono',monospace", fontSize:13, color:"#00FF9D" }}>{ip}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ──────────────── CONSOLE TAB ──────────────── */}
        {activeTab === "console" && (
          <div className="animate-slide-in">
            <div className="card" style={{ padding:0, overflow:"hidden" }}>
              <div style={{ padding:"12px 20px", background:"#0C1220", borderBottom:"1px solid #1C2940", fontFamily:"'JetBrains Mono',monospace", fontSize:12, color:"#5C7090", display:"flex", alignItems:"center", gap:8 }}>
                <span style={{ width:10, height:10, borderRadius:"50%", background: scanning ? "#00FF9D" : "#5C7090", animation: scanning ? "pulse-glow 1s infinite" : "none" }} />
                Scanner Console — {scanning ? "RUNNING" : "IDLE"}
              </div>
              <div style={{ padding:20, fontFamily:"'JetBrains Mono',monospace", fontSize:12, minHeight:400, maxHeight:500, overflowY:"auto", background:"#070B14" }}>
                {log.length === 0 ? (
                  <span style={{ color:"#5C7090" }}>$ awaiting scan start…</span>
                ) : (
                  log.map((entry, i) => (
                    <div key={i} style={{ marginBottom:4 }}>
                      <span style={{ color:"#5C7090" }}>[{entry.ts}]</span>{" "}
                      <span style={{ color: entry.color }}>{entry.msg}</span>
                    </div>
                  ))
                )}
                {scanning && <span style={{ color:"#00E5FF", animation:"pulse-glow 1s infinite", display:"inline-block" }}>▌</span>}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
