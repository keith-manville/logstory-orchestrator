import { useState, useEffect, useRef, useCallback } from "react";

// ─── SOURCETYPE → SECOPS LOG TYPE MAP ────────────────────────────────────────
// Based on actual YAML sourcetypes seen in splunk/attack_data
const ST_MAP = {
  "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational":   { lt:"WINDOWS_SYSMON",  color:"#3b82f6" },
  "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (4104)": { lt:"WINDOWS_SYSMON", color:"#3b82f6" },
  "XmlWinEventLog:Security":                               { lt:"WINEVTLOG",       color:"#8b5cf6" },
  "XmlWinEventLog:System":                                 { lt:"WINEVTLOG",       color:"#8b5cf6" },
  "XmlWinEventLog:Application":                            { lt:"WINEVTLOG",       color:"#8b5cf6" },
  "WinEventLog:Security":                                  { lt:"WINEVTLOG",       color:"#8b5cf6" },
  "WinEventLog:System":                                    { lt:"WINEVTLOG",       color:"#8b5cf6" },
  "WinEventLog:Microsoft-Windows-PowerShell/Operational":  { lt:"POWERSHELL",      color:"#06b6d4" },
  "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational": { lt:"POWERSHELL",    color:"#06b6d4" },
  "crowdstrike:events:sensor":                             { lt:"CS_EDR",          color:"#f59e0b" },
  "crowdstrike:events:falcon":                             { lt:"CS_EDR",          color:"#f59e0b" },
  "crowdstrike":                                           { lt:"CS_EDR",          color:"#f59e0b" },
  "sysmon:linux":                                          { lt:"LINUX_SYSMON",    color:"#10b981" },
  "Syslog:Linux-Sysmon/Operational":                       { lt:"LINUX_SYSMON",    color:"#10b981" },
  "bro:dns:json":                                          { lt:"BRO_JSON",        color:"#ec4899" },
  "bro:conn:json":                                         { lt:"BRO_JSON",        color:"#ec4899" },
  "stream:dns":                                            { lt:"WINEVTLOG",       color:"#8b5cf6" },
  "suricata":                                              { lt:"SURICATA_EVE_JSON", color:"#a855f7" },
  "osquery:results":                                       { lt:"OSQUERY",         color:"#64748b" },
};

const getLT  = (sources=[]) => {
  for (const s of sources) {
    if (ST_MAP[s]) return ST_MAP[s];
  }
  return { lt:"UNKNOWN", color:"#475569" };
};

// ─── MITRE TACTIC MAP ────────────────────────────────────────────────────────
const TACTIC_MAP = {
  T1001:"Command and Control",T1003:"Credential Access",T1005:"Collection",
  T1007:"Discovery",T1010:"Discovery",T1011:"Exfiltration",T1012:"Discovery",
  T1014:"Defense Evasion",T1016:"Discovery",T1018:"Discovery",T1020:"Exfiltration",
  T1021:"Lateral Movement",T1025:"Collection",T1027:"Defense Evasion",
  T1029:"Exfiltration",T1030:"Exfiltration",T1033:"Discovery",T1036:"Defense Evasion",
  T1037:"Persistence",T1039:"Collection",T1040:"Credential Access",
  T1041:"Exfiltration",T1046:"Discovery",T1047:"Execution",T1048:"Exfiltration",
  T1049:"Discovery",T1053:"Persistence",T1055:"Privilege Escalation",
  T1056:"Collection",T1057:"Discovery",T1059:"Execution",T1068:"Privilege Escalation",
  T1069:"Discovery",T1070:"Defense Evasion",T1071:"Command and Control",
  T1072:"Lateral Movement",T1074:"Collection",T1078:"Persistence",T1080:"Impact",
  T1082:"Discovery",T1083:"Discovery",T1087:"Discovery",T1090:"Command and Control",
  T1091:"Lateral Movement",T1092:"Command and Control",T1095:"Command and Control",
  T1098:"Persistence",T1102:"Command and Control",T1104:"Command and Control",
  T1105:"Command and Control",T1106:"Execution",T1110:"Credential Access",
  T1111:"Credential Access",T1112:"Defense Evasion",T1113:"Collection",
  T1114:"Collection",T1115:"Collection",T1119:"Collection",T1120:"Discovery",
  T1123:"Collection",T1124:"Discovery",T1125:"Collection",T1127:"Defense Evasion",
  T1129:"Execution",T1132:"Command and Control",T1133:"Persistence",
  T1134:"Privilege Escalation",T1135:"Discovery",T1136:"Persistence",
  T1137:"Persistence",T1140:"Defense Evasion",T1176:"Persistence",
  T1185:"Collection",T1187:"Credential Access",T1189:"Initial Access",
  T1190:"Initial Access",T1195:"Initial Access",T1197:"Defense Evasion",
  T1199:"Initial Access",T1200:"Initial Access",T1201:"Discovery",
  T1202:"Defense Evasion",T1203:"Execution",T1204:"Execution",T1205:"Defense Evasion",
  T1207:"Defense Evasion",T1210:"Lateral Movement",T1211:"Defense Evasion",
  T1212:"Credential Access",T1213:"Collection",T1216:"Defense Evasion",
  T1217:"Discovery",T1218:"Defense Evasion",T1219:"Command and Control",
  T1220:"Defense Evasion",T1221:"Defense Evasion",T1480:"Defense Evasion",
  T1482:"Discovery",T1484:"Privilege Escalation",T1485:"Impact",T1486:"Impact",
  T1489:"Impact",T1490:"Impact",T1491:"Impact",T1495:"Impact",T1496:"Impact",
  T1497:"Defense Evasion",T1498:"Impact",T1499:"Impact",T1518:"Discovery",
  T1525:"Persistence",T1526:"Discovery",T1527:"Persistence",T1528:"Credential Access",
  T1529:"Impact",T1530:"Collection",T1531:"Impact",T1534:"Lateral Movement",
  T1535:"Defense Evasion",T1537:"Exfiltration",T1538:"Discovery",
  T1539:"Credential Access",T1542:"Defense Evasion",T1543:"Persistence",
  T1546:"Persistence",T1547:"Persistence",T1548:"Privilege Escalation",
  T1550:"Lateral Movement",T1552:"Credential Access",T1553:"Defense Evasion",
  T1554:"Persistence",T1555:"Credential Access",T1556:"Credential Access",
  T1557:"Credential Access",T1558:"Credential Access",T1559:"Execution",
  T1560:"Collection",T1561:"Impact",T1562:"Defense Evasion",T1563:"Lateral Movement",
  T1564:"Defense Evasion",T1565:"Impact",T1566:"Initial Access",T1567:"Exfiltration",
  T1568:"Command and Control",T1569:"Execution",T1570:"Lateral Movement",
  T1571:"Command and Control",T1572:"Command and Control",T1574:"Persistence",
  T1578:"Defense Evasion",T1580:"Discovery",T1583:"Resource Development",
  T1584:"Resource Development",T1585:"Resource Development",T1586:"Resource Development",
  T1587:"Resource Development",T1588:"Resource Development",T1589:"Reconnaissance",
  T1590:"Reconnaissance",T1591:"Reconnaissance",T1592:"Reconnaissance",
  T1593:"Reconnaissance",T1594:"Reconnaissance",T1595:"Reconnaissance",
  T1596:"Reconnaissance",T1597:"Reconnaissance",T1598:"Reconnaissance",
  T1599:"Defense Evasion",T1600:"Defense Evasion",T1601:"Defense Evasion",
  T1602:"Collection",T1606:"Credential Access",T1608:"Resource Development",
  T1609:"Execution",T1610:"Execution",T1611:"Privilege Escalation",
  T1612:"Defense Evasion",T1613:"Discovery",T1614:"Discovery",T1615:"Discovery",
  T1619:"Discovery",T1620:"Defense Evasion",T1621:"Credential Access",
  T1647:"Defense Evasion",T1648:"Execution",T1649:"Credential Access",
  T1650:"Resource Development",T1651:"Execution",T1652:"Discovery",T1653:"Impact",
  T1654:"Discovery",T1656:"Defense Evasion",T1657:"Impact",T1659:"Command and Control",
};

const TACTIC_COLORS = {
  "Initial Access":"#ef4444","Execution":"#f97316","Persistence":"#eab308",
  "Privilege Escalation":"#a855f7","Defense Evasion":"#06b6d4","Credential Access":"#ec4899",
  "Discovery":"#64748b","Lateral Movement":"#f59e0b","Collection":"#10b981",
  "Command and Control":"#3b82f6","Exfiltration":"#8b5cf6","Impact":"#dc2626",
  "Reconnaissance":"#475569","Resource Development":"#334155","Unknown":"#1e293b",
};

const getTactic = id => TACTIC_MAP[id?.split(".")[0]] || "Unknown";
const tacticColor = id => TACTIC_COLORS[getTactic(id)] || "#1e293b";

const REGIONS = ["US","EU","ASIA","US-EAST1","EU-WEST2","ASIA-SOUTH1"];

// ─── GITHUB API HELPERS ───────────────────────────────────────────────────────
// All log files served via media.githubusercontent.com — no git clone needed
const RAW_BASE = "https://media.githubusercontent.com/media/splunk/attack_data/master";
const API_BASE = "https://api.github.com/repos/splunk/attack_data";
const RAW_CONTENT = "https://raw.githubusercontent.com/splunk/attack_data/master";

// Parse a YAML file (minimal parser for attack_data yml structure)
function parseAttackDataYaml(text) {
  const result = { mitre_technique:[], datasets:[], description:"", environment:"" };
  const lines = text.split("\n");
  let inDatasets = false, inDataset = false, currentDs = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith("description:")) {
      result.description = trimmed.replace("description:","").replace(/^'+|'+$/g,"").trim();
    }
    if (trimmed.startsWith("environment:")) {
      result.environment = trimmed.replace("environment:","").trim();
    }
    if (trimmed.startsWith("- T") && lines[i-1]?.trim() === "mitre_technique:") {
      result.mitre_technique.push(trimmed.replace("- ","").trim());
    }
    if (trimmed.startsWith("- T") && result.mitre_technique.length > 0 && !inDatasets) {
      result.mitre_technique.push(trimmed.replace("- ","").trim());
    }
    if (trimmed === "mitre_technique:") { /* next lines are techniques */ }
    if (trimmed === "datasets:") { inDatasets = true; continue; }

    if (inDatasets) {
      if (trimmed.startsWith("- name:")) {
        if (currentDs) result.datasets.push(currentDs);
        currentDs = { name: trimmed.replace("- name:","").trim(), path:"", sourcetype:"", source:"" };
      } else if (currentDs && trimmed.startsWith("path:")) {
        currentDs.path = trimmed.replace("path:","").trim();
      } else if (currentDs && trimmed.startsWith("sourcetype:")) {
        currentDs.sourcetype = trimmed.replace("sourcetype:","").trim();
      } else if (currentDs && trimmed.startsWith("source:")) {
        currentDs.source = trimmed.replace("source:","").trim();
      } else if (!trimmed.startsWith("-") && !trimmed.startsWith("name:") && !trimmed.startsWith("path:") && !trimmed.startsWith("sourcetype:") && !trimmed.startsWith("source:") && trimmed && !trimmed.startsWith("#") && !line.startsWith(" ") && !line.startsWith("\t")) {
        // top-level key — end of datasets block
        if (currentDs) { result.datasets.push(currentDs); currentDs = null; }
        inDatasets = false;
      }
    }
  }
  if (currentDs) result.datasets.push(currentDs);
  return result;
}

// Convert a repo path or media URL to canonical media URL
function toMediaUrl(path) {
  if (!path) return "";
  if (path.startsWith("https://media.githubusercontent.com")) return path;
  if (path.startsWith("http")) return path;
  const clean = path.startsWith("/") ? path.slice(1) : path;
  return `${RAW_BASE}/${clean}`;
}

// ─── STATIC ENTITIES (Attack Range lab — these are real, from the datasets) ──
const STATIC_ENTITIES = [
  {id:"e1",type:"hostname",value:"ar-win-dc.attackrange.local",role:"Domain Controller",techniques:["T1003.003","T1003.006","T1558.001","T1558.003","T1550.002"],desc:"Primary AD domain controller in Attack Range"},
  {id:"e2",type:"hostname",value:"ar-win-2.attackrange.local",role:"Workstation",techniques:["T1003.001","T1059.001","T1082","T1053.005","T1218"],desc:"Primary victim Windows workstation"},
  {id:"e3",type:"hostname",value:"ar-win-3.attackrange.local",role:"Workstation",techniques:["T1047","T1550.002"],desc:"Secondary workstation — lateral movement target"},
  {id:"e4",type:"user",value:"ATTACKRANGE\\Administrator",role:"Domain Admin",techniques:["T1003.001","T1003.003","T1003.006","T1558.003"],desc:"Built-in domain administrator account"},
  {id:"e5",type:"user",value:"ATTACKRANGE\\splunk",role:"Service Account",techniques:["T1053.005","T1047"],desc:"Splunk service account — abused in persistence scenarios"},
  {id:"e6",type:"user",value:"NT AUTHORITY\\SYSTEM",role:"System",techniques:["T1003.001","T1059.001"],desc:"SYSTEM context — highest privilege processes"},
  {id:"e7",type:"process",value:"lsass.exe",role:"Target Process",techniques:["T1003.001","T1003.006"],desc:"Local Security Authority Subsystem — primary cred dump target"},
  {id:"e8",type:"process",value:"procdump.exe",role:"Attack Tool",techniques:["T1003.001"],desc:"Sysinternals ProcDump — LSASS memory dump"},
  {id:"e9",type:"process",value:"mimikatz.exe",role:"Attack Tool",techniques:["T1003.003","T1003.006","T1558.001"],desc:"Credential extraction: DCSync, golden ticket, sekurlsa"},
  {id:"e10",type:"process",value:"powershell.exe",role:"Interpreter",techniques:["T1059.001","T1053.005","T1047","T1003.006"],desc:"PowerShell — primary scripting engine for attack chains"},
  {id:"e11",type:"process",value:"cmd.exe",role:"Interpreter",techniques:["T1082","T1218","T1047"],desc:"Command prompt — common parent of attack tool execution"},
  {id:"e12",type:"process",value:"wmic.exe",role:"Attack Tool",techniques:["T1047"],desc:"WMI CLI — remote execution and lateral movement"},
  {id:"e13",type:"hash",value:"aad3b435b51404eeaad3b435b51404ee",role:"NTLM Hash",techniques:["T1550.002"],desc:"Empty NTLM password hash — seen in pass-the-hash"},
  {id:"e14",type:"domain",value:"ATTACKRANGE.LOCAL",role:"AD Domain",techniques:["T1003.006","T1558.001","T1558.003","T1550.002"],desc:"Active Directory domain for Attack Range lab"},
  {id:"e15",type:"ip",value:"10.0.1.4",role:"DC IP",techniques:["T1003.006","T1558.001","T1558.003","T1550.002"],desc:"IP of domain controller"},
  {id:"e16",type:"ip",value:"10.0.1.12",role:"Workstation IP",techniques:["T1047","T1550.002"],desc:"Internal IP of victim workstation"},
  {id:"e17",type:"process",value:"svchost.exe",role:"System Process",techniques:["T1053.005"],desc:"Service host — process injection target"},
  {id:"e18",type:"file",value:"C:\\Windows\\Temp\\",role:"Staging Path",techniques:["T1003.001","T1218"],desc:"Common payload staging directory"},
  {id:"e19",type:"process",value:"ntdsutil.exe",role:"Attack Tool",techniques:["T1003.003"],desc:"AD database utility — used for NTDS.dit extraction"},
  {id:"e20",type:"process",value:"reg.exe",role:"Attack Tool",techniques:["T1547.001","T1112"],desc:"Registry CLI — persistence and config manipulation"},
];

// ─── FLOW TEMPLATES ───────────────────────────────────────────────────────────
const FLOW_TEMPLATES = [
  { id:"tpl1", name:"APT Credential Theft", color:"#ef4444",
    desc:"Initial phishing → PowerShell execution → LSASS dump → DCSync → Golden Ticket",
    techniques:["T1566.001","T1059.001","T1003.001","T1003.006","T1558.001"] },
  { id:"tpl2", name:"Ransomware Chain", color:"#f97316",
    desc:"Execution → Persistence → Lateral movement → File encryption → Inhibit recovery",
    techniques:["T1059.001","T1053.005","T1047","T1486","T1490"] },
  { id:"tpl3", name:"Kerberos Abuse", color:"#a855f7",
    desc:"Kerberoasting → Pass-the-Hash → Golden Ticket → DCSync",
    techniques:["T1558.003","T1550.002","T1558.001","T1003.006"] },
  { id:"tpl4", name:"CTF: Blue Team Hunt", color:"#06b6d4",
    desc:"Discovery-heavy scenario ideal for detection engineering workshops",
    techniques:["T1082","T1059.001","T1053.005","T1047","T1218"] },
  { id:"tpl5", name:"Cobalt Strike C2", color:"#10b981",
    desc:"Spearphish → C2 beacon → Credential access → Lateral movement",
    techniques:["T1566.001","T1572","T1003.001","T1021.001","T1047"] },
];

// ─── SAMPLE JOB HISTORY ──────────────────────────────────────────────────────
const SAMPLE_JOBS = [
  {id:"j1",tenant:"acme-prod",status:"success",startedAt:"2026-03-04T00:01:12Z",duration:94,datasets:3,trigger:"schedule",bytes:1842000},
  {id:"j2",tenant:"demo-us",status:"success",startedAt:"2026-03-04T00:01:18Z",duration:87,datasets:3,trigger:"schedule",bytes:1290000},
  {id:"j3",tenant:"workshop-eu",status:"failed",startedAt:"2026-03-03T00:01:05Z",duration:12,datasets:2,trigger:"schedule",error:"HTTP 403 on media.githubusercontent.com — rate limit or bad URL"},
  {id:"j4",tenant:"acme-prod",status:"success",startedAt:"2026-03-03T00:01:09Z",duration:112,datasets:4,trigger:"schedule",bytes:2640000},
  {id:"j5",tenant:"demo-us",status:"success",startedAt:"2026-03-02T00:01:22Z",duration:79,datasets:3,trigger:"manual",bytes:1290000},
];

// ─── STYLES / PRIMITIVES ──────────────────────────────────────────────────────
const FONTS = `@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700;800&display=swap');`;

const globalCss = `
  ${FONTS}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#020810}
  ::-webkit-scrollbar{width:4px;height:4px}
  ::-webkit-scrollbar-track{background:#040d1c}
  ::-webkit-scrollbar-thumb{background:#162035;border-radius:2px}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
  @keyframes spin{to{transform:rotate(360deg)}}
  @keyframes slideUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
  @keyframes flowBeat{0%,100%{opacity:.35;transform:scaleY(.8)}50%{opacity:1;transform:scaleY(1)}}
  @keyframes shimmer{0%{background-position:-400px 0}100%{background-position:400px 0}}
`;

const mono = { fontFamily:"'IBM Plex Mono',monospace" };
const sans = { fontFamily:"'Space Grotesk',sans-serif" };

function Pill({ label, color, sm, dot }) {
  return (
    <span style={{ display:"inline-flex", alignItems:"center", gap:4,
      padding: sm ? "1px 6px" : "2px 9px",
      borderRadius:4, fontSize: sm ? 9 : 10, ...mono, fontWeight:600,
      background:`${color}14`, color, border:`1px solid ${color}28`, whiteSpace:"nowrap" }}>
      {dot && <span style={{width:5,height:5,borderRadius:"50%",background:color,flexShrink:0}}/>}
      {label}
    </span>
  );
}

function Dot({ status, size=7 }) {
  const c={idle:"#1e3a5f",running:"#22d3ee",success:"#10b981",failed:"#ef4444",warning:"#f59e0b"};
  return <span style={{ display:"inline-block", width:size, height:size, borderRadius:"50%",
    background:c[status]||c.idle, flexShrink:0,
    boxShadow:status==="running"?`0 0 7px ${c.running}`:"none",
    animation:status==="running"?"pulse 1.5s infinite":"none" }}/>;
}

function Card({ children, style={}, onClick, glow }) {
  return (
    <div onClick={onClick} style={{ background:"#060f20",
      border:`1px solid ${glow?"#22d3ee25":"#0c1e38"}`,
      borderRadius:10, padding:16,
      boxShadow: glow?"0 0 20px #22d3ee08":"none",
      cursor:onClick?"pointer":"default",
      transition:"border-color .2s", ...style }}>
      {children}
    </div>
  );
}

function SectionLabel({ children }) {
  return <div style={{ ...mono, fontSize:10, color:"#22d3ee", letterSpacing:"0.12em",
    marginBottom:14, display:"flex", alignItems:"center", gap:8 }}>
    <span style={{color:"#22d3ee55"}}>◈</span> {children}
  </div>;
}

function Inp({ label, value, onChange, placeholder, mono:isMono, rows, disabled }) {
  const base = { background:"#030a17", border:"1px solid #0c1e38", borderRadius:6,
    padding:"8px 12px", color:"#c8d8f0", fontSize:12, outline:"none",
    fontFamily: isMono ? "'IBM Plex Mono',monospace" : "'Space Grotesk',sans-serif",
    width:"100%", opacity: disabled ? .5 : 1 };
  return (
    <label style={{ display:"flex", flexDirection:"column", gap:5 }}>
      {label && <span style={{...mono, fontSize:9, color:"#3d5a7a", letterSpacing:"0.1em", textTransform:"uppercase"}}>{label}</span>}
      {rows
        ? <textarea value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
            rows={rows} disabled={disabled}
            style={{...base, resize:"vertical"}}
            onFocus={e=>e.target.style.borderColor="#22d3ee44"}
            onBlur={e=>e.target.style.borderColor="#0c1e38"}/>
        : <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
            disabled={disabled}
            style={base}
            onFocus={e=>e.target.style.borderColor="#22d3ee44"}
            onBlur={e=>e.target.style.borderColor="#0c1e38"}/>
      }
    </label>
  );
}

function Sel({ label, value, onChange, options }) {
  return (
    <label style={{ display:"flex", flexDirection:"column", gap:5 }}>
      {label && <span style={{...mono, fontSize:9, color:"#3d5a7a", letterSpacing:"0.1em", textTransform:"uppercase"}}>{label}</span>}
      <select value={value} onChange={e=>onChange(e.target.value)}
        style={{ background:"#030a17", border:"1px solid #0c1e38", borderRadius:6,
          padding:"8px 30px 8px 12px", color:"#c8d8f0", ...mono, fontSize:12, outline:"none",
          cursor:"pointer", appearance:"none",
          backgroundImage:`url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%233d5a7a' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E")`,
          backgroundRepeat:"no-repeat", backgroundPosition:"right 10px center" }}>
        {options.map(o=><option key={o.value||o} value={o.value||o}>{o.label||o}</option>)}
      </select>
    </label>
  );
}

function Btn({ children, onClick, variant="primary", sm, style={}, disabled }) {
  const vs = {
    primary:{ background:"linear-gradient(135deg,#0891b2,#0c6e8a)", color:"#fff", border:"none" },
    secondary:{ background:"transparent", color:"#4a6a8a", border:"1px solid #162035" },
    danger:{ background:"transparent", color:"#ef4444", border:"1px solid #3a1515" },
    ghost:{ background:"transparent", color:"#3d5a7a", border:"1px solid #0c1e38" },
    green:{ background:"linear-gradient(135deg,#059669,#047857)", color:"#fff", border:"none" },
  };
  return (
    <button onClick={onClick} disabled={disabled}
      style={{ padding: sm ? "4px 10px" : "8px 18px", borderRadius:6, cursor: disabled?"not-allowed":"pointer",
        ...mono, fontSize: sm?9:11, fontWeight:600, letterSpacing:"0.05em",
        opacity: disabled ? .5 : 1, transition:"opacity .2s",
        ...vs[variant], ...style }}>{children}</button>
  );
}

function CodeBlock({ code, maxH="360px", filename }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ position:"relative" }}>
      {filename && <div style={{...mono, fontSize:9, color:"#3d5a7a", padding:"6px 14px",
        background:"#030a17", borderBottom:"1px solid #0c1e38",
        borderRadius:"8px 8px 0 0", borderTop:"1px solid #0c1e38",
        borderLeft:"1px solid #0c1e38", borderRight:"1px solid #0c1e38"}}>{filename}</div>}
      <button onClick={()=>{navigator.clipboard?.writeText(code);setCopied(true);setTimeout(()=>setCopied(false),2000);}}
        style={{ position:"absolute", top:filename?36:8, right:8, zIndex:1,
          background:copied?"#10b98122":"#0c1e38", border:`1px solid ${copied?"#10b981":"#162035"}`,
          color:copied?"#10b981":"#3d5a7a", borderRadius:4, padding:"3px 8px",
          ...mono, fontSize:9, cursor:"pointer" }}>
        {copied?"✓ copied":"copy"}
      </button>
      <pre style={{ background:"#020810", border:"1px solid #0c1e38",
        borderRadius: filename ? "0 0 8px 8px" : 8,
        padding:"14px 14px 14px 14px", overflow:"auto", maxHeight:maxH, margin:0,
        ...mono, fontSize:10, color:"#4a6a8a", lineHeight:1.7 }}>{code}</pre>
    </div>
  );
}

function Spinner({ size=16 }) {
  return <div style={{ width:size, height:size, border:`2px solid #162035`,
    borderTopColor:"#22d3ee", borderRadius:"50%", animation:"spin 0.8s linear infinite", flexShrink:0 }}/>;
}

function SkeletonRow() {
  return <div style={{ height:52, background:"linear-gradient(90deg,#060f20 25%,#0a1828 50%,#060f20 75%)",
    backgroundSize:"400px 100%", animation:"shimmer 1.4s infinite linear",
    borderRadius:8, border:"1px solid #0c1e38", marginBottom:5 }}/>;
}

// ─── GITHUB API DATASET LOADER ────────────────────────────────────────────────

// In-memory cache so we don't re-fetch on every render
const cache = { folders: null, yamls: {} };

async function fetchTechniqueFolders(token) {
  if (cache.folders) return cache.folders;
  const headers = token ? { Authorization: `token ${token}` } : {};
  const res = await fetch(`${API_BASE}/contents/datasets/attack_techniques`, { headers });
  if (!res.ok) throw new Error(`GitHub API ${res.status}: ${res.statusText}`);
  const dirs = await res.json();
  const folders = dirs.filter(d => d.type === "dir").map(d => d.name);
  cache.folders = folders;
  return folders;
}

async function fetchYamlsForTechnique(technique, token) {
  if (cache.yamls[technique]) return cache.yamls[technique];
  const headers = token ? { Authorization: `token ${token}` } : {};
  // List subdirs (tool folders like atomic_red_team, printnightmare, etc.)
  const res = await fetch(`${API_BASE}/contents/datasets/attack_techniques/${technique}`, { headers });
  if (!res.ok) return [];
  const items = await res.json();
  const subdirs = items.filter(i => i.type === "dir").map(i => i.name);

  const datasets = [];
  for (const tool of subdirs) {
    // Try to find a .yml file
    const r2 = await fetch(`${API_BASE}/contents/datasets/attack_techniques/${technique}/${tool}`, { headers });
    if (!r2.ok) continue;
    const files = await r2.json();
    const yml = files.find(f => f.name.endsWith(".yml"));
    if (!yml) continue;

    // Fetch and parse the YAML
    const r3 = await fetch(`${RAW_CONTENT}/datasets/attack_techniques/${technique}/${tool}/${yml.name}`);
    if (!r3.ok) continue;
    const text = await r3.text();
    const parsed = parseAttackDataYaml(text);

    // Build dataset entries from parsed YAML
    for (const ds of parsed.datasets) {
      if (!ds.path && !ds.name) continue;
      const mediaUrl = toMediaUrl(ds.path);
      const sources = [ds.source, ds.sourcetype].filter(Boolean);
      const ltInfo = getLT(sources);
      datasets.push({
        id: `${technique}/${tool}/${ds.name}`,
        technique,
        tool,
        name: ds.name,
        mediaUrl,
        sourcetype: ds.sourcetype,
        source: ds.source,
        sources,
        lt: ltInfo.lt,
        ltColor: ltInfo.color,
        mitre: parsed.mitre_technique.length ? parsed.mitre_technique : [technique],
        desc: parsed.description || `${technique} dataset — ${tool}`,
        environment: parsed.environment,
        yamlPath: `datasets/attack_techniques/${technique}/${tool}/${yml.name}`,
      });
    }
  }
  cache.yamls[technique] = datasets;
  return datasets;
}

// ─── DATASET BROWSER ──────────────────────────────────────────────────────────

function DatasetBrowser({ flowSteps, setFlowSteps, ghToken, setGhToken }) {
  const [techniques, setTechniques] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [expanded, setExpanded] = useState(null);        // currently expanded technique
  const [techDatasets, setTechDatasets] = useState({});  // technique → datasets[]
  const [loadingTech, setLoadingTech] = useState(null);
  const [tokenInput, setTokenInput] = useState(ghToken);
  const [showTokenForm, setShowTokenForm] = useState(false);

  const loadFolders = async (tok) => {
    setLoading(true); setError(null);
    try {
      const folders = await fetchTechniqueFolders(tok || ghToken);
      setTechniques(folders);
    } catch(e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadFolders(); }, []);

  const expandTechnique = async (tech) => {
    if (expanded === tech) { setExpanded(null); return; }
    setExpanded(tech);
    if (techDatasets[tech]) return;
    setLoadingTech(tech);
    try {
      const ds = await fetchYamlsForTechnique(tech, ghToken);
      setTechDatasets(prev => ({...prev, [tech]: ds}));
    } catch(e) {}
    setLoadingTech(null);
  };

  const addToFlow = (ds) => {
    setFlowSteps(prev => prev.find(s => s.id === ds.id) ? prev : [...prev, ds]);
  };

  const isInFlow = (ds) => flowSteps.some(s => s.id === ds.id);

  const tactics = ["all", ...new Set(techniques.map(t => getTactic(t)).filter(t => t !== "Unknown"))].sort();

  const filteredTechs = techniques.filter(t => {
    const matchSearch = !search || t.toLowerCase().includes(search.toLowerCase());
    const matchTactic = tacticFilter === "all" || getTactic(t) === tacticFilter;
    return matchSearch && matchTactic;
  });

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      {/* token / API setup */}
      <Card style={{ padding:"12px 16px" }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <span style={{ fontSize:14 }}>🔑</span>
            <div>
              <div style={{...sans, fontSize:12, fontWeight:600, color:"#c8d8f0"}}>GitHub API</div>
              <div style={{...mono, fontSize:9, color:"#3d5a7a"}}>
                {ghToken ? "token set — 5,000 req/hr" : "unauthenticated — 60 req/hr (may hit limit)"}
              </div>
            </div>
          </div>
          <div style={{ display:"flex", gap:8, alignItems:"center" }}>
            {ghToken && <Pill label="authenticated ✓" color="#10b981" sm/>}
            <Btn variant="ghost" sm onClick={()=>setShowTokenForm(v=>!v)}>
              {showTokenForm ? "cancel" : ghToken ? "update token" : "add token"}
            </Btn>
            <Btn variant="secondary" sm onClick={()=>loadFolders()}>↻ reload</Btn>
          </div>
        </div>
        {showTokenForm && (
          <div style={{ marginTop:12, display:"flex", gap:8 }}>
            <input value={tokenInput} onChange={e=>setTokenInput(e.target.value)}
              placeholder="ghp_xxxxxxxxxxxx (read-only public repo token)"
              type="password"
              style={{ flex:1, background:"#030a17", border:"1px solid #0c1e38", borderRadius:6,
                padding:"7px 12px", color:"#c8d8f0", ...mono, fontSize:11, outline:"none" }}/>
            <Btn onClick={()=>{setGhToken(tokenInput);setShowTokenForm(false);cache.folders=null;loadFolders(tokenInput);}}>
              save & reload
            </Btn>
          </div>
        )}
      </Card>

      {/* filters */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
        <Inp label="Search technique ID or keyword" value={search} onChange={setSearch}
          placeholder="T1003, kerberos, lateral…" mono/>
        <Sel label="Filter by Tactic" value={tacticFilter} onChange={setTacticFilter}
          options={["all",...Object.keys(TACTIC_COLORS)]}/>
      </div>

      <div style={{...mono, fontSize:10, color:"#1e3a5f"}}>
        {loading ? "loading from GitHub API…" : `${filteredTechs.length} techniques · ${Object.values(techDatasets).flat().length} datasets loaded · ${flowSteps.length} in flow`}
      </div>

      {error && (
        <div style={{ padding:"10px 14px", background:"#1a0808", border:"1px solid #ef444430",
          borderRadius:8, ...mono, fontSize:11, color:"#ef4444" }}>
          ⚠ {error}
          {error.includes("403") && <span style={{ color:"#f59e0b" }}> — add a GitHub token above to increase rate limit</span>}
        </div>
      )}

      {/* technique list */}
      <div style={{ display:"flex", flexDirection:"column", gap:4, maxHeight:560, overflowY:"auto" }}>
        {loading && Array(8).fill(0).map((_,i) => <SkeletonRow key={i}/>)}
        {!loading && filteredTechs.map(tech => {
          const tactic = getTactic(tech);
          const tc = TACTIC_COLORS[tactic] || "#1e293b";
          const isExp = expanded === tech;
          const ds = techDatasets[tech] || [];
          const inFlowCount = ds.filter(d => isInFlow(d)).length;

          return (
            <div key={tech}>
              <div onClick={()=>expandTechnique(tech)}
                style={{ display:"flex", alignItems:"center", gap:12, padding:"10px 14px",
                  background: isExp ? "#091828" : "#060f20",
                  border:`1px solid ${isExp?"#22d3ee25":"#0c1e38"}`,
                  borderRadius: isExp ? "8px 8px 0 0" : 8,
                  cursor:"pointer", transition:"all .15s" }}>
                <div style={{ width:3, height:32, borderRadius:2, background:tc, flexShrink:0 }}/>
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <span style={{...mono, fontSize:13, color:"#c8d8f0", fontWeight:600}}>{tech}</span>
                    {inFlowCount > 0 && <Pill label={`${inFlowCount} in flow`} color="#22d3ee" sm/>}
                    {loadingTech === tech && <Spinner size={12}/>}
                  </div>
                  <div style={{...sans, fontSize:10, color:"#3d5a7a", marginTop:2}}>
                    {tactic}
                    {ds.length > 0 && <span style={{ color:"#1e3a5f" }}> · {ds.length} datasets</span>}
                  </div>
                </div>
                <Pill label={tactic} color={tc} sm dot/>
                <span style={{ color:"#1e3a5f", fontSize:12 }}>{isExp?"▲":"▼"}</span>
              </div>

              {isExp && (
                <div style={{ background:"#040c1a", border:"1px solid #0c1e38",
                  borderTop:"none", borderRadius:"0 0 8px 8px", padding:"8px" }}>
                  {loadingTech === tech && (
                    <div style={{ display:"flex", alignItems:"center", gap:10, padding:"12px",
                      ...mono, fontSize:11, color:"#3d5a7a" }}>
                      <Spinner/> fetching YAML manifests from GitHub…
                    </div>
                  )}
                  {!loadingTech && ds.length === 0 && (
                    <div style={{ padding:"12px", ...mono, fontSize:11, color:"#1e3a5f" }}>
                      No parseable datasets found for {tech}
                    </div>
                  )}
                  {ds.map(d => {
                    const inF = isInFlow(d);
                    return (
                      <div key={d.id}
                        style={{ display:"flex", alignItems:"center", gap:10, padding:"9px 12px",
                          background: inF ? "#081b30" : "transparent",
                          borderRadius:6, marginBottom:3,
                          border:`1px solid ${inF?"#22d3ee20":"transparent"}`,
                          animation:"slideUp .2s" }}>
                        <div style={{ flex:1, minWidth:0 }}>
                          <div style={{ display:"flex", alignItems:"center", gap:7, marginBottom:2 }}>
                            <span style={{...mono, fontSize:11, color: inF?"#c8d8f0":"#6a8aaa", fontWeight: inF?600:400}}>
                              {d.name}
                            </span>
                            <Pill label={d.lt} color={d.ltColor} sm/>
                            {d.source && <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{d.source.split(":").pop()}</span>}
                          </div>
                          <div style={{...mono, fontSize:9, color:"#1e3a5f", wordBreak:"break-all"}}>
                            {d.mediaUrl || d.yamlPath}
                          </div>
                        </div>
                        <Btn variant={inF?"secondary":"ghost"} sm
                          onClick={()=>inF ? setFlowSteps(p=>p.filter(s=>s.id!==d.id)) : addToFlow(d)}>
                          {inF ? "✓ in flow" : "+ add"}
                        </Btn>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── ATTACK FLOW BUILDER ──────────────────────────────────────────────────────

function AttackFlowBuilder({ flowSteps, setFlowSteps, ghToken }) {
  const [opName, setOpName] = useState("Operation Chimera");
  const [opDesc, setOpDesc] = useState("");
  const [dragIdx, setDragIdx] = useState(null);
  const [overIdx, setOverIdx] = useState(null);
  const [openStep, setOpenStep] = useState(null);
  const [swapStep, setSwapStep] = useState(null);       // step id with swap panel open
  const [swapVariants, setSwapVariants] = useState({}); // stepId → datasets[]
  const [loadingSwap, setLoadingSwap] = useState(null); // stepId currently fetching
  const [activeTpl, setActiveTpl] = useState(null);
  const [loadingTpl, setLoadingTpl] = useState(null);

  const openSwap = async (s) => {
    if (swapStep === s.id) { setSwapStep(null); return; }
    setSwapStep(s.id);
    setOpenStep(null); // close detail panel if open
    if (swapVariants[s.id]) return; // already loaded
    setLoadingSwap(s.id);
    try {
      const candidates = [...new Set([s.technique, s.technique?.split(".")[0]])].filter(Boolean);
      let all = [];
      for (const cand of candidates) {
        const ds = await fetchYamlsForTechnique(cand, ghToken);
        all = [...all, ...ds];
      }
      // Deduplicate by id
      const seen = new Set(); const deduped = [];
      all.forEach(d => { if (!seen.has(d.id)) { seen.add(d.id); deduped.push(d); } });
      setSwapVariants(prev => ({...prev, [s.id]: deduped}));
    } catch {}
    setLoadingSwap(null);
  };

  const swapVariant = (stepId, newDs) => {
    setFlowSteps(prev => prev.map(s => s.id === stepId ? {...newDs, id: stepId} : s));
    setSwapStep(null);
  };

  const moveStep = (from, to) => {
    if (from === to) return;
    setFlowSteps(prev => {
      const a = [...prev]; const [el] = a.splice(from,1); a.splice(to,0,el); return a;
    });
  };

  const applyTemplate = async (tpl) => {
    setActiveTpl(tpl.id); setLoadingTpl(tpl.id);
    setOpName(tpl.name); setOpDesc(tpl.desc);
    // For each technique in the template, try to load its first dataset
    const newSteps = [];
    for (const tech of tpl.techniques) {
      try {
        let ds = cache.yamls[tech];
        if (!ds) ds = await fetchYamlsForTechnique(tech, ghToken);
        if (ds.length > 0) {
          const first = ds[0];
          if (!newSteps.find(s => s.id === first.id)) newSteps.push(first);
        }
      } catch(e) {
        // Add placeholder if API fails
        newSteps.push({
          id: `placeholder/${tech}`,
          technique: tech, tool:"atomic_red_team",
          name: `${tech}-dataset`,
          mediaUrl: `${RAW_BASE}/datasets/attack_techniques/${tech}/atomic_red_team/windows-sysmon.log`,
          lt:"WINDOWS_SYSMON", ltColor:"#3b82f6",
          mitre:[tech], desc:`${getTactic(tech)} technique dataset`,
          source:"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        });
      }
    }
    setFlowSteps(newSteps);
    setLoadingTpl(null);
  };

  const tacticCoverage = {};
  flowSteps.forEach(s => (s.mitre||[]).forEach(m => {
    const t = getTactic(m); tacticCoverage[t] = (tacticCoverage[t]||0)+1;
  }));

  const exportFlow = () => JSON.stringify({
    name: opName, description: opDesc,
    created: new Date().toISOString(),
    ingestion_method: "https_pull",
    media_base_url: RAW_BASE,
    steps: flowSteps.map((s,i) => ({
      step: i+1, name: s.name, technique: s.technique,
      mitre: s.mitre, tactic: (s.mitre||[]).map(getTactic),
      log_type: s.lt,
      media_url: s.mediaUrl,
      source: s.source, sourcetype: s.sourcetype,
    }))
  }, null, 2);

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      {/* templates */}
      <Card>
        <SectionLabel>FLOW TEMPLATES</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:8 }}>
          {FLOW_TEMPLATES.map(tpl => (
            <div key={tpl.id} onClick={()=>applyTemplate(tpl)}
              style={{ padding:12, borderRadius:8, cursor:"pointer",
                background: activeTpl===tpl.id ? `${tpl.color}12` : "#030a17",
                border:`1px solid ${activeTpl===tpl.id ? tpl.color+"45":"#0c1e38"}`,
                transition:"all .15s", position:"relative" }}>
              {loadingTpl===tpl.id && (
                <div style={{ position:"absolute", top:8, right:8 }}><Spinner size={10}/></div>
              )}
              <div style={{ width:6, height:6, borderRadius:"50%", background:tpl.color, marginBottom:10 }}/>
              <div style={{...sans, fontSize:11, fontWeight:700, color:"#c8d8f0", marginBottom:4 }}>{tpl.name}</div>
              <div style={{...sans, fontSize:10, color:"#2a4060", lineHeight:1.4, marginBottom:8 }}>{tpl.desc}</div>
              <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{tpl.techniques.length} TTPs</span>
            </div>
          ))}
        </div>
      </Card>

      {/* metadata + coverage */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
        <Card>
          <SectionLabel>OPERATION METADATA</SectionLabel>
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            <Inp label="Operation / CTF Name" value={opName} onChange={setOpName} placeholder="Operation Chimera"/>
            <Inp label="Brief / Scenario Description" value={opDesc} onChange={setOpDesc}
              placeholder="Workshop scenario for blue team detection…"/>
          </div>
        </Card>
        <Card>
          <SectionLabel>TACTIC COVERAGE</SectionLabel>
          {Object.keys(tacticCoverage).length === 0
            ? <div style={{...sans, fontSize:11, color:"#1e3a5f"}}>Add steps to see coverage</div>
            : <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
                {Object.entries(tacticCoverage).map(([t,n]) => {
                  const c = TACTIC_COLORS[t]||"#475569";
                  return (
                    <div key={t} style={{ display:"flex", alignItems:"center", gap:5,
                      padding:"4px 8px", background:`${c}12`, borderRadius:5, border:`1px solid ${c}28` }}>
                      <span style={{...mono, fontSize:9, color:c}}>{t}</span>
                      <span style={{ background:c, color:"#fff", borderRadius:"50%",
                        width:15, height:15, display:"flex", alignItems:"center",
                        justifyContent:"center", fontSize:9, fontWeight:"bold" }}>{n}</span>
                    </div>
                  );
                })}
              </div>
          }
        </Card>
      </div>

      {/* flow canvas */}
      <Card>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
          <SectionLabel>ATTACK CHAIN — {flowSteps.length} STEPS</SectionLabel>
          {flowSteps.length > 0 && <Btn variant="secondary" sm onClick={()=>setFlowSteps([])}>clear</Btn>}
        </div>

        {flowSteps.length === 0
          ? <div style={{ padding:"40px 0", textAlign:"center", ...sans, fontSize:12, color:"#162035" }}>
              Apply a template above, or browse the Datasets tab and add techniques to the flow
            </div>
          : <div style={{ display:"flex", flexDirection:"column", gap:0 }}>
              {flowSteps.map((s,i) => {
                const tc = TACTIC_COLORS[getTactic(s.mitre?.[0]||s.technique)] || "#1e293b";
                const isOpen = openStep === s.id;
                const isSwap = swapStep === s.id;
                const variants = swapVariants[s.id] || [];
                return (
                  <div key={s.id}>
                    <div draggable
                      onDragStart={()=>setDragIdx(i)}
                      onDragOver={e=>{e.preventDefault();setOverIdx(i);}}
                      onDrop={()=>{moveStep(dragIdx,i);setDragIdx(null);setOverIdx(null);}}
                      onDragEnd={()=>{setDragIdx(null);setOverIdx(null);}}
                      style={{ display:"flex", alignItems:"center", gap:12, padding:"11px 12px",
                        background: overIdx===i?"#091828": isSwap?"#091828":"#040c1a",
                        border:`1px solid ${overIdx===i?"#22d3ee35":isSwap?"#f59e0b35":"#0c1e38"}`,
                        borderRadius: isSwap||isOpen ? "8px 8px 0 0" : 8,
                        cursor:"grab", opacity:dragIdx===i?.35:1,
                        animation:"slideUp .2s" }}>
                      {/* step number */}
                      <div style={{ width:28, height:28, borderRadius:"50%", flexShrink:0,
                        background:`${tc}18`, border:`2px solid ${tc}55`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        ...mono, fontSize:11, fontWeight:700, color:tc }}>{i+1}</div>
                      <div style={{ width:3, height:36, borderRadius:2, background:tc, flexShrink:0 }}/>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:7, marginBottom:3 }}>
                          <span style={{...mono, fontSize:12, color:"#c8d8f0", fontWeight:600 }}>{s.name}</span>
                          <Pill label={s.technique} color="#f59e0b" sm/>
                          <Pill label={s.lt} color={s.ltColor||"#475569"} sm/>
                          {s.tool && <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{s.tool}</span>}
                        </div>
                        <div style={{...sans, fontSize:10, color:"#2a4060" }}>{s.desc?.slice(0,80)}{s.desc?.length>80?"…":""}</div>
                      </div>
                      <Pill label={getTactic(s.technique)} color={tc} sm dot/>
                      <div style={{ display:"flex", gap:5, flexShrink:0 }}>
                        <Btn variant={isSwap?"primary":"ghost"} sm
                          onClick={e=>{e.stopPropagation();openSwap(s);}}>
                          {isSwap ? "▲ variants" : "⇄ swap"}
                        </Btn>
                        <Btn variant="ghost" sm onClick={()=>{setOpenStep(isOpen?null:s.id);setSwapStep(null);}}>
                          {isOpen?"▲":"▼"}
                        </Btn>
                        <Btn variant="danger" sm onClick={()=>setFlowSteps(p=>p.filter(x=>x.id!==s.id))}>×</Btn>
                        <span style={{ color:"#0c1e38", fontSize:14, padding:"0 2px", cursor:"grab" }}>⠿</span>
                      </div>
                    </div>

                    {/* ── SWAP PANEL ─────────────────────────────────── */}
                    {isSwap && (
                      <div style={{ background:"#040c1a", border:"1px solid #f59e0b25",
                        borderTop:"none", borderRadius:"0 0 8px 8px",
                        padding:"10px 12px", marginBottom:2, animation:"slideUp .15s" }}>
                        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                          <span style={{...mono, fontSize:9, color:"#f59e0b", letterSpacing:"0.1em" }}>
                            ⇄ SWAP VARIANT — {s.technique}
                          </span>
                          {loadingSwap===s.id && <Spinner size={12}/>}
                          {!loadingSwap && variants.length > 0 && (
                            <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>
                              {variants.length} variant{variants.length!==1?"s":""} available
                            </span>
                          )}
                        </div>
                        {loadingSwap===s.id && (
                          <div style={{...mono, fontSize:10, color:"#3d5a7a", padding:"8px 0" }}>
                            fetching all datasets for {s.technique}…
                          </div>
                        )}
                        {!loadingSwap && variants.length === 0 && (
                          <div style={{...mono, fontSize:10, color:"#1e3a5f", padding:"8px 0" }}>
                            No other variants found for {s.technique}
                          </div>
                        )}
                        {!loadingSwap && variants.map(v => {
                          const isCurrent = v.name === s.name && v.tool === s.tool;
                          return (
                            <div key={v.id}
                              style={{ display:"flex", alignItems:"center", gap:10,
                                padding:"8px 10px", marginBottom:4, borderRadius:6,
                                background: isCurrent?"#081b14":"#030a17",
                                border:`1px solid ${isCurrent?"#10b98130":"#0c1e38"}`,
                                cursor: isCurrent?"default":"pointer",
                                opacity: isCurrent?.7:1,
                                transition:"all .15s" }}
                              onClick={()=>!isCurrent&&swapVariant(s.id, v)}>
                              <div style={{ flex:1, minWidth:0 }}>
                                <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:3 }}>
                                  <span style={{...mono, fontSize:11,
                                    color: isCurrent?"#10b981":"#c8d8f0",
                                    fontWeight: isCurrent?700:400 }}>
                                    {v.name}
                                  </span>
                                  {isCurrent && <Pill label="current" color="#10b981" sm/>}
                                  <Pill label={v.lt} color={v.ltColor||"#475569"} sm/>
                                </div>
                                <div style={{ display:"flex", gap:6, alignItems:"center" }}>
                                  <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{v.tool}</span>
                                  {v.source && (
                                    <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>
                                      · {v.source.split(":").pop()}
                                    </span>
                                  )}
                                </div>
                              </div>
                              {!isCurrent && (
                                <Btn variant="ghost" sm>use this →</Btn>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {/* ── DETAIL PANEL ───────────────────────────────── */}
                    {isOpen && (
                      <div style={{ padding:"12px 56px", background:"#030a17",
                        borderLeft:"3px solid #0c1e38", marginBottom:2, animation:"slideUp .15s" }}>
                        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                          <div>
                            <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>MEDIA URL (HTTPS PULL)</div>
                            <div style={{...mono, fontSize:9, color:"#3d5a7a", wordBreak:"break-all", lineHeight:1.5 }}>
                              {s.mediaUrl || "—"}
                            </div>
                          </div>
                          <div>
                            <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>SOURCE / SOURCETYPE</div>
                            <div style={{...mono, fontSize:9, color:"#3d5a7a" }}>{s.source||"—"}</div>
                          </div>
                          <div>
                            <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>SECOPS LOG TYPE</div>
                            <Pill label={s.lt} color={s.ltColor||"#475569"} sm/>
                          </div>
                          <div>
                            <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>ENTITIES IN LOG</div>
                            <div style={{ display:"flex", flexWrap:"wrap", gap:3 }}>
                              {STATIC_ENTITIES.filter(e=>e.techniques.some(t=>(s.mitre||[s.technique]).includes(t))).slice(0,4).map(e=>(
                                <Pill key={e.id} label={e.value.length>18?e.value.slice(0,16)+"…":e.value} color="#8b5cf6" sm/>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {i < flowSteps.length-1 && (
                      <div style={{ display:"flex", justifyContent:"center", padding:"3px 0" }}>
                        <span style={{ color:"#22d3ee", fontSize:11, animation:"flowBeat 2s infinite" }}>▼</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
        }
      </Card>

      {flowSteps.length > 0 && (
        <Card>
          <SectionLabel>FLOW EXPORT JSON</SectionLabel>
          <CodeBlock code={exportFlow()} maxH="220px" filename={`${opName.toLowerCase().replace(/\s+/g,"-")}-flow.json`}/>
        </Card>
      )}
    </div>
  );
}

// ─── ENTITY EXPLORER ──────────────────────────────────────────────────────────

function EntityExplorer({ flowSteps }) {
  const [typeFilter, setTypeFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);

  const TYPE_ICONS = {hostname:"🖥",user:"👤",process:"⚙️",ip:"🌐",domain:"🏛",hash:"#️⃣",file:"📄"};
  const TYPE_COLORS = {hostname:"#3b82f6",user:"#a855f7",process:"#f59e0b",ip:"#22d3ee",domain:"#10b981",hash:"#ec4899",file:"#64748b"};

  // Filter entities relevant to current flow
  const flowTechs = new Set(flowSteps.flatMap(s => s.mitre || [s.technique]));
  const entities = STATIC_ENTITIES.filter(e => {
    const relevant = flowSteps.length === 0 || e.techniques.some(t => flowTechs.has(t));
    const matchType = typeFilter === "all" || e.type === typeFilter;
    const matchSearch = !search || e.value.toLowerCase().includes(search.toLowerCase())
      || e.role.toLowerCase().includes(search.toLowerCase());
    return relevant && matchType && matchSearch;
  });

  const types = ["all","hostname","user","process","ip","domain","hash","file"];
  const typeCounts = {};
  entities.forEach(e => { typeCounts[e.type] = (typeCounts[e.type]||0)+1; });

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      {flowSteps.length > 0 && (
        <div style={{ padding:"8px 14px", background:"#091828", border:"1px solid #22d3ee20",
          borderRadius:8, ...mono, fontSize:10, color:"#22d3ee" }}>
          Showing entities relevant to your {flowSteps.length}-step attack flow
          ({flowTechs.size} unique techniques) — {entities.length} matching
        </div>
      )}
      {flowSteps.length === 0 && (
        <div style={{ padding:"8px 14px", background:"#1a1000", border:"1px solid #f59e0b20",
          borderRadius:8, ...mono, fontSize:10, color:"#f59e0b" }}>
          ⓘ Build an attack flow first to filter entities to your specific chain
        </div>
      )}

      <div style={{ display:"flex", gap:6, flexWrap:"wrap", alignItems:"center" }}>
        {types.map(t => (
          <button key={t} onClick={()=>setTypeFilter(t)}
            style={{ display:"flex", alignItems:"center", gap:5, padding:"5px 12px",
              borderRadius:20, background: typeFilter===t?`${TYPE_COLORS[t]||"#22d3ee"}18`:"transparent",
              border:`1px solid ${typeFilter===t?TYPE_COLORS[t]||"#22d3ee":"#0c1e38"}`,
              color: typeFilter===t?TYPE_COLORS[t]||"#22d3ee":"#3d5a7a",
              ...mono, fontSize:10, cursor:"pointer" }}>
            {TYPE_ICONS[t]||"◉"} {t}
            {t!=="all" && typeCounts[t] && <span style={{ opacity:.6, fontSize:9 }}>({typeCounts[t]})</span>}
          </button>
        ))}
        <div style={{ flex:1, minWidth:160 }}>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="search value or role…"
            style={{ width:"100%", background:"#030a17", border:"1px solid #0c1e38", borderRadius:20,
              padding:"5px 14px", color:"#c8d8f0", ...mono, fontSize:10, outline:"none" }}/>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
        {entities.map(e => {
          const col = TYPE_COLORS[e.type]||"#475569";
          const isSel = selected?.id === e.id;
          return (
            <div key={e.id} onClick={()=>setSelected(isSel?null:e)}
              style={{ padding:14, borderRadius:9, cursor:"pointer",
                background: isSel?"#091828":"#060f20",
                border:`1px solid ${isSel?"#22d3ee30":"#0c1e38"}`,
                transition:"all .15s", animation:"slideUp .2s" }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:8 }}>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <span style={{ fontSize:16 }}>{TYPE_ICONS[e.type]||"◉"}</span>
                  <div>
                    <div style={{...mono, fontSize:11, color:"#c8d8f0", fontWeight:600, wordBreak:"break-all" }}>{e.value}</div>
                    <div style={{...mono, fontSize:9, color:col, marginTop:2 }}>{e.role}</div>
                  </div>
                </div>
                <Pill label={e.type} color={col} sm/>
              </div>
              <div style={{...sans, fontSize:10, color:"#2a4060", marginBottom:8 }}>{e.desc}</div>
              <div>
                <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>RELEVANT TECHNIQUES</div>
                <div style={{ display:"flex", flexWrap:"wrap", gap:4 }}>
                  {e.techniques.map(t => {
                    const inFlow = flowTechs.has(t);
                    return (
                      <span key={t} style={{...mono, fontSize:9, padding:"2px 6px", borderRadius:3,
                        background: inFlow?"#22d3ee15":"#0c1e38",
                        color: inFlow?"#22d3ee":"#3d5a7a",
                        border:`1px solid ${inFlow?"#22d3ee30":"#0c1e38"}`}}>{t}</span>
                    );
                  })}
                </div>
              </div>
            </div>
          );
        })}
        {entities.length === 0 && (
          <div style={{ gridColumn:"1/-1", padding:"32px 0", textAlign:"center",
            ...sans, fontSize:12, color:"#1e3a5f" }}>No entities match your filters</div>
        )}
      </div>
    </div>
  );
}

// ─── TENANT MANAGER ───────────────────────────────────────────────────────────

function TenantManager({ tenants, setTenants }) {
  const empty = { name:"", label:"", customerId:"", region:"US", credentials:"" };
  const [form, setForm] = useState(empty);
  const [editIdx, setEditIdx] = useState(null);
  const f = k => v => setForm(p=>({...p,[k]:v}));

  const save = () => {
    if (!form.name || !form.customerId) return;
    if (editIdx !== null) {
      setTenants(t=>t.map((x,i)=>i===editIdx?{...form}:x)); setEditIdx(null);
    } else setTenants(t=>[...t,{...form}]);
    setForm(empty);
  };

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <Card>
        <SectionLabel>{editIdx!==null?"EDIT TENANT":"ADD TENANT"}</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
          <Inp label="Tenant ID (safe for GitHub secret names)" value={form.name} onChange={f("name")} placeholder="acme-prod" mono/>
          <Inp label="Display Label" value={form.label} onChange={f("label")} placeholder="Acme Production"/>
          <Inp label="Customer ID (UUID)" value={form.customerId} onChange={f("customerId")} placeholder="01234567-0123-4321-abcd-…" mono/>
          <Sel label="Region" value={form.region} onChange={f("region")} options={REGIONS}/>
          <div style={{ gridColumn:"1/-1" }}>
            <Inp label="Service Account Credentials JSON" value={form.credentials} onChange={f("credentials")}
              placeholder='{"type":"service_account","project_id":"...","private_key":"..."}' rows={3} mono/>
          </div>
        </div>
        <div style={{ display:"flex", gap:8, marginTop:14 }}>
          <Btn onClick={save}>{editIdx!==null?"UPDATE":"+ ADD TENANT"}</Btn>
          {editIdx!==null && <Btn variant="secondary" onClick={()=>{setEditIdx(null);setForm(empty);}}>CANCEL</Btn>}
        </div>
      </Card>
      {tenants.length === 0 && (
        <div style={{ padding:"24px", textAlign:"center", ...sans, fontSize:12, color:"#1e3a5f",
          border:"1px dashed #0c1e38", borderRadius:8 }}>
          Add SecOps tenants — each becomes a matrix job in the generated workflow
        </div>
      )}
      {tenants.map((t,i) => (
        <Card key={i} style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"14px 16px" }}>
          <div style={{ display:"flex", alignItems:"center", gap:12 }}>
            <Dot status="idle"/>
            <div>
              <div style={{...sans, fontSize:14, fontWeight:600, color:"#c8d8f0" }}>{t.label||t.name}</div>
              <div style={{...mono, fontSize:10, color:"#1e3a5f" }}>
                {t.customerId?t.customerId.slice(0,20)+"…":"no id"} · {t.region}
              </div>
            </div>
          </div>
          <div style={{ display:"flex", gap:6, alignItems:"center" }}>
            <Pill label={t.region} color="#22d3ee" sm/>
            {t.credentials && <Pill label="creds ✓" color="#10b981" sm/>}
            <Btn variant="ghost" sm onClick={()=>{setForm({...t});setEditIdx(i);}}>edit</Btn>
            <Btn variant="danger" sm onClick={()=>setTenants(t=>t.filter((_,j)=>j!==i))}>×</Btn>
          </div>
        </Card>
      ))}
    </div>
  );
}

// ─── SCHEDULE BUILDER ─────────────────────────────────────────────────────────

const CRON_PRESETS = [
  {l:"Daily midnight",c:"1 0 * * *"},{l:"Daily 6am UTC",c:"0 6 * * *"},
  {l:"Every 6h",c:"0 */6 * * *"},{l:"Weekly Mon",c:"1 0 * * 1"},
  {l:"Twice daily",c:"1 0,12 * * *"},{l:"Custom",c:""},
];

function ScheduleBuilder({ schedule, setSchedule, delta, setDelta }) {
  const [preset, setPreset] = useState("Daily midnight");
  const parts = schedule.split(" ");
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <Card>
        <SectionLabel>CRON SCHEDULE</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:8, marginBottom:14 }}>
          {CRON_PRESETS.map(p=>(
            <button key={p.l} onClick={()=>{setPreset(p.l);if(p.c)setSchedule(p.c);}}
              style={{ padding:"9px 12px", textAlign:"left",
                background:preset===p.l?"#091828":"#030a17",
                border:`1px solid ${preset===p.l?"#22d3ee35":"#0c1e38"}`,
                color:preset===p.l?"#22d3ee":"#3d5a7a", borderRadius:6,
                ...mono, fontSize:10, cursor:"pointer" }}>{p.l}</button>
          ))}
        </div>
        {preset==="Custom" && (
          <div style={{ marginBottom:14 }}>
            <Inp label="Cron Expression" value={schedule} onChange={setSchedule} placeholder="1 0 * * *" mono/>
          </div>
        )}
        <div style={{ display:"flex", gap:6, marginBottom:10 }}>
          {["MIN","HOUR","DOM","MON","DOW"].map((f,i)=>(
            <div key={f} style={{ flex:1, textAlign:"center", background:"#030a17",
              border:"1px solid #0c1e38", borderRadius:6, padding:"10px 6px" }}>
              <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>{f}</div>
              <div style={{...mono, fontSize:18, color:"#22d3ee", fontWeight:700 }}>{parts[i]||"*"}</div>
            </div>
          ))}
        </div>
        <div style={{ padding:"8px 12px", background:"#030a17", border:"1px solid #0c1e38", borderRadius:6 }}>
          <span style={{...mono, fontSize:11, color:"#3d5a7a" }}>cron: </span>
          <span style={{...mono, fontSize:11, color:"#22d3ee" }}>'{schedule}'</span>
        </div>
      </Card>
      <Card>
        <SectionLabel>TIMESTAMP DELTA</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:8, marginBottom:10 }}>
          {["1d","1d1h","2d","0d"].map(v=>(
            <button key={v} onClick={()=>setDelta(v)}
              style={{ padding:10, borderRadius:6, cursor:"pointer",
                background:delta===v?"#091828":"#030a17",
                border:`1px solid ${delta===v?"#22d3ee35":"#0c1e38"}`,
                color:delta===v?"#22d3ee":"#3d5a7a",
                ...mono, fontSize:14, fontWeight:700 }}>{v}</button>
          ))}
        </div>
        <div style={{...mono, fontSize:10, color:"#1e3a5f" }}>{{
          "1d":"Recommended for daily midnight cron — events land yesterday, within detection window",
          "1d1h":"Offset by 1d1h — prevents deduplication if running multiple times per day",
          "2d":"Use when your ingestion pipeline has a lag before alerts fire",
          "0d":"Updates date only, keeps HH:MM:SS — events may appear as future timestamps",
        }[delta]}</div>
      </Card>
    </div>
  );
}

// ─── ENTITY EXTRACTOR PREVIEW ─────────────────────────────────────────────────
// Shows what UDM entity NDJSON will be generated for a given flow
// Based on known Attack Range entities — in production, extract_entities.py
// parses the actual downloaded log files.

function buildEntityNdjson(flowSteps) {
  const now = new Date().toISOString();
  const techniques = new Set(flowSteps.flatMap(s => s.mitre || [s.technique]));

  // Derive relevant known entities from static list
  const relevant = STATIC_ENTITIES.filter(e =>
    e.techniques.some(t => techniques.has(t))
  );

  const lines = [];

  relevant.forEach(e => {
    if (e.type === "hostname") {
      lines.push(JSON.stringify({
        entity: {
          asset: {
            hostname: e.value,
            attribute: {
              labels: [
                { key: "role", value: e.role },
                { key: "source", value: "splunk_attack_data" },
              ],
              creation_time: { seconds: Math.floor(Date.now()/1000) - 86400 },
            }
          }
        },
        metadata: {
          entity_type: "ASSET",
          interval: { start_time: now, end_time: now },
          source_type: "DERIVED_CONTEXT",
          collected_timestamp: now,
          product_name: "splunk/attack_data replay",
          vendor_name: "Splunk",
        }
      }));
    } else if (e.type === "ip") {
      lines.push(JSON.stringify({
        entity: {
          asset: {
            ip: [e.value],
            attribute: {
              labels: [{ key: "role", value: e.role }],
            }
          }
        },
        metadata: {
          entity_type: "ASSET",
          interval: { start_time: now, end_time: now },
          source_type: "DERIVED_CONTEXT",
          collected_timestamp: now,
          product_name: "splunk/attack_data replay",
          vendor_name: "Splunk",
        }
      }));
    } else if (e.type === "user") {
      const parts = e.value.split("\\");
      const username = parts.length > 1 ? parts[1] : e.value;
      const domain   = parts.length > 1 ? parts[0] : "";
      lines.push(JSON.stringify({
        entity: {
          user: {
            user_display_name: username,
            windows_sid: "",
            attribute: {
              labels: [
                { key: "domain", value: domain },
                { key: "role", value: e.role },
              ]
            }
          }
        },
        metadata: {
          entity_type: "USER",
          interval: { start_time: now, end_time: now },
          source_type: "DERIVED_CONTEXT",
          collected_timestamp: now,
          product_name: "splunk/attack_data replay",
          vendor_name: "Splunk",
        }
      }));
    } else if (e.type === "domain") {
      lines.push(JSON.stringify({
        entity: {
          asset: {
            network_domain: e.value,
            attribute: {
              labels: [{ key: "role", value: e.role }],
            }
          }
        },
        metadata: {
          entity_type: "ASSET",
          interval: { start_time: now, end_time: now },
          source_type: "DERIVED_CONTEXT",
          collected_timestamp: now,
          product_name: "splunk/attack_data replay",
          vendor_name: "Splunk",
        }
      }));
    }
    // processes and hashes are event-level data, not entity-level — skip
  });

  return lines.join("\n") || "# No entities found for current flow techniques";
}

// ─── GENERATE ARTIFACTS ───────────────────────────────────────────────────────

function GenerateTab({ tenants, flowSteps, schedule, delta }) {
  const [view, setView] = useState("workflow");

  const ready = tenants.length > 0 && flowSteps.length > 0;

  const workflow = !ready ? "# Add tenants and build an attack flow first" : `name: Logstory Attack Data Replay
# ─────────────────────────────────────────────────────────────
# Ingestion architecture: HTTPS pull from media.githubusercontent.com
# No git clone of splunk/attack_data required.
# Two-pass replay per dataset step:
#   Pass 1 — events:   logstory replay usecase … (default)
#   Pass 2 — entities: logstory replay usecase … --entities
# Entity NDJSON is built by extract_entities.py from downloaded logs
# and placed in ENTITIES/ alongside EVENTS/ before logstory runs.
# ─────────────────────────────────────────────────────────────
on:
  schedule:
    - cron: '${schedule}'
  workflow_dispatch:
    inputs:
      tenant_filter:
        description: 'Single tenant ID to replay (leave empty for all)'
        required: false
      skip_entities:
        description: 'Set to "true" to skip entity ingestion pass'
        required: false
        default: 'false'

jobs:
  replay:
    name: Replay → \${{ matrix.tenant_display }}
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
${tenants.map(t=>`          - tenant_id: ${t.name.toUpperCase().replace(/[^A-Z0-9]/g,"_")}
            tenant_display: "${t.label||t.name}"
            region: ${t.region}`).join("\n")}

    steps:
      - name: Checkout this repo (workflow + scripts only)
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install dependencies
        run: pip install logstory

      - name: Write credentials
        run: |
          echo "\${{ secrets[format('SECOPS_CREDENTIALS_{0}', matrix.tenant_id)] }}" \\
            > /tmp/secops_creds.json

      - name: Cache downloaded datasets
        uses: actions/cache@v4
        with:
          path: /tmp/attack_data_cache
          key: attack-data-\${{ hashFiles('flow.json') }}
          restore-keys: attack-data-

${flowSteps.map((s,i) => {
  const fname = s.name.replace(/[^a-zA-Z0-9._-]/g,"_");
  const safeLt = s.lt || "UNKNOWN";
  return `      # ── Step ${i+1}: ${s.name} [${s.technique}] ─────────────────────────────
      - name: "Download ${s.name}"
        run: |
          mkdir -p /tmp/attack_data_cache
          CACHE_FILE="/tmp/attack_data_cache/${fname}"
          if [ ! -f "$CACHE_FILE" ]; then
            echo "Downloading ${s.name} from media.githubusercontent.com…"
            curl -fsSL --retry 3 --retry-delay 5 \\
              "${s.mediaUrl}" -o "$CACHE_FILE"
          else
            echo "Cache hit: ${s.name}"
          fi

      - name: "Pass 1 — Events: ${s.name}"
        env:
          LOGSTORY_CUSTOMER_ID: \${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}
          LOGSTORY_REGION: \${{ matrix.region }}
        run: |
          python scripts/replay_dataset.py \\
            --log-file /tmp/attack_data_cache/${fname} \\
            --log-type "${safeLt}" \\
            --credentials /tmp/secops_creds.json \\
            --customer-id "\${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}" \\
            --region "\${{ matrix.region }}" \\
            --timestamp-delta "${delta}"

      - name: "Pass 2 — Entities: ${s.name}"
        if: \${{ github.event.inputs.skip_entities != 'true' }}
        env:
          LOGSTORY_CUSTOMER_ID: \${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}
          LOGSTORY_REGION: \${{ matrix.region }}
        run: |
          python scripts/replay_dataset.py \\
            --log-file /tmp/attack_data_cache/${fname} \\
            --log-type "${safeLt}" \\
            --credentials /tmp/secops_creds.json \\
            --customer-id "\${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}" \\
            --region "\${{ matrix.region }}" \\
            --timestamp-delta "${delta}" \\
            --entities`;
}).join("\n\n")}

      - name: Cleanup credentials
        if: always()
        run: rm -f /tmp/secops_creds.json
`;

  const replayScript = `#!/usr/bin/env python3
"""
scripts/replay_dataset.py
─────────────────────────────────────────────────────────────
Logstory wrapper for Splunk Attack Data repo.

Ingestion method: HTTPS pull — files are downloaded from
media.githubusercontent.com by the workflow, then passed here.
No git clone or LFS required.

Two-pass replay:
  Pass 1 (default):  replay events via logstory
  Pass 2 (--entities): extract UDM entities from log, then
                        replay via logstory --entities

The ENTITIES/ subfolder is built by extract_entities.py and
placed alongside EVENTS/ before logstory runs, so that
logstory replay usecase … --entities picks it up automatically.
─────────────────────────────────────────────────────────────
"""
import argparse, os, shutil, subprocess, sys, tempfile
from pathlib import Path

SOURCETYPE_TO_LOGTYPE = {
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational": "WINDOWS_SYSMON",
    "XmlWinEventLog:Security":   "WINEVTLOG",
    "XmlWinEventLog:System":     "WINEVTLOG",
    "XmlWinEventLog:Application":"WINEVTLOG",
    "WinEventLog:Security":      "WINEVTLOG",
    "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational": "POWERSHELL",
    "WinEventLog:Microsoft-Windows-PowerShell/Operational":    "POWERSHELL",
    "crowdstrike:events:sensor": "CS_EDR",
    "crowdstrike:events:falcon": "CS_EDR",
    "sysmon:linux":              "LINUX_SYSMON",
    "Syslog:Linux-Sysmon/Operational": "LINUX_SYSMON",
    "bro:dns:json":              "BRO_JSON",
    "bro:conn:json":             "BRO_JSON",
    "suricata":                  "SURICATA_EVE_JSON",
}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log-file",        required=True)
    p.add_argument("--log-type",        required=True)
    p.add_argument("--credentials",     required=True)
    p.add_argument("--customer-id",     required=True)
    p.add_argument("--region",          default="US")
    p.add_argument("--timestamp-delta", default="1d")
    p.add_argument("--entities",        action="store_true",
                   help="Run entity extraction + entity ingestion pass instead of event pass")
    args = p.parse_args()

    log_file = Path(args.log_file)
    if not log_file.exists():
        sys.exit(f"[error] Log file not found: {log_file}")

    with tempfile.TemporaryDirectory() as tmp:
        usecase_root = Path(tmp) / "SPLUNK_ATTACK_DATA"

        # ── Pass 1: Events ───────────────────────────────────────────────────
        if not args.entities:
            events_dir = usecase_root / "EVENTS"
            events_dir.mkdir(parents=True)
            shutil.copy(log_file, events_dir / f"{args.log_type}.log")
            print(f"[events] Replaying {log_file.name} as {args.log_type}")

        # ── Pass 2: Entities ─────────────────────────────────────────────────
        else:
            # Build entity NDJSON from the downloaded log file
            entity_ndjson = extract_entities(log_file, args.log_type)
            if not entity_ndjson:
                print(f"[entities] No entities extracted from {log_file.name} — skipping")
                sys.exit(0)

            # Logstory expects: USECASE/EVENTS/<LOGTYPE>.log (must exist)
            #                   USECASE/ENTITIES/<LOGTYPE>.ndjson
            events_dir  = usecase_root / "EVENTS"
            entity_dir  = usecase_root / "ENTITIES"
            events_dir.mkdir(parents=True)
            entity_dir.mkdir(parents=True)

            # Events file must exist for logstory to find the usecase,
            # but we replay with --entities so only the ENTITIES/ folder is sent.
            shutil.copy(log_file, events_dir / f"{args.log_type}.log")

            entity_file = entity_dir / f"{args.log_type}.ndjson"
            entity_file.write_text(entity_ndjson)
            print(f"[entities] Wrote {len(entity_ndjson.splitlines())} entity records → {entity_file}")

        env = {
            **os.environ,
            "LOGSTORY_CUSTOMER_ID":      args.customer_id,
            "LOGSTORY_CREDENTIALS_PATH": args.credentials,
            "LOGSTORY_REGION":           args.region,
            "LOGSTORY_USECASES_BUCKETS": f"file://{tmp}",
        }

        cmd = [
            "logstory", "replay", "usecase", "SPLUNK_ATTACK_DATA",
            f"--timestamp-delta={args.timestamp_delta}",
        ]
        if args.entities:
            cmd.append("--entities")

        result = subprocess.run(cmd, env=env)
        sys.exit(result.returncode)


def extract_entities(log_file: Path, log_type: str) -> str:
    """
    Parse a downloaded Splunk Attack Data log file and emit UDM entity NDJSON.

    Strategy per log type:
      WINDOWS_SYSMON / WINEVTLOG  — XML event log, grep for Computer, User, IpAddress
      POWERSHELL                  — XML event log, grep for Computer, User
      CS_EDR                      — JSON lines, extract hostname / userPrincipalName
      LINUX_SYSMON                — syslog-style, extract hostname from header
      BRO_JSON / SURICATA_*       — JSON lines, extract id.orig_h / dest_ip

    Returns NDJSON string (one UDM entity JSON object per line).
    """
    import json, re
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    entities = {}  # keyed by (type, value) to deduplicate

    def add_asset(hostname=None, ip=None):
        if hostname:
            k = ("asset_host", hostname.lower())
            if k not in entities:
                entities[k] = {
                    "entity": {"asset": {"hostname": hostname, "attribute": {
                        "labels": [{"key": "source", "value": "splunk_attack_data"}]
                    }}},
                    "metadata": {
                        "entity_type": "ASSET",
                        "interval": {"start_time": now, "end_time": now},
                        "source_type": "DERIVED_CONTEXT",
                        "collected_timestamp": now,
                        "product_name": "splunk/attack_data replay",
                        "vendor_name": "Splunk",
                    }
                }
        if ip and not ip.startswith(("0.", "127.", "::1", "-")):
            k = ("asset_ip", ip)
            if k not in entities:
                entities[k] = {
                    "entity": {"asset": {"ip": [ip], "attribute": {
                        "labels": [{"key": "source", "value": "splunk_attack_data"}]
                    }}},
                    "metadata": {
                        "entity_type": "ASSET",
                        "interval": {"start_time": now, "end_time": now},
                        "source_type": "DERIVED_CONTEXT",
                        "collected_timestamp": now,
                        "product_name": "splunk/attack_data replay",
                        "vendor_name": "Splunk",
                    }
                }

    def add_user(username, domain=""):
        if not username or username in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return
        k = ("user", username.lower())
        if k not in entities:
            entities[k] = {
                "entity": {"user": {
                    "user_display_name": username,
                    "attribute": {"labels": [
                        {"key": "domain", "value": domain},
                        {"key": "source", "value": "splunk_attack_data"},
                    ]}
                }},
                "metadata": {
                    "entity_type": "USER",
                    "interval": {"start_time": now, "end_time": now},
                    "source_type": "DERIVED_CONTEXT",
                    "collected_timestamp": now,
                    "product_name": "splunk/attack_data replay",
                    "vendor_name": "Splunk",
                }
            }

    raw = log_file.read_text(errors="replace")

    if log_type in ("WINDOWS_SYSMON", "WINEVTLOG", "POWERSHELL"):
        # XML event log — extract tags
        for m in re.finditer(r"<Computer>([^<]+)</Computer>", raw):
            add_asset(hostname=m.group(1).strip())
        for m in re.finditer(r"<Data Name=['\"]SubjectUserName['\"]>([^<]+)</Data>", raw):
            val = m.group(1).strip()
            if val not in ("-", ""):
                add_user(val)
        for m in re.finditer(r"<Data Name=['\"]TargetUserName['\"]>([^<]+)</Data>", raw):
            val = m.group(1).strip()
            if val not in ("-", ""):
                add_user(val)
        for m in re.finditer(r"<Data Name=['\"]IpAddress['\"]>([^<]+)</Data>", raw):
            ip = m.group(1).strip().lstrip("-")
            if re.match(r"\\d+\\.\\d+\\.\\d+\\.\\d+", ip):
                add_asset(ip=ip)
        for m in re.finditer(r"<Data Name=['\"]DestinationIp['\"]>([^<]+)</Data>", raw):
            add_asset(ip=m.group(1).strip())

    elif log_type == "CS_EDR":
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                if h := obj.get("ComputerName") or obj.get("HostName"):
                    add_asset(hostname=h)
                if u := obj.get("UserName") or obj.get("userPrincipalName"):
                    add_user(u)
                if ip := obj.get("LocalAddressIP4") or obj.get("RemoteAddressIP4"):
                    add_asset(ip=ip)
            except Exception:
                pass

    elif log_type == "LINUX_SYSMON":
        for m in re.finditer(r"^\\S+ \\d+ \\d+:\\d+:\\d+ (\\S+) ", raw, re.MULTILINE):
            add_asset(hostname=m.group(1))
        for m in re.finditer(r"User=(\\S+)", raw):
            add_user(m.group(1))

    elif log_type in ("BRO_JSON", "SURICATA_EVE_JSON"):
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                for field in ("id.orig_h", "src_ip"):
                    if ip := obj.get(field):
                        add_asset(ip=ip)
                for field in ("id.resp_h", "dest_ip"):
                    if ip := obj.get(field):
                        add_asset(ip=ip)
            except Exception:
                pass

    return "\\n".join(json.dumps(v) for v in entities.values())


if __name__ == "__main__":
    main()
`;

  const entityExtractStandalone = `#!/usr/bin/env python3
"""
scripts/extract_entities.py  (standalone — for local testing)
─────────────────────────────────────────────────────────────
Usage:
  python scripts/extract_entities.py \\
    --log-file /tmp/windows-sysmon.log \\
    --log-type WINDOWS_SYSMON \\
    --out /tmp/entities.ndjson

  # Then push directly to SecOps entity API:
  python scripts/push_entities.py \\
    --ndjson /tmp/entities.ndjson \\
    --credentials creds.json \\
    --customer-id <UUID>

Or let replay_dataset.py handle it automatically with --entities flag.
─────────────────────────────────────────────────────────────
"""
# (Entity extraction logic is embedded in replay_dataset.py above.
#  This standalone wrapper calls the same extract_entities() function.)

import argparse, sys
from pathlib import Path
from replay_dataset import extract_entities

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log-file",  required=True)
    p.add_argument("--log-type",  required=True)
    p.add_argument("--out",       required=True, help="Output .ndjson path")
    args = p.parse_args()

    ndjson = extract_entities(Path(args.log_file), args.log_type)
    count = len(ndjson.splitlines()) if ndjson else 0
    if not count:
        print("[warn] No entities extracted — check log_type and file contents")
        sys.exit(0)

    Path(args.out).write_text(ndjson)
    print(f"[ok] Wrote {count} entity records → {args.out}")

if __name__ == "__main__":
    main()
`;

  const entityNdjson = flowSteps.length === 0
    ? '# Build an attack flow first to preview entity NDJSON'
    : buildEntityNdjson(flowSteps);

  const secretCmds = tenants.length === 0 ? "# Add tenants first" :
    tenants.flatMap(t => {
      const s = t.name.toUpperCase().replace(/[^A-Z0-9]/g,"_");
      return [
        `# ${t.label||t.name} (${t.region})`,
        `gh secret set SECOPS_CUSTOMER_ID_${s} --body "${t.customerId||"REPLACE_WITH_UUID"}"`,
        `gh secret set SECOPS_CREDENTIALS_${s} < /path/to/${t.name}-service-account.json`,
        "",
      ];
    }).join("\n");

  const urlList = flowSteps.length === 0 ? "# Build an attack flow first" :
    flowSteps.map(s => `# ${s.name} [${s.technique}] → ${s.lt}\ncurl -fsSL "${s.mediaUrl}" -o /tmp/${s.name}.log`).join("\n\n");

  const tabs = [
    ["workflow", ".github/workflows/logstory-replay.yml"],
    ["replay",   "scripts/replay_dataset.py"],
    ["entities", "ENTITIES/ NDJSON preview"],
    ["extract",  "scripts/extract_entities.py"],
    ["secrets",  "gh secret commands"],
    ["urls",     "dataset URLs (curl)"],
  ];

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      {!ready && (
        <div style={{ padding:"12px 16px", background:"#1a0f00", border:"1px solid #f59e0b28",
          borderRadius:8, ...mono, fontSize:11, color:"#f59e0b" }}>
          ⚠ {!tenants.length&&"Add at least one tenant. "}
          {!flowSteps.length&&"Build an attack flow with at least one step."}
        </div>
      )}

      {/* Architecture summary */}
      <Card style={{ padding:"14px 16px" }}>
        <SectionLabel>INGESTION ARCHITECTURE</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10 }}>
          {[
            {icon:"🚫", label:"No git clone",     desc:"splunk/attack_data not checked out. No 9 GB repo, no LFS."},
            {icon:"⬇️", label:"curl on demand",   desc:"Selected dataset files downloaded via HTTPS at runtime only."},
            {icon:"💾", label:"Actions cache",     desc:"Files cached by flow hash — no redundant downloads."},
            {icon:"🧬", label:"Entity pass",       desc:"Pass 2 extracts hostnames/users/IPs → UDM NDJSON → logstory --entities."},
          ].map(item=>(
            <div key={item.label} style={{ padding:"12px", background:"#030a17", borderRadius:8, border:"1px solid #0c1e38" }}>
              <div style={{ fontSize:16, marginBottom:6 }}>{item.icon}</div>
              <div style={{...sans, fontSize:11, fontWeight:700, color:"#c8d8f0", marginBottom:4 }}>{item.label}</div>
              <div style={{...sans, fontSize:10, color:"#2a4060" }}>{item.desc}</div>
            </div>
          ))}
        </div>

        {/* Pipeline diagram */}
        <div style={{ marginTop:14, padding:"12px 14px", background:"#030a17",
          borderRadius:8, border:"1px solid #0c1e38" }}>
          <div style={{...mono, fontSize:9, color:"#1e3a5f", marginBottom:8 }}>TWO-PASS PIPELINE PER DATASET STEP</div>
          <div style={{ display:"flex", alignItems:"center", gap:0, flexWrap:"wrap", rowGap:6 }}>
            {[
              {label:"curl download",     color:"#3b82f6", sub:"media.githubusercontent.com"},
              {label:"→", plain:true},
              {label:"Pass 1: Events",    color:"#10b981", sub:"logstory replay usecase …"},
              {label:"→", plain:true},
              {label:"extract_entities()",color:"#a855f7", sub:"parse XML/JSON log → UDM NDJSON"},
              {label:"→", plain:true},
              {label:"Pass 2: Entities",  color:"#ec4899", sub:"logstory replay … --entities"},
              {label:"→", plain:true},
              {label:"SecOps tenant",     color:"#22d3ee", sub:"events + entity context ingested"},
            ].map((s,i) => s.plain
              ? <span key={i} style={{ color:"#1e3a5f", margin:"0 4px", fontSize:14 }}>›</span>
              : <div key={i} style={{ padding:"6px 10px", borderRadius:6,
                  background:`${s.color}12`, border:`1px solid ${s.color}30` }}>
                  <div style={{...mono, fontSize:10, color:s.color, fontWeight:600 }}>{s.label}</div>
                  <div style={{...mono, fontSize:8, color:"#1e3a5f", marginTop:2 }}>{s.sub}</div>
                </div>
            )}
          </div>
        </div>
      </Card>

      {/* tab selector */}
      <div style={{ display:"flex", gap:2, background:"#030a17", borderRadius:6, padding:3, border:"1px solid #0c1e38", flexWrap:"wrap" }}>
        {tabs.map(([k,l])=>(
          <button key={k} onClick={()=>setView(k)}
            style={{ flex:1, minWidth:100, padding:"7px 4px", borderRadius:5,
              background:view===k?"#060f20":"transparent", border:"none",
              color:view===k?"#22d3ee":"#3d5a7a",
              ...mono, fontSize:9, cursor:"pointer", whiteSpace:"nowrap" }}>{l}</button>
        ))}
      </div>

      {view==="workflow" && <CodeBlock code={workflow}              maxH="560px" filename=".github/workflows/logstory-replay.yml"/>}
      {view==="replay"   && <CodeBlock code={replayScript}         maxH="560px" filename="scripts/replay_dataset.py"/>}
      {view==="extract"  && <CodeBlock code={entityExtractStandalone} maxH="400px" filename="scripts/extract_entities.py"/>}

      {view==="entities" && (
        <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
          {/* explainer */}
          <div style={{ padding:"12px 16px", background:"#0d0920", border:"1px solid #a855f730",
            borderRadius:8 }}>
            <div style={{...sans, fontSize:13, fontWeight:700, color:"#c8d8f0", marginBottom:6 }}>
              What is entity ingestion?
            </div>
            <div style={{...sans, fontSize:11, color:"#4a6a8a", lineHeight:1.6 }}>
              Logstory usecases can contain an <code style={{...mono, color:"#a855f7", fontSize:10}}>ENTITIES/</code> folder
              alongside <code style={{...mono, color:"#3b82f6", fontSize:10}}>EVENTS/</code>.
              When you run <code style={{...mono, color:"#22d3ee", fontSize:10}}>logstory replay usecase … --entities</code>,
              it sends each NDJSON record to the SecOps <strong style={{color:"#c8d8f0"}}>ImportEntities</strong> API
              (<code style={{...mono, fontSize:9, color:"#4a6a8a"}}>v2/entities:batchCreate</code>).
              This populates the <strong style={{color:"#c8d8f0"}}>Entity Graph</strong> with asset/user context that enriches
              events — e.g. "ar-win-dc is a Domain Controller" — making it visible in the Asset View and queryable in UDM search.
            </div>
          </div>

          {/* entity type breakdown */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:8 }}>
            {[
              {type:"ASSET (hostname)", color:"#3b82f6", icon:"🖥",
               desc:"asset.hostname — populates Asset View, enables hostname-based enrichment"},
              {type:"ASSET (ip)",       color:"#22d3ee", icon:"🌐",
               desc:"asset.ip[] — GeoIP enrichment applied automatically at ingest"},
              {type:"USER",             color:"#a855f7", icon:"👤",
               desc:"user.user_display_name — enables identity context on PROCESS_LAUNCH events"},
            ].map(e=>(
              <div key={e.type} style={{ padding:"12px", background:"#030a17",
                borderRadius:8, border:`1px solid ${e.color}22` }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                  <span style={{ fontSize:16 }}>{e.icon}</span>
                  <span style={{...mono, fontSize:10, color:e.color, fontWeight:700 }}>{e.type}</span>
                </div>
                <div style={{...sans, fontSize:10, color:"#2a4060" }}>{e.desc}</div>
              </div>
            ))}
          </div>

          {/* stats */}
          {flowSteps.length > 0 && (() => {
            const lines = entityNdjson.split("\n").filter(l=>l.trim()&&!l.startsWith("#"));
            const assets = lines.filter(l=>l.includes('"ASSET"')).length;
            const users  = lines.filter(l=>l.includes('"USER"')).length;
            return (
              <div style={{ display:"flex", gap:10 }}>
                {[["Total entities",lines.length,"#22d3ee"],["Asset records",assets,"#3b82f6"],["User records",users,"#a855f7"]].map(([l,v,c])=>(
                  <div key={l} style={{ flex:1, textAlign:"center", padding:"10px",
                    background:"#030a17", borderRadius:8, border:`1px solid ${c}22` }}>
                    <div style={{...sans, fontSize:20, fontWeight:800, color:c }}>{v}</div>
                    <div style={{...mono, fontSize:9, color:"#1e3a5f" }}>{l.toUpperCase()}</div>
                  </div>
                ))}
              </div>
            );
          })()}

          <CodeBlock code={entityNdjson} maxH="380px" filename="ENTITIES/WINDOWS_SYSMON.ndjson (preview)"/>

          <div style={{ padding:"10px 14px", background:"#030a17", border:"1px solid #0c1e38",
            borderRadius:8, ...mono, fontSize:10, color:"#1e3a5f" }}>
            ℹ In production, <span style={{color:"#a855f7"}}>extract_entities()</span> in replay_dataset.py
            parses the actual downloaded log file using regex/JSON — so entity values come from real telemetry,
            not from static metadata. Processes and file hashes are event-level data and are NOT sent as entities
            (they enrich at query time from events, not from the entity graph).
          </div>
        </div>
      )}

      {view==="secrets" && (
        <div>
          <div style={{...mono, fontSize:10, color:"#1e3a5f", marginBottom:8 }}>
            Run these commands in your repo with the GitHub CLI
          </div>
          <CodeBlock code={secretCmds} maxH="300px" filename="gh secret setup"/>
          {tenants.length > 0 && (
            <div style={{ marginTop:12, display:"flex", flexDirection:"column", gap:8 }}>
              {tenants.map((t,i) => {
                const s = t.name.toUpperCase().replace(/[^A-Z0-9]/g,"_");
                return (
                  <Card key={i} style={{ padding:"12px 14px", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                    <div>
                      <div style={{...sans, fontSize:13, fontWeight:600, color:"#c8d8f0" }}>{t.label||t.name}</div>
                      <div style={{...mono, fontSize:9, color:"#1e3a5f" }}>{t.region}</div>
                    </div>
                    <div style={{ display:"flex", flexDirection:"column", gap:4, alignItems:"flex-end" }}>
                      <div style={{...mono, fontSize:9}}>
                        <span style={{color:"#f59e0b"}}>SECOPS_CUSTOMER_ID_{s}</span>
                        <span style={{color:"#1e3a5f"}}> = {t.customerId?t.customerId.slice(0,16)+"…":"⚠ not set"}</span>
                      </div>
                      <div style={{...mono, fontSize:9}}>
                        <span style={{color:"#f59e0b"}}>SECOPS_CREDENTIALS_{s}</span>
                        <span style={{color:t.credentials?"#10b981":"#ef4444"}}> = {t.credentials?"✓ provided":"⚠ not set"}</span>
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}
      {view==="urls" && (
        <div>
          <div style={{...mono, fontSize:10, color:"#1e3a5f", marginBottom:8}}>
            Direct download URLs for your selected datasets — no auth required
          </div>
          <CodeBlock code={urlList} maxH="400px" filename="dataset download URLs"/>
        </div>
      )}
    </div>
  );
}

// ─── STATUS MONITOR ───────────────────────────────────────────────────────────

function StatusMonitor({ tenants }) {
  const [jobs, setJobs] = useState(SAMPLE_JOBS);
  const [simRunning, setSimRunning] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const [ghRepo, setGhRepo] = useState("your-org/your-repo");

  const stats = {
    total: jobs.length,
    success: jobs.filter(j=>j.status==="success").length,
    failed: jobs.filter(j=>j.status==="failed").length,
    running: jobs.filter(j=>j.status==="running").length,
    totalBytes: jobs.reduce((a,j)=>a+(j.bytes||0),0),
  };

  const tenantNames = [...new Set(jobs.map(j=>j.tenant))];

  const triggerRun = () => {
    if (simRunning) return;
    setSimRunning(true);
    const list = tenants.length > 0 ? tenants.map(t=>t.name) : ["acme-prod","demo-us"];
    const newJobs = list.map((t,i) => ({
      id:`sim-${Date.now()}-${i}`, tenant:t, status:"running",
      startedAt: new Date().toISOString(), duration:0, datasets:3, trigger:"manual"
    }));
    setJobs(j=>[...newJobs,...j]);
    setTimeout(()=>{
      setJobs(j=>j.map(job => {
        const n = newJobs.find(x=>x.id===job.id);
        if (!n) return job;
        const ok = Math.random() > 0.12;
        return {...job, status: ok?"success":"failed",
          duration: Math.floor(80+Math.random()*100),
          bytes: ok ? Math.floor(900000+Math.random()*2000000) : 0,
          error: ok ? undefined : "curl: HTTP 403 from media.githubusercontent.com — check dataset URL"
        };
      }));
      setSimRunning(false);
    }, 3800);
  };

  const fmt = iso => {
    const d = new Date(iso);
    return d.toLocaleDateString("en-US",{month:"short",day:"numeric"})
      + " " + d.toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"});
  };
  const fmtBytes = b => b > 1e6 ? `${(b/1e6).toFixed(1)} MB` : b > 1e3 ? `${(b/1e3).toFixed(0)} KB` : `${b} B`;

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      {/* stats */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10 }}>
        {[
          {l:"Total Runs",v:stats.total,c:"#22d3ee"},
          {l:"Successful",v:stats.success,c:"#10b981"},
          {l:"Failed",v:stats.failed,c:"#ef4444"},
          {l:"Running",v:stats.running+(simRunning?(tenants.length||2):0),c:"#f59e0b"},
          {l:"Data Ingested",v:fmtBytes(stats.totalBytes),c:"#8b5cf6"},
        ].map(s=>(
          <Card key={s.l} style={{ textAlign:"center", padding:"14px 10px" }}>
            <div style={{...sans, fontSize:22, fontWeight:800, color:s.c, marginBottom:4 }}>{s.v}</div>
            <div style={{...mono, fontSize:9, color:"#1e3a5f", letterSpacing:"0.1em" }}>{s.l.toUpperCase()}</div>
          </Card>
        ))}
      </div>

      {/* tenant health */}
      <Card>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
          <SectionLabel>TENANT HEALTH</SectionLabel>
          <Btn onClick={triggerRun} disabled={simRunning}>
            {simRunning ? "⟳ RUNNING…" : "▶ TRIGGER MANUAL RUN"}
          </Btn>
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))", gap:8 }}>
          {tenantNames.map(name=>{
            const tj = jobs.filter(j=>j.tenant===name);
            const last = tj[0];
            const sr = Math.round(tj.filter(j=>j.status==="success").length/tj.length*100);
            const running = simRunning && (tenants.length===0 || tenants.find(t=>t.name===name));
            return (
              <div key={name} style={{ padding:"12px 14px", borderRadius:8, background:"#040c1a",
                border:`1px solid ${last?.status==="failed"?"#ef444430":"#0c1e38"}` }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                  <span style={{...mono, fontSize:11, color:"#c8d8f0", fontWeight:600 }}>{name}</span>
                  <Dot status={running?"running":last?.status||"idle"}/>
                </div>
                <div style={{ height:3, background:"#0c1e38", borderRadius:2, marginBottom:8, overflow:"hidden" }}>
                  <div style={{ height:"100%", width:`${sr}%`, transition:"width .6s",
                    background: sr>80?"#10b981":sr>50?"#f59e0b":"#ef4444", borderRadius:2 }}/>
                </div>
                <div style={{...mono, fontSize:9, color:"#1e3a5f" }}>{sr}% success · {tj.length} runs</div>
                {last?.bytes > 0 && <div style={{...mono, fontSize:9, color:"#1e3a5f" }}>last: {fmtBytes(last.bytes)}</div>}
                {last?.status==="failed" && <div style={{...mono, fontSize:9, color:"#ef4444", marginTop:3 }}>⚠ last run failed</div>}
              </div>
            );
          })}
          {tenantNames.length===0 && (
            <div style={{ gridColumn:"1/-1", padding:"24px 0", textAlign:"center",
              ...sans, fontSize:12, color:"#1e3a5f" }}>Configure tenants to see health</div>
          )}
        </div>
      </Card>

      {/* run log */}
      <Card>
        <SectionLabel>RUN LOG</SectionLabel>
        <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
          {jobs.map(j=>(
            <div key={j.id}>
              <div onClick={()=>setExpanded(expanded===j.id?null:j.id)}
                style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
                  padding:"10px 12px", borderRadius:7, cursor:"pointer",
                  background:expanded===j.id?"#060f20":"#040c1a",
                  border:`1px solid ${j.status==="failed"?"#ef444330":j.status==="running"?"#22d3ee30":"#0c1e38"}`,
                  transition:"all .15s", animation:"slideUp .2s" }}>
                <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                  <Dot status={j.status}/>
                  <div>
                    <div style={{...mono, fontSize:12, color:"#c8d8f0", fontWeight:600 }}>{j.tenant}</div>
                    <div style={{...mono, fontSize:9, color:"#1e3a5f" }}>{fmt(j.startedAt)}</div>
                  </div>
                </div>
                <div style={{ display:"flex", gap:7, alignItems:"center" }}>
                  <Pill label={j.trigger} color="#3d5a7a" sm/>
                  <Pill label={`${j.datasets} datasets`} color="#22d3ee" sm/>
                  {j.bytes > 0 && <span style={{...mono, fontSize:9, color:"#1e3a5f" }}>{fmtBytes(j.bytes)}</span>}
                  {j.duration > 0 && <span style={{...mono, fontSize:9, color:"#1e3a5f" }}>{j.duration}s</span>}
                  <Pill label={j.status} color={j.status==="success"?"#10b981":j.status==="failed"?"#ef4444":j.status==="running"?"#22d3ee":"#475569"} sm/>
                  <span style={{ color:"#1e3a5f", fontSize:10 }}>{expanded===j.id?"▲":"▼"}</span>
                </div>
              </div>
              {expanded===j.id && (
                <div style={{ padding:"12px 14px", background:"#030a17",
                  borderLeft:"3px solid #0c1e38", marginBottom:2 }}>
                  {j.error && (
                    <div style={{ padding:"8px 12px", background:"#1a0808", border:"1px solid #ef444328",
                      borderRadius:6, marginBottom:10, ...mono, fontSize:10, color:"#ef4444" }}>
                      {j.error}
                    </div>
                  )}
                  <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10 }}>
                    {[["Tenant",j.tenant],["Trigger",j.trigger],["Duration",j.duration>0?`${j.duration}s`:"in progress"],
                      ["Data",j.bytes>0?fmtBytes(j.bytes):"—"],["Started",fmt(j.startedAt)],["Status",j.status],
                      ["Datasets",j.datasets],["Job ID",j.id]].map(([k,v])=>(
                      <div key={k}>
                        <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:2 }}>{k.toUpperCase()}</div>
                        <div style={{...mono, fontSize:10, color:"#6a8aaa" }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* GitHub CLI commands */}
      <Card>
        <SectionLabel>MONITOR VIA GITHUB CLI</SectionLabel>
        <div style={{ marginBottom:10 }}>
          <Inp label="Your repo (owner/repo)" value={ghRepo} onChange={setGhRepo} mono/>
        </div>
        <CodeBlock filename="monitoring commands" code={`# List recent workflow runs
gh run list --repo ${ghRepo} --workflow=logstory-replay.yml --limit=20

# Watch a live run in real time
gh run watch --repo ${ghRepo}

# View logs for a specific run
gh run view <run-id> --repo ${ghRepo} --log

# Trigger manually for all tenants
gh workflow run logstory-replay.yml --repo ${ghRepo}

# Trigger for a specific tenant
gh workflow run logstory-replay.yml --repo ${ghRepo} -f tenant_filter=acme-prod

# Download run logs as artifact
gh run download <run-id> --repo ${ghRepo}`} maxH="200px"/>
      </Card>
    </div>
  );
}

// ─── THREAT INTEL TAB ────────────────────────────────────────────────────────
// GTI API (VirusTotal Enterprise) — uses /api/v3 endpoints
// Actors:    GET /api/v3/threat_actors?filter=name:{query}
// Campaigns: GET /api/v3/collections?filter=name:{query}
// TTPs:      Embedded in relationships → attack_techniques on actor/collection objects

const GTI_BASE = "https://gti-cors-proxy.twoseven.workers.dev/vt-proxy/api/v3";

// Kill-chain phase ordering for sorting TTPs into a narrative flow
const PHASE_ORDER = [
  "Reconnaissance","Resource Development","Initial Access","Execution",
  "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
  "Discovery","Lateral Movement","Collection","Command and Control",
  "Exfiltration","Impact","Unknown",
];

// Well-known actors for quick-pick (name → GTI search term)
const KNOWN_ACTORS = [
  { name:"Volt Typhoon",    aliases:"Bronze Silhouette · VANGUARD PANDA", nation:"CN", color:"#ef4444" },
  { name:"APT29",           aliases:"Cozy Bear · Midnight Blizzard · YTTRIUM", nation:"RU", color:"#f97316" },
  { name:"APT41",           aliases:"BARIUM · Winnti · Double Dragon", nation:"CN", color:"#ef4444" },
  { name:"Lazarus Group",   aliases:"HIDDEN COBRA · Zinc", nation:"KP", color:"#a855f7" },
  { name:"FIN7",            aliases:"Carbon Spider · ELBRUS", nation:"UA/RU", color:"#f59e0b" },
  { name:"ALPHV",           aliases:"BlackCat · Noberus", nation:"RaaS", color:"#ec4899" },
  { name:"LockBit",         aliases:"LockBit 3.0 · Black", nation:"RaaS", color:"#dc2626" },
  { name:"Scattered Spider",aliases:"Muddled Libra · UNC3944", nation:"EN", color:"#06b6d4" },
  { name:"Sandworm",        aliases:"Voodoo Bear · IRIDIUM", nation:"RU", color:"#f97316" },
  { name:"TA577",           aliases:"Water Curupira", nation:"Cybercrime", color:"#64748b" },
];



function ThreatIntelTab({ flowSteps, setFlowSteps, gtiToken, setGtiToken, ghToken }) {
  const [query, setQuery]           = useState("");
  const [searchType, setSearchType] = useState("actor"); // actor | campaign
  const [loading, setLoading]       = useState(false);
  const [result, setResult]         = useState(null);
  const [error, setError]           = useState(null);
  const [showToken, setShowToken]   = useState(false);
  const [tokenInput, setTokenInput] = useState(gtiToken);
  const [coverage, setCoverage]     = useState({}); // technique → "matched"|"unmatched"|"loading"
  const [buildingFlow, setBuildingFlow] = useState(false);
  const [selectedTtps, setSelectedTtps] = useState(new Set());
  const [tacticFilter, setTacticFilter] = useState("all");

  // Check attack_data coverage for each TTP
  const checkCoverage = async (ttps) => {
    const result = {};
    // First pass — check local cache
    for (const t of ttps) {
      const baseId = t.id.split(".")[0];
      if (cache.yamls[t.id]) { result[t.id] = "matched"; continue; }
      if (cache.yamls[baseId]) { result[t.id] = "matched"; continue; }
      result[t.id] = "unknown";
    }
    setCoverage({...result});

    // Second pass — check GitHub API for unknowns
    const unknown = ttps.filter(t => result[t.id] === "unknown");
    for (const t of unknown) {
      setCoverage(prev => ({...prev, [t.id]: "loading"}));
      try {
        const headers = ghToken ? { Authorization: `token ${ghToken}` } : {};
        // Try exact match first, then parent technique
        const candidates = [t.id, t.id.split(".")[0]];
        let found = false;
        for (const cand of candidates) {
          const r = await fetch(`${API_BASE}/contents/datasets/attack_techniques/${cand}`, { headers });
          if (r.ok) { found = true; break; }
        }
        setCoverage(prev => ({...prev, [t.id]: found ? "matched" : "unmatched"}));
      } catch {
        setCoverage(prev => ({...prev, [t.id]: "unmatched"}));
      }
    }
  };

  const search = async () => {
    if (!query.trim()) return;
    if (!gtiToken) { setError("A GTI API key is required. Click 'add key' above to set your VT Enterprise key."); return; }
    setLoading(true); setError(null); setResult(null); setCoverage({}); setSelectedTtps(new Set());

    try {
      // Live GTI API call
      const endpoint = searchType === "actor"
        ? `${GTI_BASE}/threat_actors?filter=name%3A${encodeURIComponent(query)}&limit=5`
        : `${GTI_BASE}/collections?filter=name%3A${encodeURIComponent(query)}&limit=5`;
      const res = await fetch(endpoint, {
        headers: { "x-apikey": gtiToken, "Accept": "application/json" }
      });
      if (!res.ok) throw new Error(`GTI API ${res.status}: ${res.statusText}`);
      const data = await res.json();
      const items = data.data || [];
      if (items.length === 0) throw new Error(`No ${searchType}s found matching "${query}"`);

      // Take first result, fetch its attack_technique relationships
      const item = items[0];
      const relRes = await fetch(
        `${GTI_BASE}/${searchType === "actor" ? "threat_actors" : "collections"}/${item.id}/relationships/attack_techniques?limit=40`,
        { headers: { "x-apikey": gtiToken, "Accept": "application/json" } }
      );
      const relData = relRes.ok ? await relRes.json() : { data: [] };
      const ttps = (relData.data || []).map(t => ({
        id: t.id,
        tactic: getTactic(t.id),
        confidence: t.attributes?.confidence || 80,
        source: "GTI",
      }));

      const built = {
        id: item.id,
        type: searchType,
        name: item.attributes?.name || item.id,
        aliases: item.attributes?.aliases || [],
        nation: item.attributes?.country || "Unknown",
        color: "#22d3ee",
        ttps,
        description: item.attributes?.description || "",
        gtiUrl: `https://www.virustotal.com/gui/collection/${item.id}`,
        campaigns: 0, iocs: 0,
        firstSeen: item.attributes?.first_submission_date || "",
        lastSeen: item.attributes?.last_modification_date || "",
      };
      setResult(built);
      setSelectedTtps(new Set(ttps.map(t => t.id)));
      await checkCoverage(ttps);
    } catch(e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const buildFlow = async () => {
    if (!result || selectedTtps.size === 0) return;
    setBuildingFlow(true);

    // Sort selected TTPs by kill-chain phase order
    const sorted = result.ttps
      .filter(t => selectedTtps.has(t.id))
      .sort((a, b) => PHASE_ORDER.indexOf(a.tactic) - PHASE_ORDER.indexOf(b.tactic));

    const newSteps = [];
    for (const ttp of sorted) {
      // Only add TTPs with coverage
      if (coverage[ttp.id] !== "matched") continue;
      try {
        const candidates = [ttp.id, ttp.id.split(".")[0]];
        let ds = null;
        for (const cand of candidates) {
          let cached = cache.yamls[cand];
          if (!cached) cached = await fetchYamlsForTechnique(cand, ghToken);
          if (cached && cached.length > 0) { ds = cached[0]; break; }
        }
        if (ds && !newSteps.find(s => s.id === ds.id)) newSteps.push(ds);
      } catch {}
    }

    setFlowSteps(newSteps);
    setBuildingFlow(false);
  };

  const toggleTtp = (id) => setSelectedTtps(prev => {
    const n = new Set(prev);
    n.has(id) ? n.delete(id) : n.add(id);
    return n;
  });

  const selectAll   = (ids) => setSelectedTtps(prev => new Set([...prev, ...ids]));
  const deselectAll = (ids) => setSelectedTtps(prev => { const n=new Set(prev); ids.forEach(id=>n.delete(id)); return n; });

  // Group TTPs by tactic for display
  const groupedTtps = {};
  if (result) {
    result.ttps.forEach(t => {
      if (tacticFilter !== "all" && t.tactic !== tacticFilter) return;
      if (!groupedTtps[t.tactic]) groupedTtps[t.tactic] = [];
      groupedTtps[t.tactic].push(t);
    });
    // Sort groups by kill-chain phase
    Object.keys(groupedTtps).forEach(tac =>
      groupedTtps[tac].sort((a,b) => a.id.localeCompare(b.id))
    );
  }

  const matchedCount   = result ? result.ttps.filter(t => coverage[t.id] === "matched").length : 0;
  const unmatchedCount = result ? result.ttps.filter(t => coverage[t.id] === "unmatched").length : 0;
  const loadingCount   = result ? result.ttps.filter(t => coverage[t.id] === "loading" || coverage[t.id] === "unknown").length : 0;
  const selectedMatchedCount = result ? result.ttps.filter(t => selectedTtps.has(t.id) && coverage[t.id] === "matched").length : 0;

  const NATION_COLORS = { CN:"#ef4444", RU:"#f97316", KP:"#a855f7", IR:"#ec4899", RaaS:"#dc2626", EN:"#06b6d4", Cybercrime:"#64748b", Unknown:"#1e3a5f" };

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>

      {/* API key setup */}
      <Card style={{ padding:"12px 16px" }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <span style={{ fontSize:16 }}>🔑</span>
            <div>
              <div style={{...sans, fontSize:12, fontWeight:600, color:"#c8d8f0" }}>Google Threat Intelligence API</div>
              <div style={{...mono, fontSize:9, color:"#3d5a7a" }}>
                {gtiToken ? "VT Enterprise key active — live GTI search enabled" : "Add your VT Enterprise API key to enable threat actor search"}
              </div>
            </div>
          </div>
          <div style={{ display:"flex", gap:8, alignItems:"center" }}>
            {gtiToken
              ? <Pill label="live GTI ✓" color="#10b981" sm/>
              : <Pill label="key required" color="#ef4444" sm/>}
            <Btn variant="ghost" sm onClick={()=>setShowToken(v=>!v)}>
              {showToken ? "cancel" : gtiToken ? "update key" : "add key"}
            </Btn>
          </div>
        </div>
        {showToken && (
          <div style={{ marginTop:12, display:"flex", gap:8 }}>
            <input value={tokenInput} onChange={e=>setTokenInput(e.target.value)}
              type="password" placeholder="VT Enterprise API key (64 hex chars)"
              style={{ flex:1, background:"#030a17", border:"1px solid #0c1e38", borderRadius:6,
                padding:"7px 12px", color:"#c8d8f0", ...mono, fontSize:11, outline:"none" }}/>
            <Btn onClick={()=>{setGtiToken(tokenInput);setShowToken(false);}}>save</Btn>
          </div>
        )}
        {!gtiToken && (
          <div style={{ marginTop:10, padding:"8px 12px", background:"#1a0808",
            border:"1px solid #ef444420", borderRadius:6,
            ...mono, fontSize:9, color:"#ef4444" }}>
            ⓘ GTI API key required — get yours at virustotal.com/gui/my-apikey (VT Enterprise / GTI subscription needed)
          </div>
        )}
      </Card>

      {/* Search */}
      <Card>
        <SectionLabel>SEARCH THREAT ACTORS &amp; CAMPAIGNS</SectionLabel>
        <div style={{ display:"flex", gap:8, marginBottom:12 }}>
          <div style={{ display:"flex", borderRadius:6, overflow:"hidden", border:"1px solid #0c1e38", flexShrink:0 }}>
            {["actor","campaign"].map(t=>(
              <button key={t} onClick={()=>setSearchType(t)}
                style={{ padding:"8px 16px", background:searchType===t?"#091828":"#030a17",
                  border:"none", color:searchType===t?"#22d3ee":"#3d5a7a",
                  ...mono, fontSize:10, cursor:"pointer", borderRight:t==="actor"?"1px solid #0c1e38":"none" }}>
                {t==="actor" ? "🧑‍💻 Actor" : "🎯 Campaign"}
              </button>
            ))}
          </div>
          <input value={query} onChange={e=>setQuery(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&search()}
            placeholder={searchType==="actor" ? "Volt Typhoon, APT29, LockBit, Scattered Spider…" : "campaign name or ID…"}
            style={{ flex:1, background:"#030a17", border:"1px solid #0c1e38", borderRadius:6,
              padding:"8px 14px", color:"#c8d8f0", ...sans, fontSize:13, outline:"none" }}/>
          <Btn onClick={search} disabled={loading||!query.trim()}>
            {loading ? "searching…" : "→ search"}
          </Btn>
        </div>

        {/* Quick-pick actors */}
        <div>
          <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:8, letterSpacing:"0.1em" }}>QUICK SELECT</div>
          <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
            {KNOWN_ACTORS.map(a=>(
              <button key={a.name} onClick={()=>{setQuery(a.name);setSearchType("actor");}}
                style={{ padding:"4px 10px", borderRadius:4, cursor:"pointer",
                  background: query===a.name?"#091828":"transparent",
                  border:`1px solid ${query===a.name?a.color+"60":"#0c1e38"}`,
                  color: query===a.name?a.color:"#3d5a7a",
                  ...mono, fontSize:9, display:"flex", alignItems:"center", gap:5 }}>
                <span style={{ background:NATION_COLORS[a.nation]||"#1e3a5f", color:"#fff",
                  padding:"1px 4px", borderRadius:2, fontSize:8 }}>{a.nation}</span>
                {a.name}
              </button>
            ))}
          </div>
        </div>
      </Card>

      {/* Error */}
      {error && (
        <div style={{ padding:"12px 16px", background:"#1a0808", border:"1px solid #ef444430",
          borderRadius:8, ...mono, fontSize:11, color:"#ef4444", animation:"slideUp .2s" }}>
          ⚠ {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <Card>
          <div style={{ display:"flex", alignItems:"center", gap:12, padding:"8px 0",
            ...mono, fontSize:11, color:"#3d5a7a" }}>
            <Spinner/> Querying GTI for "{query}"…
          </div>
        </Card>
      )}

      {/* Result */}
      {result && !loading && (
        <div style={{ display:"flex", flexDirection:"column", gap:14, animation:"slideUp .25s" }}>

          {/* Actor / Campaign header */}
          <Card glow style={{ padding:"18px 20px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:16 }}>
              <div style={{ flex:1 }}>
                <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:8 }}>
                  <div style={{ width:10, height:10, borderRadius:"50%", background:result.color,
                    boxShadow:`0 0 12px ${result.color}` }}/>
                  <span style={{...sans, fontSize:22, fontWeight:800, color:"#e2f0ff" }}>{result.name}</span>
                  <Pill label={result.type === "threat-actor" ? "Threat Actor" : "Campaign"} color="#22d3ee" sm/>
                  {result.nation && result.nation !== "Unknown" && (
                    <span style={{ background:NATION_COLORS[result.nation]||"#1e3a5f",
                      color:"#fff", padding:"2px 8px", borderRadius:4, ...mono, fontSize:10, fontWeight:700 }}>
                      {result.nation}
                    </span>
                  )}
                </div>
                {result.aliases?.length > 0 && (
                  <div style={{...mono, fontSize:10, color:"#3d5a7a", marginBottom:10 }}>
                    Also known as: {result.aliases.join(" · ")}
                  </div>
                )}
                <div style={{...sans, fontSize:12, color:"#4a6a8a", lineHeight:1.6, maxWidth:700 }}>
                  {result.description}
                </div>
              </div>
              <div style={{ display:"flex", flexDirection:"column", gap:8, flexShrink:0, minWidth:140 }}>
                {[
                  ["TTPs",        result.ttps.length, "#22d3ee"],
                  ["Matched",     matchedCount,        "#10b981"],
                  ["Unmatched",   unmatchedCount,      "#ef4444"],
                  ["Checking",    loadingCount,        "#f59e0b"],
                ].map(([l,v,c])=>(
                  <div key={l} style={{ display:"flex", justifyContent:"space-between",
                    padding:"4px 10px", background:"#030a17", borderRadius:5, border:"1px solid #0c1e38" }}>
                    <span style={{...mono, fontSize:9, color:"#1e3a5f" }}>{l}</span>
                    <span style={{...mono, fontSize:12, fontWeight:700, color:c }}>{v}</span>
                  </div>
                ))}
                <a href={result.gtiUrl} target="_blank" rel="noopener noreferrer"
                  style={{ textAlign:"center", padding:"6px 10px", background:"#030a17",
                    border:"1px solid #22d3ee30", borderRadius:5, color:"#22d3ee",
                    ...mono, fontSize:9, textDecoration:"none" }}>
                  view in GTI →
                </a>
              </div>
            </div>
          </Card>

          {/* Coverage summary bar */}
          <Card style={{ padding:"12px 16px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:10 }}>
              <SectionLabel>ATTACK_DATA COVERAGE</SectionLabel>
              <div style={{ display:"flex", gap:6 }}>
                {["all",...new Set(result.ttps.map(t=>t.tactic))].filter(t=>t!=="Unknown").map(t=>(
                  <button key={t} onClick={()=>setTacticFilter(t)}
                    style={{ padding:"3px 8px", borderRadius:3, cursor:"pointer",
                      background:tacticFilter===t?`${TACTIC_COLORS[t]||"#22d3ee"}15`:"transparent",
                      border:`1px solid ${tacticFilter===t?TACTIC_COLORS[t]||"#22d3ee":"#0c1e38"}`,
                      color:tacticFilter===t?TACTIC_COLORS[t]||"#22d3ee":"#3d5a7a",
                      ...mono, fontSize:9, cursor:"pointer" }}>{t==="all"?"all":t.split(" ").map(w=>w[0]).join("")}</button>
                ))}
              </div>
            </div>
            <div style={{ display:"flex", height:6, borderRadius:3, overflow:"hidden", gap:1, marginBottom:10 }}>
              {result.ttps.map(t=>(
                <div key={t.id} title={`${t.id} — ${coverage[t.id]||"unknown"}`}
                  style={{ flex:1, background:
                    coverage[t.id]==="matched"?"#10b981":
                    coverage[t.id]==="unmatched"?"#ef444450":
                    coverage[t.id]==="loading"?"#f59e0b":
                    "#0c1e38", transition:"background .3s" }}/>
              ))}
            </div>
            <div style={{ display:"flex", gap:14 }}>
              {[["matched","#10b981","✓ have attack_data"],["unmatched","#ef4444","✗ no coverage"],["loading","#f59e0b","⟳ checking"]].map(([s,c,l])=>(
                <div key={s} style={{ display:"flex", alignItems:"center", gap:5 }}>
                  <div style={{ width:8, height:8, borderRadius:2, background:c }}/>
                  <span style={{...mono, fontSize:9, color:"#1e3a5f" }}>{l}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* TTP grid grouped by tactic */}
          <Card>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
              <SectionLabel>TTPS — {result.ttps.length} TECHNIQUES ({selectedTtps.size} SELECTED)</SectionLabel>
              <div style={{ display:"flex", gap:6 }}>
                <Btn variant="ghost" sm onClick={()=>selectAll(result.ttps.filter(t=>coverage[t.id]==="matched").map(t=>t.id))}>
                  select matched
                </Btn>
                <Btn variant="ghost" sm onClick={()=>setSelectedTtps(new Set(result.ttps.map(t=>t.id)))}>
                  select all
                </Btn>
                <Btn variant="secondary" sm onClick={()=>setSelectedTtps(new Set())}>
                  clear
                </Btn>
              </div>
            </div>

            <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
              {PHASE_ORDER.filter(phase => groupedTtps[phase]).map(phase => {
                const pttps = groupedTtps[phase];
                const tc = TACTIC_COLORS[phase] || "#1e293b";
                const phaseIds = pttps.map(t=>t.id);
                const allSel = phaseIds.every(id=>selectedTtps.has(id));
                return (
                  <div key={phase}>
                    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:7 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:7 }}>
                        <div style={{ width:3, height:14, borderRadius:2, background:tc }}/>
                        <span style={{...mono, fontSize:10, color:tc, fontWeight:700 }}>{phase.toUpperCase()}</span>
                        <span style={{...mono, fontSize:9, color:"#1e3a5f" }}>({pttps.length})</span>
                      </div>
                      <button onClick={()=> allSel ? deselectAll(phaseIds) : selectAll(phaseIds)}
                        style={{ background:"transparent", border:"none", color:"#1e3a5f",
                          ...mono, fontSize:9, cursor:"pointer" }}>
                        {allSel ? "deselect all" : "select all"}
                      </button>
                    </div>
                    <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))", gap:6 }}>
                      {pttps.map(t => {
                        const cov = coverage[t.id] || "unknown";
                        const isSel = selectedTtps.has(t.id);
                        const covColor = cov==="matched"?"#10b981":cov==="unmatched"?"#ef4444":cov==="loading"?"#f59e0b":"#1e3a5f";
                        return (
                          <div key={t.id} onClick={()=>toggleTtp(t.id)}
                            style={{ padding:"9px 11px", borderRadius:7, cursor:"pointer",
                              background: isSel?"#091828":"#030a17",
                              border:`1px solid ${isSel?tc+"50":"#0c1e38"}`,
                              transition:"all .15s", opacity: cov==="unmatched"?.6:1 }}>
                            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:4 }}>
                              <span style={{...mono, fontSize:12, color: isSel?"#c8d8f0":"#6a8aaa", fontWeight:isSel?700:400 }}>
                                {t.id}
                              </span>
                              <div style={{ display:"flex", alignItems:"center", gap:4 }}>
                                {isSel && <span style={{ color:tc, fontSize:9 }}>✓</span>}
                                <div style={{ width:7, height:7, borderRadius:"50%", background:covColor,
                                  boxShadow: cov==="loading"?"0 0 6px #f59e0b":"none",
                                  animation: cov==="loading"?"pulse 1s infinite":"none" }}/>
                              </div>
                            </div>
                            <div style={{...sans, fontSize:9, color:"#2a4060", marginBottom:5 }}>
                              {getTactic(t.id)}
                            </div>
                            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                              <span style={{...mono, fontSize:8, color:covColor }}>
                                {cov==="matched"?"✓ has data":cov==="unmatched"?"✗ no data":cov==="loading"?"checking…":"—"}
                              </span>
                              <span style={{...mono, fontSize:8, color:"#1e3a5f" }}>
                                {t.confidence}% conf
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>

          {/* Build flow CTA */}
          <Card glow style={{ padding:"18px 20px" }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", gap:16 }}>
              <div>
                <div style={{...sans, fontSize:15, fontWeight:700, color:"#e2f0ff", marginBottom:4 }}>
                  Build Attack Flow from {result.name}
                </div>
                <div style={{...sans, fontSize:11, color:"#3d5a7a" }}>
                  {selectedMatchedCount > 0
                    ? `${selectedMatchedCount} matched technique${selectedMatchedCount>1?"s":""} selected → will load datasets from splunk/attack_data, sorted by kill-chain phase`
                    : "Select techniques above (matched ones only will be included in the flow)"}
                </div>
                {unmatchedCount > 0 && (
                  <div style={{...mono, fontSize:10, color:"#f59e0b", marginTop:6 }}>
                    ⚠ {unmatchedCount} techniques have no attack_data coverage and will be skipped
                  </div>
                )}
              </div>
              <div style={{ display:"flex", gap:8, flexShrink:0 }}>
                <Btn variant="secondary" onClick={()=>{
                  // Export TTP list as JSON
                  const exp = {
                    actor: result.name, type: result.type, nation: result.nation,
                    queried: new Date().toISOString(),
                    source: "GTI API",
                    ttps: result.ttps.map(t=>({
                      id: t.id, tactic: t.tactic, confidence: t.confidence,
                      attack_data_coverage: coverage[t.id]||"unknown",
                    })),
                    coverage_summary: { matched: matchedCount, unmatched: unmatchedCount, total: result.ttps.length }
                  };
                  navigator.clipboard?.writeText(JSON.stringify(exp,null,2));
                }}>copy TTP JSON</Btn>
                <Btn onClick={buildFlow} disabled={buildingFlow||selectedMatchedCount===0}>
                  {buildingFlow ? "⟳ loading datasets…" : `⛓ build flow (${selectedMatchedCount} steps)`}
                </Btn>
              </div>
            </div>
            {flowSteps.length > 0 && (
              <div style={{ marginTop:12, padding:"8px 12px", background:"#030a17",
                border:"1px solid #10b98130", borderRadius:6,
                ...mono, fontSize:10, color:"#10b981" }}>
                ✓ Attack Flow populated with {flowSteps.length} steps — switch to the Attack Flow tab to review and reorder
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

// ─── APP SHELL ────────────────────────────────────────────────────────────────

const TABS = [
  {id:"threatintel",icon:"🧠", label:"Threat Intel"},
  {id:"flow",     icon:"⛓", label:"Attack Flow"},
  {id:"datasets", icon:"📂", label:"Datasets"},
  {id:"entities", icon:"🔍", label:"Entities"},
  {id:"tenants",  icon:"🏢", label:"Tenants"},
  {id:"schedule", icon:"⏰", label:"Schedule"},
  {id:"generate", icon:"⚙️", label:"Generate"},
  {id:"status",   icon:"📡", label:"Status"},
];

const PAGE_META = {
  threatintel:["Threat Intelligence",  "Search Google Threat Intelligence for threat actors and campaigns — extract MITRE TTPs, check attack_data coverage, and build an attack flow in one click"],
  flow:     ["Attack Flow Builder",   "Chain TTPs into an ordered attack sequence — drag to reorder, apply templates, export as JSON for CTF or workshop use"],
  datasets: ["Live Dataset Browser",  "Enumerate all technique folders from splunk/attack_data via GitHub API — click a technique to load its YAML manifests and add datasets to your flow"],
  entities: ["Entity Explorer",       "Hostnames, users, processes, IPs, and IOCs present in Attack Range datasets — filtered to your current flow"],
  tenants:  ["SecOps Tenants",        "Configure multi-tenant credentials — each tenant becomes a GitHub Actions matrix job"],
  schedule: ["Schedule & Timing",     "GitHub Actions cron schedule and logstory timestamp delta settings"],
  generate: ["Generate Artifacts",    "Export GitHub Actions workflow (HTTPS pull architecture), Python replay script, and GitHub CLI secret commands"],
  status:   ["Status & Monitoring",   "Monitor replay jobs, tenant health, and ingestion volume"],
};

export default function App() {
  const [tab, setTab]             = useState("threatintel");
  const [flowSteps, setFlowSteps] = useState([]);
  const [tenants, setTenants]     = useState([]);
  const [schedule, setSchedule]   = useState("1 0 * * *");
  const [delta, setDelta]         = useState("1d");
  const [ghToken, setGhToken]     = useState("");
  const [gtiToken, setGtiToken]   = useState("");

  const badges = {
    threatintel: 0, flow: flowSteps.length, datasets: 0,
    entities: 0, tenants: tenants.length,
    schedule: 0, generate: 0, status: SAMPLE_JOBS.filter(j=>j.status==="failed").length,
  };

  const [title, sub] = PAGE_META[tab];

  return (
    <div style={{ minHeight:"100vh", background:"#020810", color:"#c8d8f0", ...sans }}>
      <style>{globalCss}</style>

      {/* header */}
      <div style={{ position:"sticky", top:0, zIndex:300, background:"#020810",
        borderBottom:"1px solid #08172c" }}>
        <div style={{ maxWidth:1240, margin:"0 auto", padding:"0 24px",
          display:"flex", alignItems:"center", justifyContent:"space-between", height:50 }}>
          <div style={{ display:"flex", alignItems:"center", gap:12 }}>
            <div style={{ width:28, height:28, borderRadius:7, flexShrink:0,
              background:"linear-gradient(135deg,#0891b2,#0c6e8a)",
              display:"flex", alignItems:"center", justifyContent:"center",
              fontSize:13, boxShadow:"0 0 16px #0891b220" }}>⛓</div>
            <div>
              <div style={{ fontWeight:800, fontSize:14, letterSpacing:"0.04em", color:"#e2f0ff" }}>
                LOGSTORY ORCHESTRATOR
              </div>
              <div style={{...mono, fontSize:8, color:"#0c1e38", letterSpacing:"0.16em" }}>
                SPLUNK ATTACK DATA → SECOPS · HTTPS PULL · MULTI-TENANT · CTF & WORKSHOPS
              </div>
            </div>
          </div>
          <div style={{ display:"flex", gap:5, alignItems:"center" }}>
            {flowSteps.length > 0 && <Pill label={`${flowSteps.length} step flow`} color="#22d3ee" sm/>}
            {tenants.length > 0 && <Pill label={`${tenants.length} tenant${tenants.length>1?"s":""}`} color="#10b981" sm/>}
            <Pill label={schedule} color="#f59e0b" sm/>
            <Pill label={`Δ ${delta}`} color="#8b5cf6" sm/>
          </div>
        </div>

        <div style={{ maxWidth:1240, margin:"0 auto", padding:"0 24px",
          display:"flex", overflowX:"auto", gap:0 }}>
          {TABS.map(t=>(
            <button key={t.id} onClick={()=>setTab(t.id)}
              style={{ display:"flex", alignItems:"center", gap:6, padding:"10px 15px",
                background: tab===t.id?"#060f20":"transparent", border:"none",
                borderBottom: tab===t.id?"2px solid #22d3ee":"2px solid transparent",
                color: tab===t.id?"#22d3ee":"#3d5a7a",
                ...mono, fontSize:10, fontWeight:tab===t.id?700:400,
                letterSpacing:"0.1em", textTransform:"uppercase",
                cursor:"pointer", transition:"all .2s", whiteSpace:"nowrap" }}>
              <span style={{ fontSize:12 }}>{t.icon}</span>
              {t.label}
              {badges[t.id]>0 && (
                <span style={{ background:"#22d3ee18", color:"#22d3ee", border:"1px solid #22d3ee30",
                  borderRadius:10, padding:"0 5px", ...mono, fontSize:9, fontWeight:700 }}>
                  {badges[t.id]}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* content */}
      <div style={{ maxWidth:1240, margin:"0 auto", padding:"24px 24px 60px" }}>
        <div style={{ marginBottom:20 }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:5 }}>
            <span style={{ fontSize:18 }}>{TABS.find(t=>t.id===tab)?.icon}</span>
            <span style={{ fontWeight:700, fontSize:20, color:"#e2f0ff" }}>{title}</span>
          </div>
          <div style={{...mono, fontSize:11, color:"#1e3a5f" }}>{sub}</div>
        </div>

        {tab==="threatintel"&& <ThreatIntelTab flowSteps={flowSteps} setFlowSteps={setFlowSteps} gtiToken={gtiToken} setGtiToken={setGtiToken} ghToken={ghToken}/>}
        {tab==="flow"     && <AttackFlowBuilder flowSteps={flowSteps} setFlowSteps={setFlowSteps} ghToken={ghToken}/>}
        {tab==="datasets" && <DatasetBrowser flowSteps={flowSteps} setFlowSteps={setFlowSteps} ghToken={ghToken} setGhToken={setGhToken}/>}
        {tab==="entities" && <EntityExplorer flowSteps={flowSteps}/>}
        {tab==="tenants"  && <TenantManager tenants={tenants} setTenants={setTenants}/>}
        {tab==="schedule" && <ScheduleBuilder schedule={schedule} setSchedule={setSchedule} delta={delta} setDelta={setDelta}/>}
        {tab==="generate" && <GenerateTab tenants={tenants} flowSteps={flowSteps} schedule={schedule} delta={delta}/>}
        {tab==="status"   && <StatusMonitor tenants={tenants}/>}
      </div>

      {/* footer */}
      <div style={{ borderTop:"1px solid #06111f", padding:"12px 24px",
        display:"flex", justifyContent:"center", gap:24 }}>
        {[
          ["splunk/attack_data","https://github.com/splunk/attack_data"],
          ["chronicle/logstory","https://github.com/chronicle/logstory"],
          ["logstory docs","https://chronicle.github.io/logstory/"],
          ["MITRE ATT&CK","https://attack.mitre.org"],
          ["SecOps parsers","https://cloud.google.com/chronicle/docs/ingestion/parser-list/supported-default-parsers"],
        ].map(([l,h])=>(
          <a key={l} href={h} target="_blank" rel="noopener noreferrer"
            style={{...mono, fontSize:9, color:"#0c1e38", textDecoration:"none",
              letterSpacing:"0.05em", transition:"color .2s"}}
            onMouseEnter={e=>e.target.style.color="#22d3ee"}
            onMouseLeave={e=>e.target.style.color="#0c1e38"}>{l}</a>
        ))}
      </div>
    </div>
  );
}
