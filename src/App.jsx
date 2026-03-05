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

const SECOPS_LOG_TYPES = new Set([
  "APACHE","APACHE_TOMCAT","ARUBA_SWITCH","AWS_CLOUDTRAIL","AWS_CLOUDWATCH",
  "AWS_ROUTE53","AWS_S3_SERVER_ACCESS","AWS_VPC_FLOW","AZURE_AD","AZURE_AD_AUDIT",
  "AZURE_AD_CONTEXT","AZURE_AD_SIGNIN","AZURE_AD_USER","AZURE_APP_GATEWAY",
  "AZURE_FIREWALL","AZURE_KUBERNETES","AZURE_MONITOR","AZURE_NSG","AZURE_STORAGE",
  "AZURE_WAF","BARRACUDA_SPAM","BLUECOAT_PROXY","CARBON_BLACK","CARBON_BLACK_EDR",
  "CATO_NETWORKS","CHECK_POINT_FIREWALL","CISCO_ASA_FIREWALL","CISCO_EMAIL",
  "CISCO_FMC","CISCO_IOS","CISCO_ISE","CISCO_MERAKI","CISCO_ROUTER",
  "CISCO_SECURE_ENDPOINT","CISCO_STEALTHWATCH","CISCO_SWITCH","CISCO_UMBRELLA_DNS",
  "CISCO_UMBRELLA_PROXY","CISCO_VPN","CISCO_WSA","CITRIX_ADC","CITRIX_NETSCALER",
  "CLOUD_AUDIT","CLOUDFLARE","CLOUDFLARE_GATEWAY","COFENSE",
  "CROWDSTRIKE_EDR","CROWDSTRIKE_FALCON","CROWDSTRIKE_SPOTLIGHT","CYLANCE_PROTECT",
  "DARKTRACE","ELASTIC","EXCHANGE_MAIL","EXTRAHOP","F5_BIGIP_LTM",
  "FIREEYE_HX","FIREEYE_NX","FORTINET_FORTIANALYZER","FORTINET_FORTICLIENT",
  "FORTINET_FORTIEDR","FORTINET_FORTIGATE","FORTINET_FORTIMANAGER","FORTINET_FORTIPROXY",
  "GCP_AUDIT","GCP_CLOUDNAT","GCP_FIREWALL","GCP_IDS","GCP_LOADBALANCING","GCP_VPC_FLOW",
  "GOOGLE_CLOUD_ARMOR","GOOGLE_WORKSPACE_ACTIVITY","IMPERVA_WAF","INFOBLOX",
  "JUNIPER_FIREWALL","JUNIPER_ROUTER","JUNIPER_SWITCH","KUBERNETES_AUDIT","KUBERNETES_NODE",
  "LACEWORK","LINUX_SYSLOG","MCAFEE_AV","MCAFEE_EDR","MCAFEE_ENS","MCAFEE_EPO",
  "MICROSOFT_CLOUD_APP_SECURITY","MICROSOFT_DEFENDER_ENDPOINT","MICROSOFT_DEFENDER_IDENTITY",
  "MICROSOFT_GRAPH_ALERT","MICROSOFT_SCCM","MICROSOFT_SYSMON","MISP","NETSKOPE","NGINX",
  "O365_MANAGEMENT","OFFICE_365","OKTA","OKTA_SYSTEM_LOG","PALO_ALTO_CORTEX_XDR",
  "PALO_ALTO_FIREWALL","PALO_ALTO_GLOBALPROTECT","PALO_ALTO_NETWORKS_WILDFIRE",
  "PALO_ALTO_PRISMA_CLOUD","PING_FEDERATE","PROOFPOINT_MAIL","PROOFPOINT_ON_DEMAND",
  "QUALYS_VM","RAPID7_INSIGHTDR","RSA_NETWITNESS","SAILPOINT","SALESFORCE",
  "SENTINELONE_EDR","SERVICENOW","SONICWALL_FIREWALL","SOPHOS_CENTRAL","SOPHOS_ENDPOINT",
  "SPLUNK","SURICATA","SURICATA_EVE_JSON","SYMANTEC","SYMANTEC_DLP","SYMANTEC_EDR",
  "SYMANTEC_PROXY","SYSDIG","TANIUM","TENABLE","TRENDMICRO_AV","TRENDMICRO_VISIONONE",
  "UNIX_SYSLOG","VARONIS_DG","VECTRA_XDR","VMWARE_ESX","VMWARE_NSX","VMWARE_VCENTER",
  "WINDOWS_AD","WINDOWS_DEFENDER","WINDOWS_DNS","WINDOWS_DHCP","WINDOWS_EVENT","WINDOWS_SYSMON",
  "WINEVTLOG","POWERSHELL","CS_EDR","LINUX_SYSMON","BRO_JSON","OSQUERY",
  "ZSCALER_INTERNET_ACCESS","ZSCALER_PRIVATE_ACCESS","ZSCALER_WEB",
]);

const REGIONS = ["US","EU","ASIA","US-EAST1","EU-WEST2","ASIA-SOUTH1"];

const CRON_PRESETS = [
  {l:"Daily midnight", c:"1 0 * * *"},
  {l:"Daily 6am UTC",  c:"0 6 * * *"},
  {l:"Every 6h",       c:"0 */6 * * *"},
  {l:"Weekly Mon",     c:"1 0 * * 1"},
  {l:"Twice daily",    c:"1 0,12 * * *"},
  {l:"Custom",         c:""},
];

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
const cache = { folders: null, yamls: {}, index: null };

// Fetch the full git tree in one call and build a cross-reference:
//   repoIndex.byTechnique[T1078] = Set(["WINDOWS_SYSMON","CS_EDR", ...])
//   repoIndex.byLogType[WINDOWS_SYSMON] = Set(["T1078","T1003", ...])
//   repoIndex.tacticLogTypes[credential-access] = Set(["WINDOWS_SYSMON", ...])
async function fetchRepoIndex(token) {
  if (cache.index) return cache.index;
  const headers = token ? { Authorization: `token ${token}` } : {};

  // Single API call — truncated=false gives us all paths up to ~100k files
  const res = await fetch(
    `${API_BASE}/git/trees/master?recursive=1`,
    { headers }
  );
  if (!res.ok) throw new Error(`Tree API ${res.status}`);
  const data = await res.json();

  const byTechnique  = {};   // T1078 → Set of log types
  const byLogType    = {};   // WINDOWS_SYSMON → Set of techniques
  const tacticLogTypes = {}; // tactic → Set of log types

  // Paths look like: datasets/attack_techniques/T1078.001/rubeus/T1078.001_Rubeus.yml
  const ymlRe = /^datasets\/attack_techniques\/(T\d+(?:\.\d+)?)\//;

  for (const item of data.tree) {
    if (item.type !== "blob") continue;
    if (!item.path.endsWith(".yml")) continue;
    const m = item.path.match(ymlRe);
    if (!m) continue;
    const tech = m[1];

    // Derive log type from the yaml filename — filenames often contain sourcetype
    // e.g. T1078.001_windows_security.log → WINDOWS, attack_data_windows_sysmon.yml
    const fname = item.path.split("/").pop().toLowerCase();
    let lt = null;

    // Check filename against known log type keywords
    for (const logType of SECOPS_LOG_TYPES) {
      const key = logType.toLowerCase().replace(/_/g, "");
      const fnKey = fname.replace(/[_.-]/g, "");
      // Try progressively shorter substrings of the log type
      const parts = logType.toLowerCase().split("_");
      const firstTwo = parts.slice(0, 2).join("");
      if (fnKey.includes(firstTwo) || fnKey.includes(key.slice(0, 8))) {
        lt = logType;
        break;
      }
    }

    if (!lt) continue; // can't map this file to a log type

    const tactic = getTactic(tech);

    if (!byTechnique[tech]) byTechnique[tech] = new Set();
    byTechnique[tech].add(lt);

    if (!byLogType[lt]) byLogType[lt] = new Set();
    byLogType[lt].add(tech);

    if (tactic) {
      if (!tacticLogTypes[tactic]) tacticLogTypes[tactic] = new Set();
      tacticLogTypes[tactic].add(lt);
    }
  }

  cache.index = { byTechnique, byLogType, tacticLogTypes };
  return cache.index;
}

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

function FlowBuilder({ flowSteps, setFlowSteps, ghToken, setGhToken }) {
  // ── Dataset browser state ──────────────────────────────────────────────────
  const [techniques, setTechniques]   = useState([]);
  const [loadingFolders, setLoadingFolders] = useState(false);
  const [folderError, setFolderError] = useState(null);
  const [repoIndex, setRepoIndex]     = useState(null); // cross-ref: tactic↔logtype↔technique
  const [search, setSearch]           = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [logTypeFilter, setLogTypeFilter] = useState("all");
  const [expanded, setExpanded]       = useState(null);
  const [techDatasets, setTechDatasets] = useState({});
  const [loadingTech, setLoadingTech] = useState(null);
  const [tokenInput, setTokenInput]   = useState(ghToken);
  const [showTokenForm, setShowTokenForm] = useState(false);
  const [browserOpen, setBrowserOpen] = useState(false);

  // ── Flow builder state ─────────────────────────────────────────────────────
  const [opName, setOpName]           = useState("Operation Chimera");
  const [opDesc, setOpDesc]           = useState("");
  const [openStep, setOpenStep]       = useState(null);
  const [swapStep, setSwapStep]       = useState(null);
  const [swapVariants, setSwapVariants] = useState({});
  const [loadingSwap, setLoadingSwap] = useState(null);

  // ── Dataset browser logic ──────────────────────────────────────────────────
  const loadFolders = async (tok) => {
    setLoadingFolders(true); setFolderError(null);
    const token = tok || ghToken;
    try {
      const folders = await fetchTechniqueFolders(token);
      setTechniques(folders);
      // Fire index fetch in background — doesn't block the folder list
      fetchRepoIndex(token).then(idx => setRepoIndex(idx)).catch(() => {});
    } catch(e) { setFolderError(e.message); }
    finally { setLoadingFolders(false); }
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

  const addToFlow   = (ds) => setFlowSteps(prev => prev.find(s => s.id === ds.id) ? prev : [...prev, ds]);
  const isInFlow    = (ds) => flowSteps.some(s => s.id === ds.id);

  // ── Filter options derived from repoIndex (populated after background fetch) ─
  // Log types available for the current tactic selection (or all if no tactic)
  const availableLogTypes = (() => {
    if (!repoIndex) return ["all", ...Array.from(SECOPS_LOG_TYPES).sort()];
    if (tacticFilter === "all") {
      return ["all", ...Array.from(
        new Set(Object.values(repoIndex.byLogType).flatMap(s => [...s]).length > 0
          ? Object.keys(repoIndex.byLogType)
          : SECOPS_LOG_TYPES)
      ).sort()];
    }
    // Only log types that actually have datasets for this tactic
    const lts = repoIndex.tacticLogTypes[tacticFilter];
    return ["all", ...(lts ? [...lts].sort() : Array.from(SECOPS_LOG_TYPES).sort())];
  })();

  // Tactics available for the current log type selection (or all if no log type)
  const availableTactics = (() => {
    if (!repoIndex || logTypeFilter === "all") return ["all", ...Object.keys(TACTIC_COLORS)];
    // Which techniques have this log type?
    const techs = repoIndex.byLogType[logTypeFilter] || new Set();
    // Which tactics do those techniques belong to?
    const tactics = new Set([...techs].map(t => getTactic(t)).filter(Boolean));
    return ["all", ...Object.keys(TACTIC_COLORS).filter(t => tactics.has(t))];
  })();

  // Filter techniques using repoIndex for cross-filter, falling back to techDatasets for loaded ones
  const filteredTechs = techniques.filter(t => {
    const matchSearch = !search || t.toLowerCase().includes(search.toLowerCase());
    const matchTactic = tacticFilter === "all" || getTactic(t) === tacticFilter;
    const matchLogType = logTypeFilter === "all" || (() => {
      // If we have the index, use it
      if (repoIndex) return (repoIndex.byTechnique[t] || new Set()).has(logTypeFilter);
      // Fall back to lazily-loaded data
      if (techDatasets[t]) return techDatasets[t].some(d => d.lt === logTypeFilter);
      return true; // unloaded, show optimistically
    })();
    return matchSearch && matchTactic && matchLogType;
  });

  // Stats for loaded datasets
  const allLoadedDs = Object.values(techDatasets).flat();
  const mappedCount = allLoadedDs.filter(d => SECOPS_LOG_TYPES.has(d.lt)).length;
  const unmappedCount = allLoadedDs.length - mappedCount;

  // ── Flow builder logic ─────────────────────────────────────────────────────
  const openSwap = async (s) => {
    if (swapStep === s.id) { setSwapStep(null); return; }
    setSwapStep(s.id); setOpenStep(null);
    if (swapVariants[s.id]) return;
    setLoadingSwap(s.id);
    try {
      const candidates = [...new Set([s.technique, s.technique?.split(".")[0]])].filter(Boolean);
      let all = [];
      for (const cand of candidates) {
        const ds = await fetchYamlsForTechnique(cand, ghToken);
        all = [...all, ...ds];
      }
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
      log_type: s.lt, media_url: s.mediaUrl,
      source: s.source, sourcetype: s.sourcetype,
    }))
  }, null, 2);

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>

      {/* ── Op metadata + import ───────────────────────────────────────────── */}
      <Card>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr auto", gap:12, alignItems:"end" }}>
          <Inp label="Operation / CTF Name" value={opName} onChange={setOpName} placeholder="Operation Chimera"/>
          <Inp label="Brief / Scenario Description" value={opDesc} onChange={setOpDesc}
            placeholder="Blue team detection workshop…"/>
          <div>
            <div style={{...mono, fontSize:9, color:"#3d5a7a", marginBottom:6, letterSpacing:"0.08em"}}>
              IMPORT TECHNIQUES
            </div>
            <div style={{ display:"flex", gap:8 }}>
              <input
                placeholder="T1078, T1055, T1003…  (comma-separated or paste JSON)"
                style={{ width:320, background:"#030a17", border:"1px solid #0c1e38", borderRadius:6,
                  padding:"7px 10px", color:"#c8d8f0", ...mono, fontSize:11, outline:"none" }}
                onKeyDown={e => {
                  if (e.key !== "Enter") return;
                  const val = e.target.value.trim();
                  let techs = [];
                  try {
                    const parsed = JSON.parse(val);
                    // Accept attack-flow JSON export or plain array
                    if (Array.isArray(parsed)) techs = parsed.map(t => typeof t==="string"?t:t.technique).filter(Boolean);
                    else if (parsed.steps) techs = parsed.steps.map(s=>s.technique).filter(Boolean);
                  } catch {
                    techs = val.split(/[,\s]+/).map(s=>s.trim()).filter(s=>/^T\d/.test(s));
                  }
                  if (techs.length > 0) {
                    techs.forEach(tech => {
                      const id = `import/${tech}/${Date.now()}`;
                      addToFlow({ id, technique:tech, name:`${tech}-dataset`, lt:"UNKNOWN",
                        ltColor:"#475569", mitre:[tech], desc:`Imported technique`,
                        mediaUrl:`${RAW_BASE}/datasets/attack_techniques/${tech}/atomic_red_team/windows-sysmon.log`,
                        source:"", sourcetype:"" });
                    });
                    e.target.value = "";
                  }
                }}
              />
            </div>
            <div style={{...mono, fontSize:9, color:"#1e3a5f", marginTop:4}}>
              Press Enter · accepts T-IDs, comma list, or ATT&amp;CK Flow JSON export
            </div>
          </div>
        </div>
      </Card>

      {/* ── Attack chain ────────────────────────────────────────────────────── */}
      <Card>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
          <div style={{ display:"flex", alignItems:"center", gap:12 }}>
            <SectionLabel>ATTACK CHAIN — {flowSteps.length} STEPS</SectionLabel>
            {Object.entries(tacticCoverage).map(([t,n]) => {
              const c = TACTIC_COLORS[t]||"#475569";
              return (
                <div key={t} style={{ display:"flex", alignItems:"center", gap:4,
                  padding:"2px 7px", background:`${c}12`, borderRadius:4, border:`1px solid ${c}28` }}>
                  <span style={{...mono, fontSize:9, color:c}}>{t}</span>
                  <span style={{ background:c, color:"#fff", borderRadius:"50%",
                    width:14, height:14, display:"flex", alignItems:"center",
                    justifyContent:"center", fontSize:8, fontWeight:"bold" }}>{n}</span>
                </div>
              );
            })}
          </div>
          <div style={{ display:"flex", gap:8 }}>
            {flowSteps.length > 0 && <Btn variant="secondary" sm onClick={()=>setFlowSteps([])}>clear all</Btn>}
            <Btn variant="primary" sm onClick={()=>setBrowserOpen(v=>!v)}>
              {browserOpen ? "▲ close browser" : "+ add step"}
            </Btn>
          </div>
        </div>

        {flowSteps.length === 0 && !browserOpen && (
          <div style={{ padding:"40px 0", textAlign:"center", ...sans, fontSize:12, color:"#162035" }}>
            Paste technique IDs above and press Enter, or click <strong style={{color:"#22d3ee"}}>+ add step</strong> to browse datasets
          </div>
        )}

        {flowSteps.length > 0 && (
          <div style={{ display:"flex", flexDirection:"column", gap:0, marginBottom: browserOpen ? 16 : 0 }}>
            {flowSteps.map((s,i) => {
              const tc = TACTIC_COLORS[getTactic(s.mitre?.[0]||s.technique)] || "#1e293b";
              const isOpen = openStep === s.id;
              const isSwap = swapStep === s.id;
              const variants = swapVariants[s.id] || [];
              return (
                <div key={s.id}>
                  <div style={{ display:"flex", alignItems:"center", gap:12, padding:"11px 12px",
                    background: isSwap?"#091828":"#040c1a",
                    border:`1px solid ${isSwap?"#f59e0b35":"#0c1e38"}`,
                    borderRadius: isSwap||isOpen ? "8px 8px 0 0" : 8 }}>

                    {/* step number */}
                    <div style={{ display:"flex", flexDirection:"column", gap:2, alignItems:"center", flexShrink:0 }}>
                      <div style={{ width:28, height:28, borderRadius:"50%",
                        background:`${tc}18`, border:`2px solid ${tc}55`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        ...mono, fontSize:11, fontWeight:700, color:tc }}>{i+1}</div>
                      <div style={{ display:"flex", flexDirection:"column", gap:1 }}>
                        <button onClick={()=>{ if(i===0) return; setFlowSteps(p=>{const a=[...p];[a[i-1],a[i]]=[a[i],a[i-1]];return a;}); }}
                          disabled={i===0}
                          style={{ background:"none", border:"none", color:i===0?"#0c1e38":"#3d5a7a",
                            cursor:i===0?"default":"pointer", fontSize:9, padding:"1px 3px", lineHeight:1 }}>▲</button>
                        <button onClick={()=>{ if(i===flowSteps.length-1) return; setFlowSteps(p=>{const a=[...p];[a[i],a[i+1]]=[a[i+1],a[i]];return a;}); }}
                          disabled={i===flowSteps.length-1}
                          style={{ background:"none", border:"none", color:i===flowSteps.length-1?"#0c1e38":"#3d5a7a",
                            cursor:i===flowSteps.length-1?"default":"pointer", fontSize:9, padding:"1px 3px", lineHeight:1 }}>▼</button>
                      </div>
                    </div>

                    <div style={{ width:3, height:36, borderRadius:2, background:tc, flexShrink:0 }}/>

                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:7, marginBottom:3 }}>
                        <span style={{...mono, fontSize:12, color:"#c8d8f0", fontWeight:600 }}>{s.name}</span>
                        <Pill label={s.technique} color="#f59e0b" sm/>
                        <Pill label={s.lt} color={s.ltColor||"#475569"} sm/>
                        {SECOPS_LOG_TYPES.has(s.lt)
                          ? <Pill label="✓ SecOps" color="#10b981" sm/>
                          : <Pill label="⚠ unmapped" color="#f59e0b" sm/>}
                        {s.tool && <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{s.tool}</span>}
                      </div>
                      <div style={{...sans, fontSize:10, color:"#2a4060" }}>{s.desc?.slice(0,80)}{s.desc?.length>80?"…":""}</div>
                    </div>

                    <Pill label={getTactic(s.technique)} color={tc} sm dot/>
                    <div style={{ display:"flex", gap:5, flexShrink:0 }}>
                      <Btn variant={isSwap?"primary":"ghost"} sm onClick={e=>{e.stopPropagation();openSwap(s);}}>
                        {isSwap ? "▲ variants" : "⇄ swap"}
                      </Btn>
                      <Btn variant="ghost" sm onClick={()=>{setOpenStep(isOpen?null:s.id);setSwapStep(null);}}>
                        {isOpen?"▲":"▼"}
                      </Btn>
                      <Btn variant="danger" sm onClick={()=>setFlowSteps(p=>p.filter(x=>x.id!==s.id))}>×</Btn>
                    </div>
                  </div>

                  {/* swap panel */}
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
                          <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{variants.length} variant{variants.length!==1?"s":""} available</span>
                        )}
                      </div>
                      {loadingSwap===s.id && <div style={{...mono, fontSize:10, color:"#3d5a7a", padding:"8px 0" }}>fetching variants for {s.technique}…</div>}
                      {!loadingSwap && variants.length === 0 && <div style={{...mono, fontSize:10, color:"#1e3a5f", padding:"8px 0" }}>No other variants found</div>}
                      {!loadingSwap && variants.map(v => {
                        const isCurrent = v.name === s.name && v.tool === s.tool;
                        return (
                          <div key={v.id}
                            style={{ display:"flex", alignItems:"center", gap:10,
                              padding:"8px 10px", marginBottom:4, borderRadius:6,
                              background: isCurrent?"#081b14":"#030a17",
                              border:`1px solid ${isCurrent?"#10b98130":"#0c1e38"}`,
                              cursor: isCurrent?"default":"pointer", opacity: isCurrent?.7:1, transition:"all .15s" }}
                            onClick={()=>!isCurrent&&swapVariant(s.id, v)}>
                            <div style={{ flex:1, minWidth:0 }}>
                              <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:3 }}>
                                <span style={{...mono, fontSize:11, color: isCurrent?"#10b981":"#c8d8f0", fontWeight: isCurrent?700:400 }}>{v.name}</span>
                                {isCurrent && <Pill label="current" color="#10b981" sm/>}
                                <Pill label={v.lt} color={v.ltColor||"#475569"} sm/>
                              </div>
                              <div style={{ display:"flex", gap:6 }}>
                                <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{v.tool}</span>
                                {v.source && <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>· {v.source.split(":").pop()}</span>}
                              </div>
                            </div>
                            {!isCurrent && <Btn variant="ghost" sm>use this →</Btn>}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* detail panel */}
                  {isOpen && (
                    <div style={{ padding:"12px 56px", background:"#030a17",
                      borderLeft:"3px solid #0c1e38", marginBottom:2, animation:"slideUp .15s" }}>
                      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                        <div>
                          <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>MEDIA URL (HTTPS PULL)</div>
                          <div style={{...mono, fontSize:9, color:"#3d5a7a", wordBreak:"break-all", lineHeight:1.5 }}>{s.mediaUrl||"—"}</div>
                        </div>
                        <div>
                          <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>SOURCE / SOURCETYPE</div>
                          <div style={{...mono, fontSize:9, color:"#3d5a7a" }}>{s.source||"—"}</div>
                        </div>
                        <div>
                          <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:4 }}>SECOPS LOG TYPE</div>
                          <Pill label={s.lt} color={s.ltColor||"#475569"} sm/>
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
        )}

        {/* ── Inline Dataset Browser ─────────────────────────────────────────── */}
        {browserOpen && (
          <div style={{ borderTop: flowSteps.length > 0 ? "1px solid #0c1e38" : "none",
            paddingTop: flowSteps.length > 0 ? 16 : 0 }}>

            {/* token bar */}
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
              marginBottom:12, padding:"10px 12px", background:"#030a17",
              borderRadius:8, border:"1px solid #0c1e38" }}>
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ fontSize:13 }}>🔑</span>
                <div style={{...mono, fontSize:10, color: ghToken ? "#10b981" : "#f59e0b"}}>
                  {ghToken ? "GitHub token set — 5,000 req/hr" : "No token — 60 req/hr (may hit limit)"}
                </div>
              </div>
              <div style={{ display:"flex", gap:8 }}>
                {ghToken && <Pill label="authenticated ✓" color="#10b981" sm/>}
                <Btn variant="ghost" sm onClick={()=>setShowTokenForm(v=>!v)}>
                  {showTokenForm ? "cancel" : ghToken ? "update token" : "add token"}
                </Btn>
                <Btn variant="secondary" sm onClick={()=>loadFolders()}>↻</Btn>
              </div>
            </div>

            {showTokenForm && (
              <div style={{ display:"flex", gap:8, marginBottom:12 }}>
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

            {/* search + filters */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:10, marginBottom:10 }}>
              <Inp label="Search technique ID or keyword" value={search} onChange={setSearch}
                placeholder="T1003, kerberos, lateral…" mono/>
              <Sel
                label={`Filter by Tactic${logTypeFilter !== "all" ? ` · ${availableTactics.length - 1} match` : ""}`}
                value={tacticFilter} onChange={v => { setTacticFilter(v); setLogTypeFilter("all"); }}
                options={availableTactics}/>
              <Sel
                label={`Filter by Log Type${repoIndex ? ` · ${availableLogTypes.length - 1} available` : " · indexing…"}`}
                value={logTypeFilter} onChange={v => { setLogTypeFilter(v); setTacticFilter("all"); }}
                options={availableLogTypes}/>
            </div>

            {/* stats bar */}
            <div style={{ display:"flex", gap:12, alignItems:"center", marginBottom:10, flexWrap:"wrap" }}>
              <div style={{...mono, fontSize:10, color:"#1e3a5f"}}>
                {loadingFolders ? "loading from GitHub API…"
                  : `${filteredTechs.length} techniques · ${allLoadedDs.length} datasets loaded · ${flowSteps.length} in flow`}
              </div>
              {allLoadedDs.length > 0 && (
                <>
                  <div style={{ display:"flex", alignItems:"center", gap:5, padding:"2px 8px",
                    background:"#10b98112", border:"1px solid #10b98128", borderRadius:4 }}>
                    <span style={{...mono, fontSize:9, color:"#10b981"}}>✓ {mappedCount} SecOps mapped</span>
                  </div>
                  {unmappedCount > 0 && (
                    <div style={{ display:"flex", alignItems:"center", gap:5, padding:"2px 8px",
                      background:"#f59e0b12", border:"1px solid #f59e0b28", borderRadius:4 }}>
                      <span style={{...mono, fontSize:9, color:"#f59e0b"}}>⚠ {unmappedCount} unmapped</span>
                    </div>
                  )}
                  {logTypeFilter !== "all" && (
                    <div style={{ display:"flex", alignItems:"center", gap:5, padding:"2px 8px",
                      background:"#22d3ee12", border:"1px solid #22d3ee28", borderRadius:4 }}>
                      <span style={{...mono, fontSize:9, color:"#22d3ee"}}>filter: {logTypeFilter}</span>
                      <span onClick={()=>setLogTypeFilter("all")}
                        style={{ cursor:"pointer", color:"#22d3ee", fontSize:11, lineHeight:1 }}>×</span>
                    </div>
                  )}
                </>
              )}
            </div>

            {folderError && (
              <div style={{ padding:"10px 14px", background:"#1a0808", border:"1px solid #ef444430",
                borderRadius:8, ...mono, fontSize:11, color:"#ef4444", marginBottom:8 }}>
                ⚠ {folderError}
                {folderError.includes("403") && <span style={{ color:"#f59e0b" }}> — add a GitHub token to increase rate limit</span>}
              </div>
            )}

            {/* technique list */}
            <div style={{ display:"flex", flexDirection:"column", gap:4, maxHeight:480, overflowY:"auto" }}>
              {loadingFolders && Array(6).fill(0).map((_,i) => <SkeletonRow key={i}/>)}
              {!loadingFolders && filteredTechs.map(tech => {
                const tactic = getTactic(tech);
                const tc = TACTIC_COLORS[tactic] || "#1e293b";
                const isExp = expanded === tech;
                const ds = techDatasets[tech] || [];
                const inFlowCount = ds.filter(d => isInFlow(d)).length;
                return (
                  <div key={tech}>
                    <div onClick={()=>expandTechnique(tech)}
                      style={{ display:"flex", alignItems:"center", gap:12, padding:"9px 14px",
                        background: isExp ? "#091828" : "#060f20",
                        border:`1px solid ${isExp?"#22d3ee25":"#0c1e38"}`,
                        borderRadius: isExp ? "8px 8px 0 0" : 8,
                        cursor:"pointer", transition:"all .15s" }}>
                      <div style={{ width:3, height:28, borderRadius:2, background:tc, flexShrink:0 }}/>
                      <div style={{ flex:1 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                          <span style={{...mono, fontSize:12, color:"#c8d8f0", fontWeight:600}}>{tech}</span>
                          {inFlowCount > 0 && <Pill label={`${inFlowCount} in flow`} color="#22d3ee" sm/>}
                          {loadingTech === tech && <Spinner size={12}/>}
                        </div>
                        <div style={{...sans, fontSize:10, color:"#3d5a7a", marginTop:1}}>
                          {tactic}{ds.length > 0 && <span style={{ color:"#1e3a5f" }}> · {ds.length} datasets</span>}
                        </div>
                      </div>
                      <Pill label={tactic} color={tc} sm dot/>
                      <span style={{ color:"#1e3a5f", fontSize:11 }}>{isExp?"▲":"▼"}</span>
                    </div>
                    {isExp && (
                      <div style={{ background:"#040c1a", border:"1px solid #0c1e38",
                        borderTop:"none", borderRadius:"0 0 8px 8px", padding:"8px" }}>
                        {loadingTech === tech && (
                          <div style={{ display:"flex", alignItems:"center", gap:10, padding:"12px",
                            ...mono, fontSize:11, color:"#3d5a7a" }}>
                            <Spinner/> fetching YAML manifests…
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
                                border:`1px solid ${inF?"#22d3ee20":"transparent"}` }}>
                              <div style={{ flex:1, minWidth:0 }}>
                                <div style={{ display:"flex", alignItems:"center", gap:7, marginBottom:2 }}>
                                  <span style={{...mono, fontSize:11, color: inF?"#c8d8f0":"#6a8aaa", fontWeight: inF?600:400}}>
                                    {d.name}
                                  </span>
                                  <Pill label={d.lt} color={d.ltColor} sm/>
                                  {SECOPS_LOG_TYPES.has(d.lt)
                                    ? <Pill label="✓ SecOps" color="#10b981" sm/>
                                    : <Pill label="⚠ unmapped" color="#f59e0b" sm/>}
                                  {d.source && <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{d.source.split(":").pop()}</span>}
                                </div>
                                <div style={{...mono, fontSize:9, color:"#1e3a5f", wordBreak:"break-all"}}>{d.mediaUrl||d.yamlPath}</div>
                              </div>
                              <Btn variant={inF?"secondary":"ghost"} sm
                                onClick={()=>inF ? setFlowSteps(p=>p.filter(s=>s.id!==d.id)) : addToFlow(d)}>
                                {inF ? "✓ added" : "+ add"}
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
        )}
      </Card>

      {/* ── Flow Export ─────────────────────────────────────────────────────── */}
      {flowSteps.length > 0 && (
        <Card>
          <SectionLabel>FLOW EXPORT JSON</SectionLabel>
          <CodeBlock code={exportFlow()} maxH="220px" filename={`${opName.toLowerCase().replace(/\s+/g,"-")}-flow.json`}/>
        </Card>
      )}
    </div>
  );
}

function ConfigTab({ tenants, setTenants, schedule, setSchedule, delta, setDelta, ghToken, setGhToken, ghRepo, setGhRepo }) {
  const empty = { name:"", label:"", customerId:"", region:"US", credentials:"", ingestionLabels:[] };
  const [form, setForm]     = useState(empty);
  const [editIdx, setEditIdx] = useState(null);
  const [labelKey, setLabelKey] = useState("");
  const [labelVal, setLabelVal] = useState("");
  const [preset, setPreset] = useState("Daily midnight");
  const [showTokenForm, setShowTokenForm] = useState(false);
  const [tokenInput, setTokenInput] = useState(ghToken);
  const f = k => v => setForm(p=>({...p,[k]:v}));

  const save = () => {
    if (!form.name || !form.customerId) return;
    if (editIdx !== null) {
      setTenants(t=>t.map((x,i)=>i===editIdx?{...form}:x)); setEditIdx(null);
    } else setTenants(t=>[...t,{...form}]);
    setForm(empty); setLabelKey(""); setLabelVal("");
  };

  const addLabel = () => {
    if (!labelKey.trim()) return;
    setForm(p=>({...p, ingestionLabels:[...(p.ingestionLabels||[]), {key:labelKey.trim(), value:labelVal.trim()}]}));
    setLabelKey(""); setLabelVal("");
  };

  const removeLabel = idx => setForm(p=>({...p, ingestionLabels:(p.ingestionLabels||[]).filter((_,i)=>i!==idx)}));
  const parts = schedule.split(" ");

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>

      {/* ── GitHub / API ─────────────────────────────────────────────────── */}
      <Card>
        <SectionLabel>GITHUB</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
          <div>
            <Inp label="Runner repo (owner/repo)" value={ghRepo} onChange={setGhRepo}
              mono placeholder="keith-manville/demo-data"/>
          </div>
          <div>
            <div style={{...mono, fontSize:9, color:"#3d5a7a", marginBottom:6, letterSpacing:"0.08em"}}>GITHUB TOKEN</div>
            <div style={{ display:"flex", gap:8, alignItems:"center" }}>
              {ghToken
                ? <div style={{ display:"flex", gap:8, alignItems:"center", flex:1 }}>
                    <Pill label="token set ✓" color="#10b981" sm/>
                    <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>5,000 req/hr</span>
                    <Btn variant="ghost" sm onClick={()=>setShowTokenForm(v=>!v)}>update</Btn>
                  </div>
                : <Btn variant="secondary" sm onClick={()=>setShowTokenForm(v=>!v)}>+ add token</Btn>
              }
            </div>
            {showTokenForm && (
              <div style={{ display:"flex", gap:8, marginTop:8 }}>
                <input value={tokenInput} onChange={e=>setTokenInput(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxx" type="password"
                  style={{ flex:1, background:"#030a17", border:"1px solid #0c1e38", borderRadius:6,
                    padding:"7px 10px", color:"#c8d8f0", ...mono, fontSize:11, outline:"none" }}/>
                <Btn sm onClick={()=>{ setGhToken(tokenInput); setShowTokenForm(false); }}>save</Btn>
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* ── Schedule ─────────────────────────────────────────────────────── */}
      <Card>
        <SectionLabel>SCHEDULE & TIMING</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
          {/* cron */}
          <div>
            <div style={{...mono, fontSize:9, color:"#3d5a7a", marginBottom:8, letterSpacing:"0.08em"}}>CRON PRESET</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6, marginBottom:10 }}>
              {CRON_PRESETS.map(p=>(
                <button key={p.l} onClick={()=>{setPreset(p.l);if(p.c)setSchedule(p.c);}}
                  style={{ padding:"7px 10px", textAlign:"left",
                    background:preset===p.l?"#091828":"#030a17",
                    border:`1px solid ${preset===p.l?"#22d3ee35":"#0c1e38"}`,
                    color:preset===p.l?"#22d3ee":"#3d5a7a", borderRadius:6,
                    ...mono, fontSize:10, cursor:"pointer" }}>{p.l}</button>
              ))}
            </div>
            {preset==="Custom" && (
              <Inp label="Cron Expression" value={schedule} onChange={setSchedule} placeholder="1 0 * * *" mono/>
            )}
            <div style={{ display:"flex", gap:5, marginTop:8 }}>
              {["MIN","HOUR","DOM","MON","DOW"].map((lbl,i)=>(
                <div key={lbl} style={{ flex:1, textAlign:"center", background:"#030a17",
                  border:"1px solid #0c1e38", borderRadius:6, padding:"8px 4px" }}>
                  <div style={{...mono, fontSize:7, color:"#1e3a5f", marginBottom:3}}>{lbl}</div>
                  <div style={{...mono, fontSize:14, color:"#22d3ee", fontWeight:700}}>{parts[i]||"*"}</div>
                </div>
              ))}
            </div>
          </div>
          {/* delta */}
          <div>
            <div style={{...mono, fontSize:9, color:"#3d5a7a", marginBottom:8, letterSpacing:"0.08em"}}>TIMESTAMP DELTA</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6, marginBottom:10 }}>
              {["1d","1d1h","2d","0d"].map(v=>(
                <button key={v} onClick={()=>setDelta(v)}
                  style={{ padding:"12px 8px", borderRadius:6, cursor:"pointer",
                    background:delta===v?"#091828":"#030a17",
                    border:`1px solid ${delta===v?"#22d3ee35":"#0c1e38"}`,
                    color:delta===v?"#22d3ee":"#3d5a7a",
                    ...mono, fontSize:16, fontWeight:700 }}>{v}</button>
              ))}
            </div>
            <div style={{ padding:"10px 12px", background:"#030a17", border:"1px solid #0c1e38",
              borderRadius:6, ...mono, fontSize:10, color:"#3d5a7a", lineHeight:1.5 }}>
              {{"1d":"Recommended for daily midnight cron — events land yesterday, within detection window",
                "1d1h":"Offset by 1d1h — prevents deduplication if running multiple times",
                "2d":"Use when your ingestion pipeline has a lag before alerts fire",
                "0d":"Updates date only, keeps HH:MM:SS — events may appear as future timestamps",
              }[delta]}
            </div>
          </div>
        </div>
      </Card>

      {/* ── Tenants ───────────────────────────────────────────────────────── */}
      <Card>
        <SectionLabel>{editIdx!==null ? "EDIT TENANT" : "ADD TENANT"}</SectionLabel>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:12 }}>
          <Inp label="Tenant ID" value={form.name} onChange={f("name")} placeholder="acme-prod" mono/>
          <Inp label="Display Label" value={form.label} onChange={f("label")} placeholder="Acme Production"/>
          <Inp label="Customer ID (UUID)" value={form.customerId} onChange={f("customerId")} placeholder="01234567-…" mono/>
          <Sel label="Region" value={form.region} onChange={f("region")} options={REGIONS}/>
          <div style={{ gridColumn:"1/-1" }}>
            <Inp label="Service Account Credentials JSON" value={form.credentials} onChange={f("credentials")}
              placeholder='{"type":"service_account","project_id":"...","private_key":"..."}' rows={3} mono/>
          </div>
        </div>

        <div style={{ marginTop:12 }}>
          <div style={{...mono, fontSize:9, color:"#3d5a7a", marginBottom:6, letterSpacing:"0.08em"}}>
            INGESTION LABELS
          </div>
          {(form.ingestionLabels||[]).length > 0 && (
            <div style={{ display:"flex", flexWrap:"wrap", gap:6, marginBottom:8 }}>
              {(form.ingestionLabels||[]).map((lbl,i)=>(
                <span key={i} style={{ display:"inline-flex", alignItems:"center", gap:6, padding:"3px 8px",
                  background:"#0a1628", border:"1px solid #0c1e38", borderRadius:5,
                  ...mono, fontSize:10, color:"#22d3ee" }}>
                  <span style={{ color:"#3d5a7a" }}>{lbl.key}</span>=<span>{lbl.value}</span>
                  <span onClick={()=>removeLabel(i)} style={{ cursor:"pointer", color:"#ef4444" }}>×</span>
                </span>
              ))}
            </div>
          )}
          <div style={{ display:"flex", gap:8 }}>
            <div style={{ flex:1 }}><Inp label="Key" value={labelKey} onChange={setLabelKey} mono placeholder="env"/></div>
            <div style={{ flex:1 }}><Inp label="Value" value={labelVal} onChange={setLabelVal} mono placeholder="demo"/></div>
            <Btn onClick={addLabel} sm style={{ marginBottom:1 }}>+ add</Btn>
          </div>
        </div>

        <div style={{ display:"flex", gap:8, marginTop:12 }}>
          <Btn onClick={save}>{editIdx!==null ? "update" : "+ add tenant"}</Btn>
          {editIdx!==null && <Btn variant="secondary" onClick={()=>{setEditIdx(null);setForm(empty);setLabelKey("");setLabelVal("");}}>cancel</Btn>}
        </div>
      </Card>

      {tenants.length === 0
        ? <div style={{ padding:"24px", textAlign:"center", ...sans, fontSize:12, color:"#1e3a5f",
            border:"1px dashed #0c1e38", borderRadius:8 }}>
            Add SecOps tenants — each becomes a matrix job in the generated workflow
          </div>
        : tenants.map((t,i)=>(
          <Card key={i} style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"12px 16px" }}>
            <div style={{ display:"flex", alignItems:"center", gap:12 }}>
              <Dot status="idle"/>
              <div>
                <div style={{...sans, fontSize:13, fontWeight:600, color:"#c8d8f0"}}>{t.label||t.name}</div>
                <div style={{...mono, fontSize:10, color:"#1e3a5f"}}>
                  {t.customerId ? t.customerId.slice(0,20)+"…" : "no id"} · {t.region}
                </div>
                {(t.ingestionLabels||[]).length > 0 && (
                  <div style={{ display:"flex", gap:4, marginTop:3, flexWrap:"wrap" }}>
                    {t.ingestionLabels.map((lbl,li)=>(
                      <span key={li} style={{...mono, fontSize:9, color:"#3d5a7a", background:"#040c1a",
                        border:"1px solid #0c1e38", borderRadius:3, padding:"1px 5px"}}>
                        {lbl.key}={lbl.value}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div style={{ display:"flex", gap:6, alignItems:"center" }}>
              <Pill label={t.region} color="#22d3ee" sm/>
              {t.credentials && <Pill label="creds ✓" color="#10b981" sm/>}
              {(t.ingestionLabels||[]).length > 0 && <Pill label={`${t.ingestionLabels.length} labels`} color="#8b5cf6" sm/>}
              <Btn variant="ghost" sm onClick={()=>{setForm({...t, ingestionLabels:t.ingestionLabels||[]});setEditIdx(i);}}>edit</Btn>
              <Btn variant="danger" sm onClick={()=>setTenants(t=>t.filter((_,j)=>j!==i))}>×</Btn>
            </div>
          </Card>
        ))
      }
    </div>
  );
}

// ─── ENTITY EXTRACTOR PREVIEW ─────────────────────────────────────────────────
// Shows what UDM entity NDJSON will be generated for a given flow
// Based on known Attack Range entities — in production, extract_entities.py
// parses the actual downloaded log files.

// ─── ENTITY EXTRACTOR PREVIEW ─────────────────────────────────────────────────
// Shows what UDM entity NDJSON will be generated for a given flow
// Based on known Attack Range entities — in production, extract_entities.py
// parses the actual downloaded log files.

function buildEntityNdjson(flowSteps) {
  const now = new Date().toISOString();
  const techniques = new Set(flowSteps.flatMap(s => s.mitre || [s.technique]));

  // Entity list removed — returns empty (entities extracted from logs at runtime)
  const relevant = [];

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

function DeployTab({ tenants, flowSteps, schedule, delta, ghToken, ghRepo, setGhRepo }) {
  const [view, setView]         = useState("push");
  const [pushState, setPushState] = useState("idle");
  const [pushLog, setPushLog]   = useState([]);
  const [pushRepo, setPushRepo] = useState(ghRepo || "");

  // status monitor state
  const [runs, setRuns]         = useState([]);
  const [loadingRuns, setLoadingRuns] = useState(false);
  const [runError, setRunError] = useState(null);
  const [expandedRun, setExpandedRun] = useState(null);
  const [triggering, setTriggering] = useState(false);
  const [lastFetch, setLastFetch] = useState(null);

  useEffect(() => { if(ghRepo) setPushRepo(ghRepo); }, [ghRepo]);

  const ready = tenants.length > 0 && flowSteps.length > 0;
  const repoValid = pushRepo && pushRepo.includes("/");

  // ── push logic ────────────────────────────────────────────────────────────
  async function getFileSha(repo, path, token) {
    try {
      const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" }
      });
      if (r.status === 404) return null;
      return (await r.json()).sha || null;
    } catch { return null; }
  }

  async function pushFile(repo, path, fileContent, token, log) {
    const sha = await getFileSha(repo, path, token);
    const body = { message: `chore: update ${path} via logstory-orchestrator`,
      content: btoa(unescape(encodeURIComponent(fileContent))), ...(sha ? { sha } : {}) };
    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const ok = r.status === 200 || r.status === 201;
    log(ok ? `✓  ${path}` : `✗  ${path} (HTTP ${r.status})`);
    if (!ok) { const e = await r.json(); log(`   └─ ${e.message}`); throw new Error(e.message); }
  }

  async function handlePush() {
    if (!ghToken) { setPushLog(["✗  No GitHub token — add it in Config"]); setPushState("error"); return; }
    if (!repoValid) { setPushLog(["✗  Enter a valid repo (owner/repo)"]); setPushState("error"); return; }
    if (!ready) { setPushLog(["✗  Add tenants and an attack flow first"]); setPushState("error"); return; }
    setPushState("pushing"); setPushLog([`Pushing to ${pushRepo} …`]);
    if (setGhRepo) setGhRepo(pushRepo);
    const log = msg => setPushLog(p => [...p, msg]);
    try {
      log(""); log("── workflow ─────────────────────────────────────────────");
      await pushFile(pushRepo, ".github/workflows/logstory-replay.yml", workflow, ghToken, log);
      log(""); log("── scripts ──────────────────────────────────────────────");
      await pushFile(pushRepo, "scripts/replay_dataset.py", replayScript, ghToken, log);
      await pushFile(pushRepo, "scripts/extract_entities.py", entityExtractStandalone, ghToken, log);
      await pushFile(pushRepo, "requirements.txt", "logstory\n", ghToken, log);
      log(""); log("── README ───────────────────────────────────────────────");
      const readme = `# demo-data\n\nLogstory attack data replay runner.\nGenerated by [logstory-orchestrator](https://keith-manville.github.io/logstory-orchestrator/).\n\n## Required secrets\n\n\`\`\`bash\n${secretCmds}\n\`\`\`\n`;
      await pushFile(pushRepo, "README.md", readme, ghToken, log);
      log(""); log("✅  All done — trigger a run below.");
      setPushState("done");
      fetchRuns();
    } catch(e) {
      log(""); log("❌  Push failed. Check token has repo + workflow scopes.");
      setPushState("error");
    }
  }

  // ── run monitor logic ─────────────────────────────────────────────────────
  const fetchRuns = async () => {
    if (!repoValid) return;
    setLoadingRuns(true); setRunError(null);
    try {
      const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
      if (ghToken) headers.Authorization = `Bearer ${ghToken}`;
      const res = await fetch(
        `https://api.github.com/repos/${pushRepo}/actions/workflows/logstory-replay.yml/runs?per_page=20`,
        { headers }
      );
      if (!res.ok) throw new Error(`GitHub API ${res.status}`);
      const data = await res.json();
      setRuns((data.workflow_runs || []).map(r => ({
        id: String(r.id), runNumber: r.run_number,
        status: r.conclusion === "success" ? "success" : r.conclusion === "failure" ? "failed"
              : r.status === "in_progress" ? "running" : r.conclusion || r.status || "unknown",
        startedAt: r.created_at, actor: r.actor?.login, branch: r.head_branch,
        trigger: r.event === "schedule" ? "schedule" : r.event === "workflow_dispatch" ? "manual" : r.event,
        duration: r.updated_at && r.created_at ? Math.round((new Date(r.updated_at)-new Date(r.created_at))/1000) : 0,
        url: r.html_url,
      })));
      setLastFetch(new Date());
    } catch(e) { setRunError(e.message); }
    finally { setLoadingRuns(false); }
  };

  const triggerRun = async () => {
    if (!repoValid || !ghToken) return;
    setTriggering(true);
    try {
      const res = await fetch(
        `https://api.github.com/repos/${pushRepo}/actions/workflows/logstory-replay.yml/dispatches`,
        { method:"POST", headers:{ Authorization:`Bearer ${ghToken}`, Accept:"application/vnd.github+json",
            "Content-Type":"application/json", "X-GitHub-Api-Version":"2022-11-28" },
          body: JSON.stringify({ ref:"main" }) }
      );
      if (!res.ok) throw new Error(`Dispatch failed: ${res.status}`);
      setTimeout(fetchRuns, 3000);
    } catch(e) { setRunError(e.message); }
    finally { setTriggering(false); }
  };

  useEffect(() => { if (repoValid) fetchRuns(); }, [pushRepo, ghToken]);

  const fmt = iso => {
    const d = new Date(iso);
    return d.toLocaleDateString("en-US",{month:"short",day:"numeric"})+" "+d.toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"});
  };

  const stats = {
    total: runs.length,
    success: runs.filter(j=>j.status==="success").length,
    failed: runs.filter(j=>j.status==="failed").length,
    running: runs.filter(j=>j.status==="running").length,
  };
  const successRate = runs.length > 0 ? Math.round(stats.success/runs.length*100) : 0;

  // ── workflow/script strings (inherited from GenerateTab logic) ────────────
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

  const workflow = !ready ? "# Add tenants and build an attack flow first" : `name: Logstory Attack Data Replay
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
${tenants.map(t=>{
  const labelStr = (t.ingestionLabels||[]).length > 0
    ? "\n            ingestion_labels: \"" + t.ingestionLabels.map(l=>`${l.key}=${l.value}`).join(",") + "\""
    : "";
  return `          - tenant_id: ${t.name.toUpperCase().replace(/[^A-Z0-9]/g,"_")}
            tenant_display: "${t.label||t.name}"
            region: ${t.region}${labelStr}`;
}).join("\n")}

    steps:
      - name: Checkout this repo
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
          cache-dependency-path: requirements.txt

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
  return `      # ── Step ${i+1}: ${s.name} [${s.technique}]
      - name: "Download ${s.name}"
        run: |
          mkdir -p /tmp/attack_data_cache
          CACHE_FILE="/tmp/attack_data_cache/${fname}"
          if [ ! -f "$CACHE_FILE" ]; then
            curl -fsSL --retry 3 --retry-delay 5 \\
              "${s.mediaUrl}" -o "$CACHE_FILE"
          fi

      - name: "Pass 1 — Events: ${s.name}"
        run: |
          python scripts/replay_dataset.py \\
            --log-file /tmp/attack_data_cache/${fname} \\
            --log-type "${safeLt}" \\
            --credentials /tmp/secops_creds.json \\
            --customer-id "\${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}" \\
            --region "\${{ matrix.region }}"\${{ matrix.ingestion_labels && format(' --labels {0}', matrix.ingestion_labels) || '' }} \\
            --timestamp-delta "${delta}"

      - name: "Pass 2 — Entities: ${s.name}"
        if: \${{ github.event.inputs.skip_entities != 'true' }}
        run: |
          python scripts/replay_dataset.py \\
            --log-file /tmp/attack_data_cache/${fname} \\
            --log-type "${safeLt}" \\
            --credentials /tmp/secops_creds.json \\
            --customer-id "\${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}" \\
            --region "\${{ matrix.region }}"\${{ matrix.ingestion_labels && format(' --labels {0}', matrix.ingestion_labels) || '' }} \\
            --timestamp-delta "${delta}" \\
            --entities`;
}).join("\n\n")}

      - name: Cleanup credentials
        if: always()
        run: rm -f /tmp/secops_creds.json
`;

  const replayScript = `#!/usr/bin/env python3
"""scripts/replay_dataset.py — Logstory wrapper for Splunk Attack Data"""
import argparse, os, shutil, subprocess, sys, tempfile
from pathlib import Path

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log-file",        required=True)
    p.add_argument("--log-type",        required=True)
    p.add_argument("--credentials",     required=True)
    p.add_argument("--customer-id",     required=True)
    p.add_argument("--region",          default="US")
    p.add_argument("--timestamp-delta", default="1d")
    p.add_argument("--labels",          default="")
    p.add_argument("--entities",        action="store_true")
    args = p.parse_args()

    log_file = Path(args.log_file)
    if not log_file.exists():
        sys.exit(f"[error] Log file not found: {log_file}")

    with tempfile.TemporaryDirectory() as tmp:
        usecase_root = Path(tmp) / "SPLUNK_ATTACK_DATA"
        events_dir   = usecase_root / "EVENTS"
        events_dir.mkdir(parents=True)
        shutil.copy(log_file, events_dir / f"{args.log_type}.log")

        if args.entities:
            from extract_entities import extract_entities
            ndjson = extract_entities(log_file, args.log_type)
            if ndjson:
                entity_dir = usecase_root / "ENTITIES"
                entity_dir.mkdir(parents=True)
                (entity_dir / f"{args.log_type}.ndjson").write_text(ndjson)

        env = { **os.environ,
            "LOGSTORY_CUSTOMER_ID":      args.customer_id,
            "LOGSTORY_CREDENTIALS_PATH": args.credentials,
            "LOGSTORY_REGION":           args.region,
            "LOGSTORY_USECASES_BUCKETS": f"file://{tmp}",
        }
        cmd = ["logstory","replay","usecase","SPLUNK_ATTACK_DATA",
               f"--timestamp-delta={args.timestamp_delta}"]
        if args.entities: cmd.append("--entities")
        sys.exit(subprocess.run(cmd, env=env).returncode)

if __name__ == "__main__":
    main()
`;

  const entityExtractStandalone = `#!/usr/bin/env python3
"""scripts/extract_entities.py — extract UDM entity NDJSON from Splunk Attack Data logs"""
import json, re, sys
from pathlib import Path
from datetime import datetime, timezone

def extract_entities(log_file: Path, log_type: str) -> str:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    entities = {}

    def asset(hostname=None, ip=None):
        if hostname:
            k = ("h", hostname.lower())
            if k not in entities:
                entities[k] = {"entity":{"asset":{"hostname":hostname,"attribute":{"labels":[{"key":"source","value":"splunk_attack_data"}]}}},
                    "metadata":{"entity_type":"ASSET","interval":{"start_time":now,"end_time":now},"source_type":"DERIVED_CONTEXT","collected_timestamp":now,"product_name":"splunk/attack_data","vendor_name":"Splunk"}}
        if ip and not ip.startswith(("0.","127.","::1","-")):
            k = ("ip", ip)
            if k not in entities:
                entities[k] = {"entity":{"asset":{"ip":[ip],"attribute":{"labels":[{"key":"source","value":"splunk_attack_data"}]}}},
                    "metadata":{"entity_type":"ASSET","interval":{"start_time":now,"end_time":now},"source_type":"DERIVED_CONTEXT","collected_timestamp":now,"product_name":"splunk/attack_data","vendor_name":"Splunk"}}

    def user(username, domain=""):
        if not username or username in ("-","SYSTEM","LOCAL SERVICE","NETWORK SERVICE"): return
        k = ("u", username.lower())
        if k not in entities:
            entities[k] = {"entity":{"user":{"user_display_name":username,"attribute":{"labels":[{"key":"domain","value":domain},{"key":"source","value":"splunk_attack_data"}]}}},
                "metadata":{"entity_type":"USER","interval":{"start_time":now,"end_time":now},"source_type":"DERIVED_CONTEXT","collected_timestamp":now,"product_name":"splunk/attack_data","vendor_name":"Splunk"}}

    raw = log_file.read_text(errors="replace")
    if log_type in ("WINDOWS_SYSMON","WINEVTLOG","POWERSHELL"):
        for m in re.finditer(r"<Computer>([^<]+)</Computer>", raw): asset(hostname=m.group(1).strip())
        for m in re.finditer(r"<Data Name=['\"]SubjectUserName['\"]>([^<]+)</Data>", raw): user(m.group(1).strip())
        for m in re.finditer(r"<Data Name=['\"]TargetUserName['\"]>([^<]+)</Data>", raw): user(m.group(1).strip())
        for m in re.finditer(r"<Data Name=['\"]IpAddress['\"]>([^<]+)</Data>", raw):
            ip = m.group(1).strip().lstrip("-")
            if re.match(r"\d+\.\d+\.\d+\.\d+", ip): asset(ip=ip)
    elif log_type == "CS_EDR":
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                if h := obj.get("ComputerName") or obj.get("HostName"): asset(hostname=h)
                if u := obj.get("UserName") or obj.get("userPrincipalName"): user(u)
            except: pass
    elif log_type in ("BRO_JSON","SURICATA_EVE_JSON"):
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                for f in ("id.orig_h","src_ip","id.resp_h","dest_ip"):
                    if ip := obj.get(f): asset(ip=ip)
            except: pass
    return "\n".join(json.dumps(v) for v in entities.values())

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--log-file", required=True)
    p.add_argument("--log-type", required=True)
    p.add_argument("--out",      required=True)
    a = p.parse_args()
    ndjson = extract_entities(Path(a.log_file), a.log_type)
    count = len(ndjson.splitlines()) if ndjson else 0
    if not count: print("[warn] No entities extracted"); sys.exit(0)
    Path(a.out).write_text(ndjson)
    print(f"[ok] {count} entity records → {a.out}")
`;

  const DEPLOY_FILES = [
    ".github/workflows/logstory-replay.yml",
    "scripts/replay_dataset.py",
    "scripts/extract_entities.py",
    "requirements.txt",
    "README.md",
  ];

  const codeViews = [
    ["workflow", ".github/workflows/logstory-replay.yml", workflow],
    ["replay",   "scripts/replay_dataset.py",             replayScript],
    ["extract",  "scripts/extract_entities.py",           entityExtractStandalone],
    ["secrets",  "gh secret commands",                    secretCmds],
  ];

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>

      {!ready && (
        <div style={{ padding:"12px 16px", background:"#1a0f00", border:"1px solid #f59e0b28",
          borderRadius:8, ...mono, fontSize:11, color:"#f59e0b" }}>
          ⚠ {!tenants.length && "Add at least one tenant in Config. "}
          {!flowSteps.length && "Build an attack flow first."}
        </div>
      )}

      {/* ── Push panel ──────────────────────────────────────────────────── */}
      <Card style={{ padding:"16px 20px" }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}>
          <div>
            <SectionLabel>PUSH TO REPO</SectionLabel>
            <div style={{...sans, fontSize:11, color:"#3d5a7a", marginTop:4 }}>
              Commits generated workflow + scripts to your runner repo. Token needs
              <code style={{...mono, fontSize:10, color:"#22d3ee", margin:"0 4px"}}>repo</code>+
              <code style={{...mono, fontSize:10, color:"#22d3ee"}}>workflow</code> scopes.
            </div>
          </div>
          <div style={{ display:"flex", gap:8 }}>
            <button onClick={handlePush} disabled={pushState==="pushing"}
              style={{ padding:"8px 18px", borderRadius:6, border:"none", cursor:"pointer",
                background: pushState==="pushing"?"#0c1e38": pushState==="done"?"#065f46": pushState==="error"?"#7f1d1d":"#1d4ed8",
                color: pushState==="pushing"?"#3d5a7a":"#e2f0ff",
                ...mono, fontSize:11, fontWeight:700,
                opacity: pushState==="pushing"?0.7:1 }}>
              {pushState==="pushing"?"⏳ Pushing…": pushState==="done"?"✅ Pushed": pushState==="error"?"❌ Retry":"⬆ Push to Repo"}
            </button>
            {pushState !== "idle" && (
              <button onClick={()=>{setPushState("idle");setPushLog([]);}}
                style={{ padding:"8px 12px", borderRadius:6, border:"1px solid #0c1e38",
                  background:"transparent", color:"#3d5a7a", ...mono, fontSize:10, cursor:"pointer" }}>reset</button>
            )}
          </div>
        </div>

        <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:12 }}>
          <div style={{ flex:1 }}>
            <input value={pushRepo} onChange={e=>setPushRepo(e.target.value)}
              placeholder="owner/repo  e.g. keith-manville/demo-data"
              style={{ width:"100%", background:"#030a17", border:"1px solid #0c1e38",
                borderRadius:6, padding:"7px 10px", color:"#c8d8f0", ...mono, fontSize:11,
                outline:"none", boxSizing:"border-box" }}/>
          </div>
        </div>

        <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom: pushLog.length?12:0 }}>
          {DEPLOY_FILES.map(f=>(
            <div key={f} style={{ padding:"3px 8px", borderRadius:4, background:"#060f20",
              border:"1px solid #0c1e38", ...mono, fontSize:9,
              color: pushState==="done"?"#10b981": pushState==="pushing"?"#f59e0b":"#3d5a7a" }}>
              {pushState==="done"?"✓ ": pushState==="pushing"?"⏳ ":"○ "}{f}
            </div>
          ))}
        </div>

        {pushLog.length > 0 && (
          <div style={{ padding:"10px 12px", background:"#030a17", border:"1px solid #0c1e38",
            borderRadius:6, maxHeight:160, overflowY:"auto" }}>
            {pushLog.map((line,i)=>(
              <div key={i} style={{...mono, fontSize:10, lineHeight:1.7,
                color: line.startsWith("✓")?"#10b981": line.startsWith("✗")||line.startsWith("❌")?"#ef4444":
                       line.startsWith("✅")?"#10b981": line.startsWith("──")?"#22d3ee":"#3d5a7a"}}>
                {line||" "}
              </div>
            ))}
          </div>
        )}

        {!ghToken && (
          <div style={{ marginTop:10, padding:"8px 12px", background:"#1a0f00",
            border:"1px solid #f59e0b28", borderRadius:6, ...mono, fontSize:10, color:"#f59e0b" }}>
            ⚠ No GitHub token — add it in the Config tab.
          </div>
        )}
      </Card>

      {/* ── Run monitor ─────────────────────────────────────────────────── */}
      <Card>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
          <div>
            <SectionLabel>RUN MONITOR</SectionLabel>
            {lastFetch && <span style={{...mono, fontSize:9, color:"#1e3a5f", marginLeft:8 }}>fetched {fmt(lastFetch)}</span>}
          </div>
          <div style={{ display:"flex", gap:8 }}>
            <Btn onClick={fetchRuns} disabled={loadingRuns} variant="secondary" sm>
              {loadingRuns?"⟳ loading…":"↻ refresh"}
            </Btn>
            <Btn onClick={triggerRun} disabled={triggering||!ghToken} sm>
              {triggering?"⟳ dispatching…":"▶ trigger run"}
            </Btn>
          </div>
        </div>

        {runError && (
          <div style={{ padding:"8px 12px", background:"#1a0808", border:"1px solid #ef444330",
            borderRadius:6, ...mono, fontSize:10, color:"#ef4444", marginBottom:10 }}>⚠ {runError}</div>
        )}

        {runs.length > 0 && (
          <>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:8, marginBottom:12 }}>
              {[{l:"Total",v:stats.total,c:"#22d3ee"},{l:"Success",v:stats.success,c:"#10b981"},
                {l:"Failed",v:stats.failed,c:"#ef4444"},{l:"Rate",v:`${successRate}%`,c:successRate>80?"#10b981":successRate>50?"#f59e0b":"#ef4444"}
              ].map(s=>(
                <div key={s.l} style={{ textAlign:"center", padding:"10px 8px", background:"#030a17",
                  border:"1px solid #0c1e38", borderRadius:6 }}>
                  <div style={{...sans, fontSize:20, fontWeight:800, color:s.c}}>{s.v}</div>
                  <div style={{...mono, fontSize:8, color:"#1e3a5f", marginTop:2}}>{s.l.toUpperCase()}</div>
                </div>
              ))}
            </div>
            <div style={{ height:4, background:"#0c1e38", borderRadius:2, overflow:"hidden", marginBottom:12 }}>
              <div style={{ height:"100%", width:`${successRate}%`, transition:"width .6s",
                background:successRate>80?"#10b981":successRate>50?"#f59e0b":"#ef4444", borderRadius:2 }}/>
            </div>
          </>
        )}

        {loadingRuns && runs.length===0 && (
          <div style={{ padding:"20px 0", textAlign:"center", ...mono, fontSize:11, color:"#1e3a5f" }}>
            <Spinner/><span style={{ marginLeft:10 }}>Loading runs from GitHub…</span>
          </div>
        )}
        {!loadingRuns && runs.length===0 && !runError && (
          <div style={{ padding:"20px 0", textAlign:"center", ...mono, fontSize:11, color:"#1e3a5f" }}>
            No runs found for <code style={{ color:"#22d3ee" }}>logstory-replay.yml</code> in {pushRepo||ghRepo}
          </div>
        )}

        <div style={{ display:"flex", flexDirection:"column", gap:3 }}>
          {runs.map(j=>(
            <div key={j.id}>
              <div onClick={()=>setExpandedRun(expandedRun===j.id?null:j.id)}
                style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
                  padding:"9px 12px", borderRadius:6, cursor:"pointer",
                  background:expandedRun===j.id?"#060f20":"#040c1a",
                  border:`1px solid ${j.status==="failed"?"#ef444330":j.status==="running"?"#22d3ee30":"#0c1e38"}`,
                  transition:"all .15s" }}>
                <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                  <Dot status={j.status}/>
                  <div>
                    <span style={{...mono, fontSize:11, color:"#c8d8f0", fontWeight:600}}>run #{j.runNumber}</span>
                    {j.actor && <span style={{...mono, fontSize:10, color:"#3d5a7a"}}> · {j.actor}</span>}
                    <div style={{...mono, fontSize:9, color:"#1e3a5f"}}>{fmt(j.startedAt)}</div>
                  </div>
                </div>
                <div style={{ display:"flex", gap:6, alignItems:"center" }}>
                  <Pill label={j.trigger} color="#3d5a7a" sm/>
                  {j.branch && <Pill label={j.branch} color="#22d3ee" sm/>}
                  {j.duration>0 && <span style={{...mono, fontSize:9, color:"#1e3a5f"}}>{j.duration}s</span>}
                  <Pill label={j.status}
                    color={j.status==="success"?"#10b981":j.status==="failed"?"#ef4444":j.status==="running"?"#22d3ee":"#475569"} sm/>
                  <span style={{ color:"#1e3a5f", fontSize:10 }}>{expandedRun===j.id?"▲":"▼"}</span>
                </div>
              </div>
              {expandedRun===j.id && (
                <div style={{ padding:"10px 14px", background:"#030a17",
                  borderLeft:"3px solid #0c1e38", marginBottom:2, animation:"slideUp .15s" }}>
                  <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:8 }}>
                    {[["Run #",j.runNumber],["Trigger",j.trigger],["Branch",j.branch||"—"],["Actor",j.actor||"—"],
                      ["Started",fmt(j.startedAt)],["Status",j.status],["Duration",j.duration>0?`${j.duration}s`:"—"],["ID",j.id]
                    ].map(([k,v])=>(
                      <div key={k}>
                        <div style={{...mono, fontSize:8, color:"#1e3a5f", marginBottom:2}}>{k.toUpperCase()}</div>
                        <div style={{...mono, fontSize:10, color:"#6a8aaa"}}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                  {j.url && <a href={j.url} target="_blank" rel="noopener noreferrer"
                    style={{...mono, fontSize:10, color:"#22d3ee", textDecoration:"none", display:"block", marginTop:8}}>
                    → view on GitHub ↗</a>}
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* ── Generated code viewer ────────────────────────────────────────── */}
      <Card>
        <SectionLabel>GENERATED FILES</SectionLabel>
        <div style={{ display:"flex", gap:2, background:"#030a17", borderRadius:6, padding:3,
          border:"1px solid #0c1e38", marginBottom:12, flexWrap:"wrap" }}>
          {codeViews.map(([k,l])=>(
            <button key={k} onClick={()=>setView(k)}
              style={{ flex:1, minWidth:100, padding:"6px 4px", borderRadius:5,
                background:view===k?"#060f20":"transparent", border:"none",
                color:view===k?"#22d3ee":"#3d5a7a",
                ...mono, fontSize:9, cursor:"pointer", whiteSpace:"nowrap" }}>{l}</button>
          ))}
        </div>
        {codeViews.map(([k,,code])=> view===k &&
          <CodeBlock key={k} code={code} maxH="480px" filename={codeViews.find(c=>c[0]===k)[1]}/>
        )}
      </Card>
    </div>
  );
}

// ─── THREAT INTEL TAB ────────────────────────────────────────────────────────

// ─── THREAT INTEL TAB ────────────────────────────────────────────────────────
// GTI API (VirusTotal Enterprise) — uses /api/v3 endpoints
// Actors:    GET /api/v3/threat_actors?filter=name:{query}
// Campaigns: GET /api/v3/collections?filter=name:{query}
// TTPs:      Embedded in relationships → attack_techniques on actor/collection objects


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



const TABS = [
  {id:"flow",   icon:"⛓", label:"Attack Flow"},
  {id:"config", icon:"⚙️", label:"Config"},
  {id:"deploy", icon:"🚀", label:"Deploy"},
];

const PAGE_META = {
  flow:   ["Attack Flow",  "Browse Splunk attack_data techniques, build a replay sequence, export as JSON"],
  config: ["Config",       "Tenants · schedule · timestamp delta · GitHub token and repo"],
  deploy: ["Deploy",       "Push workflow + scripts to GitHub, trigger runs, monitor status"],
};

export default function App() {
  const [tab, setTab]             = useState("flow");
  const [flowSteps, setFlowSteps] = useState([]);
  const [tenants, setTenants]     = useState([]);
  const [schedule, setSchedule]   = useState("1 0 * * *");
  const [delta, setDelta]         = useState("1d");
  const [ghToken, setGhToken]     = useState("");
  const [ghRepo, setGhRepo]       = useState("keith-manville/demo-data");

  const badges = {
    flow:   flowSteps.length,
    config: tenants.length,
    deploy: 0,
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

        {tab==="flow"   && <FlowBuilder flowSteps={flowSteps} setFlowSteps={setFlowSteps} ghToken={ghToken} setGhToken={setGhToken}/>}
        {tab==="config" && <ConfigTab tenants={tenants} setTenants={setTenants} schedule={schedule} setSchedule={setSchedule} delta={delta} setDelta={setDelta} ghToken={ghToken} setGhToken={setGhToken} ghRepo={ghRepo} setGhRepo={setGhRepo}/>}
        {tab==="deploy" && <DeployTab tenants={tenants} flowSteps={flowSteps} schedule={schedule} delta={delta} ghToken={ghToken} ghRepo={ghRepo} setGhRepo={setGhRepo}/>}
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
