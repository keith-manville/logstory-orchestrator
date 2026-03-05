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
  {l:"Run once (manual only)", c:"once"},
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

  const res = await fetch(`${API_BASE}/git/trees/master?recursive=1`, { headers });
  if (!res.ok) throw new Error(`Tree API ${res.status}`);
  const data = await res.json();

  const byTechnique    = {};
  const byLogType      = {};
  const tacticLogTypes = {};

  // Direct filename-stem → SecOps log type mappings
  // Covers the cases ST_MAP can't reach via sourcetype lookup alone
  const directMap = {
    crowdstrike: "CS_EDR", falcon: "CS_EDR", cs_edr: "CS_EDR",
    sysmon: "WINDOWS_SYSMON", winevtlog: "WINEVTLOG", wineventlog: "WINEVTLOG",
    windows_security: "WINEVTLOG", windows_system: "WINEVTLOG",
    powershell: "POWERSHELL", linux_sysmon: "LINUX_SYSMON",
    bro: "BRO_JSON", zeek: "BRO_JSON", suricata: "SURICATA_EVE_JSON",
    osquery: "OSQUERY", palo_alto: "PAN_FIREWALL", paloalto: "PAN_FIREWALL",
    pan: "PAN_FIREWALL", office365: "OFFICE_365", o365: "OFFICE_365",
    aws: "AWS_CLOUDTRAIL", cloudtrail: "AWS_CLOUDTRAIL",
    gcp: "GCP_CLOUDAUDIT", azure: "AZURE_AD", azuread: "AZURE_AD",
    okta: "OKTA", github: "GITHUB", gsuite: "GSUITE",
    cisco: "CISCO_ASA_FIREWALL",
  };

  function filenameToLt(path) {
    const raw = path.split("/").pop().replace(/\.(log|json|ndjson|csv|txt|gz)$/i, "").toLowerCase();
    const stem = raw.replace(/[\-\.\s]+/g, "_");

    // 1. Exact match on full stem
    if (directMap[stem]) return directMap[stem];
    // 2. Exact match on SECOPS_LOG_TYPES (file literally named CS_EDR.log)
    if (SECOPS_LOG_TYPES.has(stem.toUpperCase())) return stem.toUpperCase();
    // 3. Partial match — does stem contain a known keyword?
    for (const [k, v] of Object.entries(directMap)) {
      if (stem.includes(k)) return v;
    }
    // 4. Check each _ segment against SECOPS_LOG_TYPES
    for (const seg of stem.split("_").filter(s => s.length > 2)) {
      if (SECOPS_LOG_TYPES.has(seg.toUpperCase())) return seg.toUpperCase();
      if (directMap[seg]) return directMap[seg];
    }
    return null;
  }

  const techRe = /^datasets\/attack_techniques\/(T\d+(?:\.\d+)?)\//;

  for (const item of data.tree) {
    if (item.type !== "blob") continue;
    const m = item.path.match(techRe);
    if (!m) continue;
    const tech = m[1];

    const isData = /\.(log|json|ndjson|csv|txt|gz)$/i.test(item.path);
    const isYml  = item.path.endsWith(".yml");
    if (!isData && !isYml) continue;

    const lt = filenameToLt(item.path);
    if (!lt) continue;

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

// ─── KILL CHAIN CANVAS ────────────────────────────────────────────────────────

const TACTIC_ORDER = [
  "Reconnaissance","Resource Development","Initial Access","Execution",
  "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
  "Discovery","Lateral Movement","Collection","Command and Control",
  "Exfiltration","Impact",
];

const TACTIC_SHORT = {
  "Reconnaissance":"RECON","Resource Development":"RESOURCE DEV",
  "Initial Access":"INIT ACCESS","Execution":"EXEC",
  "Persistence":"PERSIST","Privilege Escalation":"PRIV ESC",
  "Defense Evasion":"DEF EVASION","Credential Access":"CRED ACCESS",
  "Discovery":"DISCOVERY","Lateral Movement":"LAT MOVE",
  "Collection":"COLLECT","Command and Control":"C2",
  "Exfiltration":"EXFIL","Impact":"IMPACT",
};

// ── Small TTP node on the canvas ──────────────────────────────────────────────
function ChainNode({ step, index, total, onRemove, onMoveLeft, onMoveRight, onSwapDataset, repoIndex }) {
  const [expanded, setExpanded] = useState(false);
  const [swapping, setSwapping]   = useState(false);
  const [altDatasets, setAltDatasets] = useState([]);
  const tactic = getTactic(step.technique);
  const color  = tacticColor(step.technique);

  async function loadAlts() {
    setSwapping(true);
    try {
      const datasets = await fetchYamlsForTechnique(step.technique, "");
      setAltDatasets(datasets);
    } catch(e) { setAltDatasets([]); }
    setSwapping(false);
  }

  return (
    <div style={{
      position:"relative",
      background:"#060f20",
      border:`1px solid ${expanded ? color + "60" : "#0e1e35"}`,
      borderRadius:10,
      padding:"12px 14px",
      minWidth:200, maxWidth:240,
      flexShrink:0,
      boxShadow: expanded ? `0 0 20px ${color}18` : "none",
      transition:"all .2s",
      cursor:"default",
    }}>
      {/* tactic pill */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
        <span style={{ ...mono, fontSize:8, color, letterSpacing:"0.1em", fontWeight:700,
          background:`${color}15`, border:`1px solid ${color}30`,
          padding:"2px 7px", borderRadius:3 }}>{TACTIC_SHORT[tactic] || tactic}</span>
        <button onClick={()=>onRemove(index)}
          style={{ background:"none", border:"none", color:"#1e3a5f", cursor:"pointer",
            fontSize:12, padding:"0 2px", lineHeight:1 }}
          onMouseEnter={e=>e.target.style.color="#ef4444"}
          onMouseLeave={e=>e.target.style.color="#1e3a5f"}>×</button>
      </div>

      {/* technique ID + name */}
      <div style={{ ...mono, fontSize:11, color:"#e2f0ff", fontWeight:700, marginBottom:3 }}>
        {step.technique}
      </div>
      <div style={{ fontSize:11, color:"#4a6a8a", marginBottom:8, lineHeight:1.3,
        whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
        {step.name || step.desc?.substring(0,45) || "—"}
      </div>

      {/* log type badge */}
      <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:8 }}>
        <span style={{ ...mono, fontSize:9, color: step.ltColor || "#475569",
          background: `${step.ltColor || "#475569"}15`,
          border:`1px solid ${step.ltColor || "#475569"}30`,
          padding:"1px 6px", borderRadius:3 }}>{step.lt}</span>
      </div>

      {/* dataset name (truncated) */}
      <div style={{ ...mono, fontSize:8, color:"#1e3a5f", lineHeight:1.4,
        whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis", marginBottom:8 }}>
        {step.id?.split("/").slice(1).join("/")}
      </div>

      {/* actions row */}
      <div style={{ display:"flex", gap:4, alignItems:"center" }}>
        <button onClick={()=>onMoveLeft(index)} disabled={index===0}
          style={{ ...mono, fontSize:9, padding:"3px 6px", background:"#030a17",
            border:"1px solid #0e1e35", borderRadius:4, color: index===0?"#0e1e35":"#3d5a7a",
            cursor: index===0?"not-allowed":"pointer" }}>◀</button>
        <button onClick={()=>onMoveRight(index)} disabled={index===total-1}
          style={{ ...mono, fontSize:9, padding:"3px 6px", background:"#030a17",
            border:"1px solid #0e1e35", borderRadius:4, color: index===total-1?"#0e1e35":"#3d5a7a",
            cursor: index===total-1?"not-allowed":"pointer" }}>▶</button>
        <button onClick={()=>{ setExpanded(e=>!e); if(!expanded && altDatasets.length===0) loadAlts(); }}
          style={{ ...mono, fontSize:8, padding:"3px 8px", background: expanded?"#0c1e3840":"#030a17",
            border:`1px solid ${expanded?"#22d3ee30":"#0e1e35"}`, borderRadius:4,
            color: expanded?"#22d3ee":"#3d5a7a", cursor:"pointer", flex:1 }}>
          {swapping ? "…" : expanded ? "▲ close" : "⇄ swap"}
        </button>
      </div>

      {/* swap panel */}
      {expanded && (
        <div style={{ marginTop:10, borderTop:"1px solid #0e1e35", paddingTop:8, maxHeight:180, overflowY:"auto" }}>
          {altDatasets.length === 0 && !swapping && (
            <div style={{ ...mono, fontSize:8, color:"#1e3a5f" }}>No alternate datasets found</div>
          )}
          {altDatasets.map((ds, i) => (
            <div key={i} onClick={() => { onSwapDataset(index, ds); setExpanded(false); }}
              style={{ padding:"6px 8px", borderRadius:5, marginBottom:3, cursor:"pointer",
                background: ds.id===step.id ? "#0c1e38" : "#030a17",
                border:`1px solid ${ds.id===step.id ? "#22d3ee30" : "#0e1e35"}` }}
              onMouseEnter={e=>e.currentTarget.style.borderColor="#22d3ee30"}
              onMouseLeave={e=>e.currentTarget.style.borderColor= ds.id===step.id?"#22d3ee30":"#0e1e35"}>
              <div style={{ ...mono, fontSize:8, color: ds.ltColor || "#475569",
                marginBottom:2 }}>{ds.lt}</div>
              <div style={{ ...mono, fontSize:8, color:"#4a6a8a", lineHeight:1.3 }}>
                {ds.id?.split("/").slice(1).join("/")}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* connector arrow (not last) */}
      {index < total - 1 && (
        <div style={{ position:"absolute", right:-18, top:"50%", transform:"translateY(-50%)",
          color:"#0e1e35", fontSize:14, zIndex:2 }}>→</div>
      )}
    </div>
  );
}

// ── Dataset picker panel (from browse) ───────────────────────────────────────
function DatasetBrowser({ ghToken, onAdd, repoIndex }) {
  const [folders, setFolders]       = useState([]);
  const [loading, setLoading]       = useState(false);
  const [search, setSearch]         = useState("");
  const [expanded, setExpanded]     = useState(null);
  const [techDatasets, setTechDatasets] = useState({});
  const [loadingTech, setLoadingTech]   = useState(null);

  useEffect(() => {
    setLoading(true);
    fetchTechniqueFolders(ghToken)
      .then(f => setFolders(f))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [ghToken]);

  async function handleExpand(tech) {
    if (expanded === tech) { setExpanded(null); return; }
    setExpanded(tech);
    if (!techDatasets[tech]) {
      setLoadingTech(tech);
      try {
        const ds = await fetchYamlsForTechnique(tech, ghToken);
        setTechDatasets(p => ({...p, [tech]: ds}));
      } catch {}
      setLoadingTech(null);
    }
  }

  const filtered = folders.filter(f => f.toLowerCase().includes(search.toLowerCase()));

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100%" }}>
      <div style={{ padding:"0 0 8px 0" }}>
        <input value={search} onChange={e=>setSearch(e.target.value)}
          placeholder="Filter techniques…"
          style={{ width:"100%", background:"#030a17", border:"1px solid #0c1e38",
            borderRadius:6, padding:"7px 10px", color:"#c8d8f0", ...mono, fontSize:10,
            outline:"none" }}
          onFocus={e=>e.target.style.borderColor="#22d3ee44"}
          onBlur={e=>e.target.style.borderColor="#0c1e38"}/>
      </div>
      <div style={{ flex:1, overflowY:"auto" }}>
        {loading && [1,2,3,4,5].map(i=><SkeletonRow key={i}/>)}
        {filtered.map(tech => {
          const tactic = getTactic(tech);
          const color  = tacticColor(tech);
          const isOpen = expanded === tech;
          const datasets = techDatasets[tech] || [];
          return (
            <div key={tech} style={{ marginBottom:3 }}>
              <div onClick={()=>handleExpand(tech)}
                style={{ display:"flex", alignItems:"center", gap:8, padding:"7px 10px",
                  background: isOpen ? "#060f20" : "#030a17",
                  border:`1px solid ${isOpen ? color+"40":"#0c1e38"}`,
                  borderRadius:6, cursor:"pointer", transition:"all .15s" }}
                onMouseEnter={e=>e.currentTarget.style.borderColor= color+"40"}
                onMouseLeave={e=>e.currentTarget.style.borderColor= isOpen?color+"40":"#0c1e38"}>
                <span style={{ width:3, height:14, background:color, borderRadius:2, flexShrink:0 }}/>
                <span style={{ ...mono, fontSize:10, color:"#c8d8f0", fontWeight:600, flex:1 }}>{tech}</span>
                <span style={{ ...mono, fontSize:8, color:"#1e3a5f" }}>{TACTIC_SHORT[tactic]||tactic}</span>
                <span style={{ ...mono, fontSize:10, color: isOpen?"#22d3ee":"#1e3a5f" }}>{isOpen?"▲":"▼"}</span>
              </div>
              {isOpen && (
                <div style={{ marginTop:2, marginLeft:8, borderLeft:`1px solid ${color}30`, paddingLeft:8 }}>
                  {loadingTech===tech && <div style={{padding:"8px 0"}}><Spinner size={12}/></div>}
                  {datasets.length===0 && loadingTech!==tech && (
                    <div style={{ ...mono, fontSize:8, color:"#1e3a5f", padding:"6px 0" }}>No datasets</div>
                  )}
                  {datasets.map((ds,i) => (
                    <div key={i} onClick={()=>onAdd(ds)}
                      style={{ display:"flex", alignItems:"flex-start", gap:8, padding:"7px 8px",
                        background:"#030a17", border:"1px solid #0c1e38", borderRadius:5,
                        marginBottom:3, cursor:"pointer" }}
                      onMouseEnter={e=>{ e.currentTarget.style.borderColor="#22d3ee30"; e.currentTarget.style.background="#060f20"; }}
                      onMouseLeave={e=>{ e.currentTarget.style.borderColor="#0c1e38"; e.currentTarget.style.background="#030a17"; }}>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ ...mono, fontSize:8, color: ds.ltColor, marginBottom:2 }}>{ds.lt}</div>
                        <div style={{ ...mono, fontSize:9, color:"#4a6a8a", lineHeight:1.3,
                          whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                          {ds.name || ds.id}
                        </div>
                      </div>
                      <span style={{ ...mono, fontSize:9, color:"#22d3ee", flexShrink:0,
                        background:"#22d3ee18", border:"1px solid #22d3ee30",
                        padding:"2px 7px", borderRadius:4, marginTop:1 }}>+ add</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Story Generator (AI → TTP chain) ─────────────────────────────────────────
function StoryGenerator({ onGenerate, ghToken, repoIndex, geminiKey }) {
  const [story, setStory]   = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState("");

  const canGenerate = story.trim() && geminiKey?.trim();

  async function generate() {
    if (!canGenerate) return;
    setLoading(true);
    setError("");
    try {
      const availableTechs = repoIndex ? Object.keys(repoIndex.byTechnique) : [];
      const techList = availableTechs.slice(0, 200).join(", ");

      const prompt = `You are a threat intelligence expert helping map attack narratives to MITRE ATT&CK techniques.

The user wants to build an attack scenario. Available techniques in the dataset library (splunk/attack_data):
${techList}

User's attack story:
"${story}"

Map this story to an ordered chain of MITRE ATT&CK techniques. For each step:
1. Pick a technique ID from the available list if possible (prefer ones with datasets)
2. Write a short label describing what happens at that step
3. Order them chronologically as a kill chain

Respond ONLY with valid JSON, no markdown, no explanation:
{
  "title": "short scenario name",
  "steps": [
    { "technique": "T1566.001", "label": "Spearphishing email with malicious attachment" },
    { "technique": "T1204.002", "label": "User opens malicious Office document" }
  ]
}`;

      const MODELS = [
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-flash-8b",
      ];

      const callGemini = async (model) => {
        const res = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
            }),
          }
        );
        const data = await res.json();
        if (data.error) {
          const is429 = data.error.code === 429 || data.error.message?.includes("exhausted");
          throw Object.assign(new Error(data.error.message), { is429 });
        }
        return data;
      };

      let data = null;
      for (let i = 0; i < MODELS.length; i++) {
        try {
          data = await callGemini(MODELS[i]);
          break;
        } catch (e) {
          if (e.is429 && i < MODELS.length - 1) {
            setError(`Quota hit on ${MODELS[i]}, retrying with ${MODELS[i+1]}…`);
            await new Promise(r => setTimeout(r, 1500));
            continue;
          }
          throw e;
        }
      }

      setError("");
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
      const clean = text.replace(/```json|```/g, "").trim();
      const parsed = JSON.parse(clean);
      onGenerate(parsed);
    } catch (e) {
      setError(e.message?.includes("API key") || e.message?.includes("401")
        ? "Invalid Gemini API key — check the key in the sidebar"
        : `Generation failed: ${e.message}`);
    }
    setLoading(false);
  }

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
      <div style={{ display:"flex", gap:8, alignItems:"flex-end" }}>
        <div style={{ flex:1 }}>
          <textarea
            value={story}
            onChange={e=>setStory(e.target.value)}
            placeholder={geminiKey
              ? "Describe your attack scenario… e.g. User XYZ clicks a phishing link, credentials stolen, attacker moves laterally to file server and exfiltrates documents"
              : "Enter a Gemini API key in the sidebar to enable AI scenario generation…"}
            rows={2}
            disabled={!geminiKey}
            style={{ width:"100%", background:"#030a17", border:"1px solid #0c1e38",
              borderRadius:8, padding:"10px 14px", color: geminiKey ? "#c8d8f0" : "#2a4a6a",
              fontSize:12, ...sans, outline:"none", resize:"none", lineHeight:1.5,
              opacity: geminiKey ? 1 : 0.6 }}
            onFocus={e=>e.target.style.borderColor="rgba(34,211,238,0.27)"}
            onBlur={e=>e.target.style.borderColor="#0c1e38"}
            onKeyDown={e=>{ if(e.key==="Enter" && e.metaKey) generate(); }}
          />
        </div>
        <button onClick={generate} disabled={loading || !canGenerate}
          style={{ padding:"10px 20px",
            background: !canGenerate || loading ? "#030a17" : "linear-gradient(135deg,#0891b2,#0c4a6e)",
            border:`1px solid ${!canGenerate || loading ? "#0c1e38" : "#0891b240"}`,
            borderRadius:8, color: !canGenerate || loading ? "#2a4a6a" : "#fff", ...mono,
            fontSize:11, fontWeight:700, cursor: !canGenerate || loading ? "not-allowed" : "pointer",
            letterSpacing:"0.05em", whiteSpace:"nowrap", transition:"all .2s",
            flexShrink:0, height:60, display:"flex", alignItems:"center", justifyContent:"center" }}>
          {loading ? <Spinner size={14}/> : "✦ Generate"}
        </button>
      </div>
      {error && <div style={{ ...mono, fontSize:9, color:"#ef4444" }}>{error}</div>}
      <div style={{ ...mono, fontSize:8, color:"#1e3a5f" }}>
        {geminiKey
          ? "\u2318\u21b5 to generate \xb7 Gemini maps your narrative to ATT&CK techniques and finds matching datasets"
          : "\u26a0 Add a Gemini API key in the sidebar to enable AI scenario generation"}
      </div>
    </div>
  );
}


// ── Sidebar config panel ──────────────────────────────────────────────────────
function SidebarConfig({ tenants, setTenants, schedule, setSchedule, delta, setDelta,
    ghToken, setGhToken, ghRepo, setGhRepo, geminiKey, setGeminiKey, onDeploy }) {
  const empty = { name:"", label:"", customerId:"", region:"US", credentials:"", ingestionLabels:[] };
  const [form, setForm]     = useState(empty);
  const [editIdx, setEditIdx] = useState(null);
  const [addingTenant, setAddingTenant] = useState(false);
  const [preset, setPreset] = useState("Daily midnight");
  const f = k => v => setForm(p=>({...p,[k]:v}));

  const save = () => {
    if (!form.name || !form.customerId) return;
    if (editIdx !== null) {
      setTenants(t=>t.map((x,i)=>i===editIdx?{...form}:x)); setEditIdx(null);
    } else setTenants(t=>[...t,{...form}]);
    setForm(empty); setAddingTenant(false);
  };

  const parts = (schedule==="once" ? "- - - - -" : schedule).split(" ");

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:0, height:"100%", overflowY:"auto" }}>

      {/* Header */}
      <div style={{ padding:"16px 18px 12px", borderBottom:"1px solid #08172c", flexShrink:0 }}>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
          <div style={{ width:26, height:26, borderRadius:7, flexShrink:0,
            background:"linear-gradient(135deg,#0891b2,#0c6e8a)",
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:12, boxShadow:"0 0 14px #0891b220" }}>⛓</div>
          <div style={{ fontWeight:800, fontSize:13, letterSpacing:"0.05em", color:"#e2f0ff" }}>
            LOGSTORY
          </div>
        </div>
        <div style={{ ...mono, fontSize:7, color:"#0c1e38", letterSpacing:"0.16em" }}>
          SPLUNK ATTACK DATA → GOOGLE SECOPS
        </div>
      </div>

      {/* Config file import/export */}
      <div style={{ padding:"12px 18px", borderBottom:"1px solid #08172c", flexShrink:0 }}>
        <div style={{ ...mono, fontSize:8, color:"#3d5a7a", letterSpacing:"0.1em", marginBottom:8 }}>CONFIG FILE</div>
        <div style={{ display:"flex", gap:6 }}>
          <label style={{ cursor:"pointer", flex:1 }}>
            <input type="file" accept=".json" style={{ display:"none" }}
              onChange={e => {
                const file = e.target.files?.[0]; if (!file) return;
                const reader = new FileReader();
                reader.onload = evt => {
                  try {
                    const cfg = JSON.parse(evt.target.result);
                    if (cfg.tenants)   setTenants(cfg.tenants);
                    if (cfg.ghRepo)    setGhRepo(cfg.ghRepo);
                    if (cfg.ghToken)   setGhToken(cfg.ghToken);
                    if (cfg.schedule)  setSchedule(cfg.schedule);
                    if (cfg.delta)     setDelta(cfg.delta);
                    if (cfg.geminiKey) setGeminiKey(cfg.geminiKey);
                  } catch { alert("Invalid JSON config"); }
                  e.target.value="";
                };
                reader.readAsText(file);
              }}/>
            <div style={{ textAlign:"center", padding:"5px 8px", background:"#030a17",
              border:"1px solid #0c1e38", borderRadius:5, color:"#4a6a8a",
              ...mono, fontSize:9, cursor:"pointer" }}
              onMouseEnter={e=>e.currentTarget.style.borderColor="#3b82f640"}
              onMouseLeave={e=>e.currentTarget.style.borderColor="#0c1e38"}>
              ⬆ Upload
            </div>
          </label>
          <button onClick={() => {
            const cfg = { tenants, ghRepo, ghToken, schedule, delta, geminiKey,
                _note: "Logstory Orchestrator config — keep ghToken and geminiKey private" };
            const blob = new Blob([JSON.stringify(cfg,null,2)],{type:"application/json"});
            const a = document.createElement("a"); a.href=URL.createObjectURL(blob);
            a.download="logstory-config.json"; a.click();
          }} style={{ flex:1, padding:"5px 8px", background:"#030a17",
            border:"1px solid #0c1e38", borderRadius:5, color:"#4a6a8a",
            ...mono, fontSize:9, cursor:"pointer" }}
            onMouseEnter={e=>e.currentTarget.style.borderColor="#3b82f640"}
            onMouseLeave={e=>e.currentTarget.style.borderColor="#0c1e38"}>
            ⬇ Export
          </button>
        </div>
      </div>

      {/* GitHub settings */}
      <div style={{ padding:"12px 18px", borderBottom:"1px solid #08172c", flexShrink:0 }}>
        <div style={{ ...mono, fontSize:8, color:"#3d5a7a", letterSpacing:"0.1em", marginBottom:8 }}>GITHUB</div>
        <div style={{ display:"flex", flexDirection:"column", gap:7 }}>
          <Inp label="Repo (owner/repo)" value={ghRepo} onChange={setGhRepo} placeholder="you/demo-data" mono/>
          <Inp label="Token" value={ghToken} onChange={setGhToken} placeholder="ghp_…" mono/>
        </div>
      </div>

      {/* Gemini key */}
      <div style={{ padding:"12px 18px", borderBottom:"1px solid #08172c", flexShrink:0 }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
          <div style={{ ...mono, fontSize:8, color:"#3d5a7a", letterSpacing:"0.1em" }}>GEMINI API KEY</div>
          {geminiKey && <span style={{ ...mono, fontSize:7, color:"#10b981",
            background:"#10b98118", border:"1px solid #10b98130",
            padding:"1px 6px", borderRadius:3 }}>✓ set</span>}
        </div>
        <Inp value={geminiKey} onChange={setGeminiKey}
          placeholder="AIza…"
          mono/>
        <div style={{ ...mono, fontSize:7, color:"#1e3a5f", marginTop:5, lineHeight:1.5 }}>
          Used only for scenario generation · never sent to our servers ·{" "}
          <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer"
            style={{ color:"#3d5a7a", textDecoration:"none" }}
            onMouseEnter={e=>e.target.style.color="#22d3ee"}
            onMouseLeave={e=>e.target.style.color="#3d5a7a"}>get a key →</a>
        </div>
      </div>

      {/* Schedule */}
      <div style={{ padding:"12px 18px", borderBottom:"1px solid #08172c", flexShrink:0 }}>
        <div style={{ ...mono, fontSize:8, color:"#3d5a7a", letterSpacing:"0.1em", marginBottom:8 }}>SCHEDULE</div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:4, marginBottom:8 }}>
          {CRON_PRESETS.map(p=>(
            <button key={p.l} onClick={()=>{setPreset(p.l); if(p.c) setSchedule(p.c);}}
              style={{ padding:"5px 7px", textAlign:"left",
                background:preset===p.l?"#091828":"#030a17",
                border:`1px solid ${preset===p.l?"#22d3ee35":"#0c1e38"}`,
                color:preset===p.l?"#22d3ee":"#3d5a7a",
                borderRadius:5, ...mono, fontSize:8, cursor:"pointer" }}>{p.l}</button>
          ))}
        </div>
        {preset==="Custom" && (
          <Inp label="Cron expression" value={schedule} onChange={setSchedule} placeholder="1 0 * * *" mono/>
        )}
        {schedule!=="once" && (
          <div style={{ display:"flex", gap:3, marginTop:6 }}>
            {["MIN","HOUR","DOM","MON","DOW"].map((lbl,i)=>(
              <div key={lbl} style={{ flex:1, textAlign:"center", background:"#030a17",
                border:"1px solid #0c1e38", borderRadius:5, padding:"5px 2px" }}>
                <div style={{ ...mono, fontSize:6, color:"#1e3a5f", marginBottom:2 }}>{lbl}</div>
                <div style={{ ...mono, fontSize:11, color:"#22d3ee", fontWeight:700 }}>{parts[i]||"*"}</div>
              </div>
            ))}
          </div>
        )}
        {schedule==="once" && (
          <div style={{ padding:"6px 8px", background:"#030a17", border:"1px solid #0c1e38",
            borderRadius:5, ...mono, fontSize:8, color:"#22d3ee", lineHeight:1.5 }}>
            Manual trigger only via GitHub Actions
          </div>
        )}
        <div style={{ marginTop:8 }}>
          <div style={{ ...mono, fontSize:8, color:"#3d5a7a", letterSpacing:"0.1em", marginBottom:5 }}>TIMESTAMP DELTA</div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:4 }}>
            {["1d","1d1h","2d","0d"].map(v=>(
              <button key={v} onClick={()=>setDelta(v)}
                style={{ padding:"6px 4px", borderRadius:5, cursor:"pointer",
                  background:delta===v?"#091828":"#030a17",
                  border:`1px solid ${delta===v?"#22d3ee35":"#0c1e38"}`,
                  color:delta===v?"#22d3ee":"#3d5a7a",
                  ...mono, fontSize:12, fontWeight:700 }}>{v}</button>
            ))}
          </div>
        </div>
      </div>

      {/* Tenants */}
      <div style={{ padding:"12px 18px", flex:1 }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
          <div style={{ ...mono, fontSize:8, color:"#3d5a7a", letterSpacing:"0.1em" }}>
            TENANTS {tenants.length>0 && <span style={{color:"#22d3ee"}}>({tenants.length})</span>}
          </div>
          <button onClick={()=>{ setAddingTenant(t=>!t); setForm(empty); setEditIdx(null); }}
            style={{ ...mono, fontSize:9, padding:"3px 8px", background:"#030a17",
              border:"1px solid #0c1e38", borderRadius:4, color:"#3d5a7a", cursor:"pointer" }}>
            {addingTenant ? "cancel" : "+ add"}
          </button>
        </div>

        {/* Existing tenants */}
        {tenants.map((t,i) => (
          <div key={i} style={{ padding:"7px 9px", background:"#030a17", border:"1px solid #0c1e38",
            borderRadius:6, marginBottom:4, display:"flex", alignItems:"center", gap:8 }}>
            <Dot status="success" size={5}/>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ ...mono, fontSize:9, color:"#c8d8f0", fontWeight:600,
                whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{t.label||t.name}</div>
              <div style={{ ...mono, fontSize:7, color:"#1e3a5f" }}>{t.region}</div>
            </div>
            <button onClick={()=>{ setForm({...t}); setEditIdx(i); setAddingTenant(true); }}
              style={{ background:"none", border:"none", color:"#1e3a5f", cursor:"pointer", ...mono, fontSize:9 }}>✎</button>
            <button onClick={()=>setTenants(ts=>ts.filter((_,j)=>j!==i))}
              style={{ background:"none", border:"none", color:"#1e3a5f", cursor:"pointer", ...mono, fontSize:11 }}
              onMouseEnter={e=>e.target.style.color="#ef4444"}
              onMouseLeave={e=>e.target.style.color="#1e3a5f"}>×</button>
          </div>
        ))}

        {/* Add/edit form */}
        {addingTenant && (
          <div style={{ background:"#030a17", border:"1px solid #0c1e38", borderRadius:7, padding:10,
            display:"flex", flexDirection:"column", gap:7 }}>
            <Inp label="ID" value={form.name} onChange={f("name")} placeholder="acme-prod" mono/>
            <Inp label="Label" value={form.label} onChange={f("label")} placeholder="Acme Production"/>
            <Inp label="Customer ID" value={form.customerId} onChange={f("customerId")} placeholder="uuid" mono/>
            <Sel label="Region" value={form.region} onChange={f("region")} options={REGIONS}/>
            <Inp label="Credentials JSON" value={form.credentials} onChange={f("credentials")} rows={3} mono placeholder='{"type":"service_account",...}'/>
            <Btn onClick={save} sm variant={editIdx!==null?"green":"primary"}>
              {editIdx!==null ? "Update Tenant" : "Add Tenant"}
            </Btn>
          </div>
        )}
      </div>

      {/* Deploy button at bottom */}
      <div style={{ padding:"12px 18px", borderTop:"1px solid #08172c", flexShrink:0 }}>
        <button onClick={onDeploy}
          disabled={tenants.length===0}
          style={{ width:"100%", padding:"10px", background: tenants.length===0
            ? "#030a17" : "linear-gradient(135deg,#059669,#047857)",
            border:`1px solid ${tenants.length===0?"#0c1e38":"#059669"}`,
            borderRadius:7, color: tenants.length===0?"#1e3a5f":"#fff",
            ...mono, fontSize:11, fontWeight:700, cursor: tenants.length===0?"not-allowed":"pointer",
            letterSpacing:"0.08em" }}>
          🚀 DEPLOY
        </button>
      </div>
    </div>
  );
}

// ── Main kill chain canvas ────────────────────────────────────────────────────
function ScenarioCanvas({ flowSteps, setFlowSteps, ghToken, repoIndex, indexLoading, geminiKey }) {
  const [view, setView] = useState("chain"); // "chain" | "browse"
  const [dragOver, setDragOver] = useState(false);
  const [scenarioTitle, setScenarioTitle] = useState("");
  const [scenarioSummary, setScenarioSummary] = useState(null);
  const [summaryOpen, setSummaryOpen] = useState(false);
  const canvasRef = useRef(null);

  function addStep(ds) {
    setFlowSteps(p => [...p, {...ds, _key: Date.now() + Math.random()}]);
  }

  function removeStep(i) {
    setFlowSteps(p => p.filter((_,j)=>j!==i));
  }

  function moveLeft(i) {
    if (i===0) return;
    setFlowSteps(p => { const a=[...p]; [a[i-1],a[i]]=[a[i],a[i-1]]; return a; });
  }

  function moveRight(i) {
    setFlowSteps(p => {
      if (i>=p.length-1) return p;
      const a=[...p]; [a[i],a[i+1]]=[a[i+1],a[i]]; return a;
    });
  }

  function swapDataset(i, ds) {
    setFlowSteps(p => p.map((s,j)=>j===i?{...ds,_key:s._key}:s));
  }

  async function handleGenerate({ title, steps }) {
    setScenarioTitle(title || "");
    const newSteps = [];
    for (const s of steps) {
      // try to load a dataset for this technique
      try {
        const datasets = await fetchYamlsForTechnique(s.technique, ghToken);
        if (datasets.length > 0) {
          newSteps.push({ ...datasets[0], _key: Date.now()+Math.random(),
            _storyLabel: s.label });
        } else {
          // add a placeholder node
          newSteps.push({
            id: s.technique, technique: s.technique, name: s.label,
            lt: "UNKNOWN", ltColor:"#475569", desc: s.label,
            mediaUrl:"", _key: Date.now()+Math.random(), _storyLabel: s.label,
            _noDataset: true,
          });
        }
      } catch {
        newSteps.push({
          id: s.technique, technique: s.technique, name: s.label,
          lt:"UNKNOWN", ltColor:"#475569", desc:s.label, mediaUrl:"",
          _key: Date.now()+Math.random(), _storyLabel: s.label, _noDataset:true,
        });
      }
    }
    setFlowSteps(newSteps);
    setView("chain");
  }

  // Group chain steps by tactic for color-coded timeline header
  const tacticGroups = flowSteps.reduce((acc, s) => {
    const t = getTactic(s.technique);
    if (!acc[t]) acc[t] = 0;
    acc[t]++;
    return acc;
  }, {});

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100%", minHeight:0 }}>

      {/* Story generator bar */}
      <div style={{ padding:"14px 20px", borderBottom:"1px solid #08172c", flexShrink:0,
        background:"#020810" }}>
        <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:10 }}>
          <div style={{ ...mono, fontSize:9, color:"#22d3ee", letterSpacing:"0.12em" }}>
            <span style={{color:"#22d3ee55"}}>◈</span> SCENARIO GENERATOR
          </div>
          <div style={{ flex:1, height:1, background:"#08172c" }}/>
          <div style={{ ...mono, fontSize:8, color:"#1e3a5f" }}>
            {indexLoading ? "indexing repo…" : repoIndex
              ? `${Object.keys(repoIndex.byTechnique).length} techniques indexed`
              : "repo not indexed"}
          </div>
        </div>
        <StoryGenerator onGenerate={handleGenerate} ghToken={ghToken} repoIndex={repoIndex} geminiKey={geminiKey}/>
      </div>

      {/* Chain / Browse toggle + chain title */}
      <div style={{ padding:"10px 20px", borderBottom:"1px solid #08172c", flexShrink:0,
        display:"flex", alignItems:"center", gap:12 }}>
        <div style={{ display:"flex", background:"#030a17", border:"1px solid #0c1e38",
          borderRadius:6, padding:2, gap:2 }}>
          {[["chain","⛓ Chain"],["browse","◫ Browse"]].map(([v,l])=>(
            <button key={v} onClick={()=>setView(v)}
              style={{ padding:"5px 12px", borderRadius:4, ...mono, fontSize:9,
                fontWeight:600, cursor:"pointer", border:"none",
                background: view===v ? "#0c1e38" : "transparent",
                color: view===v ? "#22d3ee" : "#3d5a7a" }}>{l}</button>
          ))}
        </div>

        {scenarioTitle && (
          <div style={{ ...mono, fontSize:10, color:"#e2f0ff", fontWeight:700 }}>
            {scenarioTitle}
          </div>
        )}

        {/* tactic strip */}
        <div style={{ display:"flex", gap:4, flex:1, flexWrap:"wrap" }}>
          {Object.entries(tacticGroups).map(([t,n])=>(
            <span key={t} style={{ ...mono, fontSize:8,
              color: TACTIC_COLORS[t] || "#475569",
              background: `${TACTIC_COLORS[t] || "#475569"}15`,
              border:`1px solid ${TACTIC_COLORS[t] || "#475569"}30`,
              padding:"2px 7px", borderRadius:3 }}>
              {TACTIC_SHORT[t]||t} ×{n}
            </span>
          ))}
        </div>

        <div style={{ ...mono, fontSize:9, color:"#1e3a5f", flexShrink:0 }}>
          {flowSteps.length} step{flowSteps.length!==1?"s":""}
        </div>

        {flowSteps.length > 0 && (
          <button onClick={()=>{ if(confirm("Clear the chain?")) { setFlowSteps([]); setScenarioSummary(null); setSummaryOpen(false); } }}
            style={{ ...mono, fontSize:9, padding:"4px 9px", background:"transparent",
              border:"1px solid #1e3a5f40", borderRadius:4, color:"#1e3a5f", cursor:"pointer" }}>
            clear
          </button>
        )}
      </div>

      {/* Scenario summary panel */}
      {scenarioSummary && summaryOpen && (
        <div style={{ borderBottom:"1px solid #08172c", flexShrink:0, background:"#020d1a" }}>
          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
            padding:"8px 20px 6px", borderBottom:"1px solid #040d1c" }}>
            <div style={{ ...mono, fontSize:9, color:"#22d3ee", letterSpacing:"0.1em" }}>
              <span style={{color:"#22d3ee55"}}>◈</span> SCENARIO BRIEFING — {scenarioSummary.title}
            </div>
            <button onClick={()=>setSummaryOpen(false)}
              style={{ ...mono, fontSize:8, color:"#1e3a5f", background:"none", border:"none",
                cursor:"pointer" }}>hide ▲</button>
          </div>
          <div style={{ overflowX:"auto", padding:"12px 20px", display:"flex", gap:8 }}>
            {scenarioSummary.steps.map((s, i) => {
              const tactic = getTactic(s.technique);
              const color = tacticColor(s.technique);
              const matched = flowSteps[i];
              return (
                <div key={i} style={{ flexShrink:0, minWidth:190, maxWidth:210,
                  background:"#030a17", border:`1px solid ${color}30`,
                  borderRadius:8, padding:"10px 12px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:6 }}>
                    <span style={{ width:3, height:28, background:color, borderRadius:2, flexShrink:0 }}/>
                    <div>
                      <div style={{ ...mono, fontSize:10, color:"#e2f0ff", fontWeight:700 }}>{s.technique}</div>
                      <div style={{ ...mono, fontSize:7, color, letterSpacing:"0.08em" }}>
                        {TACTIC_SHORT[tactic]||tactic}
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize:10, color:"#7eb8f7", marginBottom:6, lineHeight:1.4 }}>
                    {s.label}
                  </div>
                  {matched && !matched._noDataset ? (
                    <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                      <span style={{ width:5, height:5, borderRadius:"50%",
                        background:"#10b981", flexShrink:0 }}/>
                      <span style={{ ...mono, fontSize:7, color:"#10b981" }}>dataset matched</span>
                      <span style={{ ...mono, fontSize:7, color: matched.ltColor || "#475569",
                        background:`${matched.ltColor||"#475569"}15`,
                        border:`1px solid ${matched.ltColor||"#475569"}30`,
                        padding:"1px 5px", borderRadius:3, marginLeft:2 }}>{matched.lt}</span>
                    </div>
                  ) : (
                    <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                      <span style={{ width:5, height:5, borderRadius:"50%",
                        background:"#f59e0b", flexShrink:0 }}/>
                      <span style={{ ...mono, fontSize:7, color:"#f59e0b" }}>no dataset — manual add</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div style={{ padding:"6px 20px 10px", display:"flex", gap:6, flexWrap:"wrap",
            alignItems:"center" }}>
            <span style={{ ...mono, fontSize:7, color:"#1e3a5f", marginRight:4 }}>LOG SOURCES:</span>
            {[...new Set(flowSteps.filter(s=>s.lt&&s.lt!=="UNKNOWN").map(s=>s.lt))].map(lt => {
              const color = flowSteps.find(s=>s.lt===lt)?.ltColor || "#475569";
              return (
                <span key={lt} style={{ ...mono, fontSize:8, color,
                  background:`${color}15`, border:`1px solid ${color}30`,
                  padding:"2px 7px", borderRadius:3 }}>{lt}</span>
              );
            })}
            {flowSteps.some(s=>!s.lt||s.lt==="UNKNOWN") && (
              <span style={{ ...mono, fontSize:7, color:"#f59e0b" }}>
                + {flowSteps.filter(s=>!s.lt||s.lt==="UNKNOWN").length} without dataset
              </span>
            )}
          </div>
        </div>
      )}
      {scenarioSummary && !summaryOpen && (
        <div style={{ padding:"4px 20px", borderBottom:"1px solid #08172c", flexShrink:0,
          display:"flex", alignItems:"center", gap:8, background:"#020d1a" }}>
          <span style={{ ...mono, fontSize:8, color:"#1e3a5f" }}>Scenario briefing hidden</span>
          <button onClick={()=>setSummaryOpen(true)}
            style={{ ...mono, fontSize:8, color:"#22d3ee", background:"none", border:"none",
              cursor:"pointer" }}>show ▼</button>
        </div>
      )}

      {/* Main content area */}
      <div style={{ flex:1, overflow:"hidden", display:"flex", minHeight:0 }}>

        {view === "chain" && (
          <div ref={canvasRef} style={{ flex:1, overflowX:"auto", overflowY:"hidden",
            padding:"20px 20px", display:"flex", alignItems:"center", gap:14 }}>
            {flowSteps.length === 0 ? (
              <div style={{ flex:1, display:"flex", flexDirection:"column",
                alignItems:"center", justifyContent:"center", gap:12 }}>
                <div style={{ fontSize:32, opacity:.15 }}>⛓</div>
                <div style={{ ...mono, fontSize:11, color:"#1e3a5f", textAlign:"center", lineHeight:1.8 }}>
                  Describe a scenario above and hit Generate<br/>
                  — or switch to Browse and add techniques manually
                </div>
              </div>
            ) : (
              flowSteps.map((step, i) => (
                <ChainNode
                  key={step._key || i}
                  step={step}
                  index={i}
                  total={flowSteps.length}
                  onRemove={removeStep}
                  onMoveLeft={moveLeft}
                  onMoveRight={moveRight}
                  onSwapDataset={swapDataset}
                  repoIndex={repoIndex}
                />
              ))
            )}
          </div>
        )}

        {view === "browse" && (
          <div style={{ flex:1, padding:"16px 20px", display:"flex", gap:16, minHeight:0 }}>
            <div style={{ flex:1, minWidth:0 }}>
              <DatasetBrowser ghToken={ghToken} onAdd={addStep} repoIndex={repoIndex}/>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Deploy Drawer (slides up) ─────────────────────────────────────────────────
function DeployDrawer({ open, onClose, tenants, flowSteps, schedule, delta, ghToken, ghRepo, setGhRepo }) {
  return (
    <div style={{
      position:"fixed", bottom:0, left:280, right:0,
      height: open ? "65vh" : 0,
      background:"#030a17",
      borderTop: open ? "1px solid #22d3ee30" : "none",
      transition:"height .35s cubic-bezier(.4,0,.2,1)",
      overflow:"hidden",
      zIndex:200,
      boxShadow: open ? "0 -20px 60px #000a" : "none",
    }}>
      {open && (
        <div style={{ height:"100%", display:"flex", flexDirection:"column" }}>
          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
            padding:"10px 20px", borderBottom:"1px solid #08172c", flexShrink:0 }}>
            <div style={{ ...mono, fontSize:10, color:"#22d3ee", letterSpacing:"0.12em" }}>
              <span style={{color:"#22d3ee55"}}>◈</span> DEPLOY
            </div>
            <button onClick={onClose}
              style={{ background:"none", border:"none", color:"#3d5a7a",
                cursor:"pointer", ...mono, fontSize:11 }}>✕ close</button>
          </div>
          <div style={{ flex:1, overflowY:"auto" }}>
            <DeployTab tenants={tenants} flowSteps={flowSteps} schedule={schedule}
              delta={delta} ghToken={ghToken} ghRepo={ghRepo} setGhRepo={setGhRepo}/>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── PHASE_ORDER (used by DeployTab) ─────────────────────────────────────────
const PHASE_ORDER = [
  "Reconnaissance","Resource Development","Initial Access","Execution",
  "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
  "Discovery","Lateral Movement","Collection","Command and Control",
  "Exfiltration","Impact","Unknown",
];

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

  // ── GitHub Secrets API helpers ─────────────────────────────────────────────
  // Secrets must be encrypted with the repo's libsodium public key before upload.
  // We load tweetnacl + tweetnacl-sealedbox lazily from CDN to avoid bundling.
  async function loadSodium() {
    if (window._sodiumReady) return window._sodium;
    // Load libsodium-wrappers — the only browser lib that implements crypto_box_seal
    // which is what GitHub's secrets API requires
    await new Promise((res, rej) => {
      const s = document.createElement("script");
      s.src = "https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.13/dist/modules/libsodium-wrappers.js";
      s.onload = res; s.onerror = rej;
      document.head.appendChild(s);
    });
    await window.sodium.ready;
    window._sodiumReady = true;
    window._sodium = window.sodium;
    return window._sodium;
  }

  async function getRepoPublicKey(repo, token) {
    const res = await fetch(`https://api.github.com/repos/${repo}/actions/secrets/public-key`, {
      headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json" },
    });
    if (!res.ok) throw new Error(`Could not fetch repo public key: ${res.status}`);
    return res.json(); // { key_id, key }
  }

  async function encryptSecret(publicKeyB64, value) {
    const sodium = await loadSodium();
    const pubKey = sodium.from_base64(publicKeyB64, sodium.base64_variants.ORIGINAL);
    const msgBytes = sodium.from_string(value);
    // crypto_box_seal = anonymous box, nonce derived internally — exactly what GitHub requires
    const encrypted = sodium.crypto_box_seal(msgBytes, pubKey);
    return sodium.to_base64(encrypted, sodium.base64_variants.ORIGINAL);
  }

  async function upsertSecret(repo, token, secretName, secretValue, keyId, publicKeyB64) {
    const encrypted = await encryptSecret(publicKeyB64, secretValue);
    const res = await fetch(`https://api.github.com/repos/${repo}/actions/secrets/${secretName}`, {
      method: "PUT",
      headers: {
        Authorization: `token ${token}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ encrypted_value: encrypted, key_id: keyId }),
    });
    if (!res.ok && res.status !== 204) {
      const err = await res.json().catch(() => ({}));
      throw new Error(`Secret ${secretName}: ${err.message || res.status}`);
    }
  }

  async function pushSecrets(repo, token, log) {
    log("── secrets ──────────────────────────────────────────────");
    let pkData;
    try {
      pkData = await getRepoPublicKey(repo, token);
    } catch(e) {
      log(`  ⚠  Could not fetch repo public key: ${e.message}`);
      log("     Secrets NOT pushed — set them manually via gh CLI");
      return;
    }
    const { key_id: keyId, key: publicKey } = pkData;

    for (const t of tenants) {
      const s = t.name.toUpperCase().replace(/[^A-Z0-9]/g, "_");
      let ok = 0, fail = 0;

      // Customer ID
      if (t.customerId?.trim()) {
        try {
          await upsertSecret(repo, token, `SECOPS_CUSTOMER_ID_${s}`, t.customerId.trim(), keyId, publicKey);
          log(`  ✓  SECOPS_CUSTOMER_ID_${s}`);
          ok++;
        } catch(e) { log(`  ✗  SECOPS_CUSTOMER_ID_${s}: ${e.message}`); fail++; }
      } else {
        log(`  ⚠  SECOPS_CUSTOMER_ID_${s} — no customerId set, skipped`);
      }

      // Credentials JSON
      if (t.credentials?.trim()) {
        try {
          JSON.parse(t.credentials); // validate before pushing
          await upsertSecret(repo, token, `SECOPS_CREDENTIALS_${s}`, t.credentials.trim(), keyId, publicKey);
          log(`  ✓  SECOPS_CREDENTIALS_${s}`);
          ok++;
        } catch(e) {
          if (e instanceof SyntaxError) {
            log(`  ✗  SECOPS_CREDENTIALS_${s} — credentials field is not valid JSON, skipped`);
          } else {
            log(`  ✗  SECOPS_CREDENTIALS_${s}: ${e.message}`);
          }
          fail++;
        }
      } else {
        log(`  ⚠  SECOPS_CREDENTIALS_${s} — no credentials set, skipped`);
      }

      log(`     ${t.label||t.name}: ${ok} set, ${fail} failed`);
    }
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
      log(""); await pushSecrets(pushRepo, ghToken, log);
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
${schedule === "once" ? "" : `  schedule:\n    - cron: '${schedule}'\n`}  workflow_dispatch:
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
        id: write_creds
        env:
          SECOPS_CREDS: \${{ secrets[format('SECOPS_CREDENTIALS_{0}', matrix.tenant_id)] }}
        run: |
          SECRET_NAME="SECOPS_CREDENTIALS_\${{ matrix.tenant_id }}"
          if [ -z "$SECOPS_CREDS" ]; then
            echo "::warning::Secret $SECRET_NAME not set — skipping tenant \${{ matrix.tenant_id }}"
            echo "           Add it: Settings → Secrets → Actions → New secret, name: $SECRET_NAME"
            echo "skip=true" >> $GITHUB_OUTPUT
            exit 0
          fi
          printf '%s' "$SECOPS_CREDS" > /tmp/secops_creds.json
          python3 -c "import json,sys; json.load(open('/tmp/secops_creds.json'))" || \\
            { echo "::error::$SECRET_NAME is invalid JSON — paste the full service account key."; exit 1; }
          echo "skip=false" >> $GITHUB_OUTPUT

      - name: Cache downloaded datasets
        if: steps.write_creds.outputs.skip != 'true'
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
        if: steps.write_creds.outputs.skip != \'true\'
        run: |
          mkdir -p /tmp/attack_data_cache
          CACHE_FILE="/tmp/attack_data_cache/${fname}"
          if [ ! -f "$CACHE_FILE" ]; then
            curl -fsSL --retry 3 --retry-delay 5 \\
              "${s.mediaUrl}" -o "$CACHE_FILE"
          fi

      - name: "Pass 1 — Events: ${s.name}"
        if: steps.write_creds.outputs.skip != \'true\'
        env:
          SECOPS_CUSTOMER_ID: \${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}
        run: |
          if [ -z "$SECOPS_CUSTOMER_ID" ]; then
            echo "ERROR: SECOPS_CUSTOMER_ID_\${{ matrix.tenant_id }} secret is not set"; exit 1
          fi
          python scripts/replay_dataset.py \\
            --log-file /tmp/attack_data_cache/${fname} \\
            --log-type "${safeLt}" \\
            --credentials /tmp/secops_creds.json \\
            --customer-id "$SECOPS_CUSTOMER_ID" \\
            --region "\${{ matrix.region }}"\${{ matrix.ingestion_labels && format(' --labels {0}', matrix.ingestion_labels) || '' }} \\
            --timestamp-delta "${delta}"

      - name: "Pass 2 — Entities: ${s.name}"
        if: \${{ github.event.inputs.skip_entities != 'true' }}
        env:
          SECOPS_CUSTOMER_ID: \${{ secrets[format('SECOPS_CUSTOMER_ID_{0}', matrix.tenant_id)] }}
        run: |
          if [ -z "$SECOPS_CUSTOMER_ID" ]; then
            echo "ERROR: SECOPS_CUSTOMER_ID_\${{ matrix.tenant_id }} secret is not set"; exit 1
          fi
          python scripts/replay_dataset.py \\
            --log-file /tmp/attack_data_cache/${fname} \\
            --log-type "${safeLt}" \\
            --credentials /tmp/secops_creds.json \\
            --customer-id "$SECOPS_CUSTOMER_ID" \\
            --region "\${{ matrix.region }}"\${{ matrix.ingestion_labels && format(' --labels {0}', matrix.ingestion_labels) || '' }} \\
            --timestamp-delta "${delta}" \\
            --entities`;
}).join("\n\n")}

      - name: Cleanup credentials
        if: always()
        run: rm -f /tmp/secops_creds.json
`;

  const replayScript = `#!/usr/bin/env python3
"""scripts/replay_dataset.py — Logstory wrapper for Splunk Attack Data

Installs a synthetic usecase directly into the logstory package usecases/
directory (the only discovery path logstory supports), replays it, then
cleans up. Works with any logstory version.
"""
import argparse, importlib, os, shutil, subprocess, sys
from pathlib import Path

USECASE_NAME = "SPLUNK_ATTACK_DATA"

def get_logstory_usecases_dir():
    """Find the usecases/ directory inside the installed logstory package."""
    import logstory
    return Path(logstory.__file__).parent / "usecases"

def install_usecase(usecases_dir, log_file, log_type, entities=False):
    """Copy the log file into the logstory usecases/ folder as a named usecase."""
    usecase_dir  = usecases_dir / USECASE_NAME
    subdir       = "ENTITIES" if entities else "EVENTS"
    ext          = ".ndjson" if entities else ".log"
    target_dir   = usecase_dir / subdir
    target_dir.mkdir(parents=True, exist_ok=True)

    # logstory discovers files by log type name — filename must match exactly
    target_file  = target_dir / f"{log_type}{ext}"
    shutil.copy(log_file, target_file)

    # Required __init__.py so Python treats it as a package
    init = usecase_dir / "__init__.py"
    if not init.exists():
        init.touch()

    return usecase_dir

def uninstall_usecase(usecases_dir):
    """Remove the synthetic usecase after replay."""
    usecase_dir = usecases_dir / USECASE_NAME
    if usecase_dir.exists():
        shutil.rmtree(usecase_dir)

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

    # Validate credentials file is present and valid JSON
    creds_path = Path(args.credentials)
    if not creds_path.exists():
        sys.exit(f"[error] Credentials file not found: {creds_path}")
    try:
        import json
        creds_content = creds_path.read_text().strip()
        if not creds_content:
            sys.exit("[error] Credentials file is empty — check that SECOPS_CREDENTIALS secret is set in GitHub")
        json.loads(creds_content)
    except json.JSONDecodeError as e:
        sys.exit(f"[error] Credentials file is not valid JSON: {e}\\n"
                 f"        Check that SECOPS_CREDENTIALS secret contains the full service account JSON key")

    # Validate customer ID
    if not args.customer_id or not args.customer_id.strip():
        sys.exit("[error] --customer-id is empty — check that SECOPS_CUSTOMER_ID secret is set in GitHub")

    log_file = Path(args.log_file)
    if not log_file.exists():
        sys.exit(f"[error] Log file not found: {log_file}")

    usecases_dir = get_logstory_usecases_dir()
    print(f"[info] logstory usecases dir: {usecases_dir}")

    # If entities mode, generate NDJSON from events log first
    replay_file = log_file
    if args.entities:
        sys.path.insert(0, str(Path(__file__).parent))
        from extract_entities import extract_entities
        ndjson = extract_entities(log_file, args.log_type)
        if not ndjson or not ndjson.strip():
            print(f"[warn] No entities extracted from {log_file.name} — skipping entity pass")
            sys.exit(0)
        ndjson_file = log_file.with_suffix(".ndjson")
        ndjson_file.write_text(ndjson)
        replay_file = ndjson_file
        print(f"[info] Extracted {len(ndjson.splitlines())} entity records")

    try:
        install_usecase(usecases_dir, replay_file, args.log_type, entities=args.entities)
        print(f"[info] Installed usecase {USECASE_NAME}/{('ENTITIES' if args.entities else 'EVENTS')}/{args.log_type}")

        env = {
            **os.environ,
            "LOGSTORY_CUSTOMER_ID":      args.customer_id,
            "LOGSTORY_CREDENTIALS_PATH": args.credentials,
            "LOGSTORY_REGION":           args.region,
        }
        cmd = [
            "logstory", "replay", "usecase", USECASE_NAME,
            f"--timestamp-delta={args.timestamp_delta}",
            f"--credentials-path={args.credentials}",
            f"--customer-id={args.customer_id}",
            f"--region={args.region}",
        ]
        if args.entities:
            cmd.append("--entities")

        print(f"[info] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, env=env)
        sys.exit(result.returncode)

    finally:
        uninstall_usecase(usecases_dir)
        print(f"[info] Cleaned up usecase {USECASE_NAME}")

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


// ─── APP ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [flowSteps, setFlowSteps] = useState([]);
  const [tenants, setTenants]     = useState([]);
  const [schedule, setSchedule]   = useState("once");
  const [delta, setDelta]         = useState("1d");
  const [ghToken, setGhToken]     = useState("");
  const [ghRepo, setGhRepo]       = useState("keith-manville/demo-data");
  const [deployOpen, setDeployOpen] = useState(false);
  const [geminiKey, setGeminiKey] = useState("");

  // Repo index (background fetch)
  const [repoIndex, setRepoIndex]     = useState(null);
  const [indexLoading, setIndexLoading] = useState(false);

  useEffect(() => {
    setIndexLoading(true);
    fetchRepoIndex(ghToken)
      .then(idx => setRepoIndex(idx))
      .catch(() => {})
      .finally(() => setIndexLoading(false));
  }, [ghToken]);

  return (
    <div style={{ display:"flex", height:"100vh", overflow:"hidden",
      background:"#020810", color:"#c8d8f0", ...sans }}>
      <style>{globalCss}</style>

      {/* Left sidebar */}
      <div style={{ width:280, flexShrink:0, borderRight:"1px solid #08172c",
        background:"#020810", overflow:"hidden", display:"flex", flexDirection:"column" }}>
        <SidebarConfig
          tenants={tenants} setTenants={setTenants}
          schedule={schedule} setSchedule={setSchedule}
          delta={delta} setDelta={setDelta}
          ghToken={ghToken} setGhToken={setGhToken}
          ghRepo={ghRepo} setGhRepo={setGhRepo}
          geminiKey={geminiKey} setGeminiKey={setGeminiKey}
          onDeploy={() => setDeployOpen(true)}
        />
      </div>

      {/* Main canvas area */}
      <div style={{ flex:1, display:"flex", flexDirection:"column", minWidth:0,
        paddingBottom: deployOpen ? 0 : 0 }}>
        <ScenarioCanvas
          flowSteps={flowSteps}
          setFlowSteps={setFlowSteps}
          ghToken={ghToken}
          repoIndex={repoIndex}
          indexLoading={indexLoading}
          geminiKey={geminiKey}
        />
      </div>

      {/* Deploy drawer (slides up from bottom) */}
      <DeployDrawer
        open={deployOpen}
        onClose={()=>setDeployOpen(false)}
        tenants={tenants}
        flowSteps={flowSteps}
        schedule={schedule}
        delta={delta}
        ghToken={ghToken}
        ghRepo={ghRepo}
        setGhRepo={setGhRepo}
      />
    </div>
  );
}
