import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  Upload, FileUp, FileSpreadsheet, FileText, ShieldAlert, AlertTriangle,
  CheckCircle2, XCircle, Info, Globe, Download, Eye, Database, Zap,
  Layers, Server, Activity, ArrowLeft, FileDigit, Lock, WifiOff, Loader2,
} from "lucide-react";
import {
  uploadVaptReport,
  uploadVaptVerificationReport,
  downloadVaptReport,
  downloadVaptReportAdmin,
  getVaptOrganizations,
  getAdminVaptRescanRequests,
  requestVaptAccess,
  requestVaptRegion,
  getVaptAccessStatus,
  getVaptOnboarding,
  updateVaptOnboarding,
  uploadVaptChecklistAttachment,
  deleteVaptChecklistAttachment,
  downloadVaptAssetListTemplate,
  getHasCompletedScans,
  decideInitialVaptDate,
  getWebSocketUrl,
} from "../services/api";
import { getClientVaptAccessState } from "../utils/vaptAccessGate";
import {
  SEVERITY_META,
  SEVERITY_ORDER,
  severityMeta,
  riskTone,
  fmtDate,
  fmtCvss,
  formatBytes,
  validateVaptFile,
  FORMAT_BADGE,
  formatSource,
  MAX_FILE_SIZE,
} from "../utils/vaptReport";

function toDatetimeLocal(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (part) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function DropZone({ onFile, error, isUploading }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer?.files?.[0];
      if (file) onFile(file);
    },
    [onFile],
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => !isUploading && inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          if (!isUploading) inputRef.current?.click();
        }
      }}
      className={`group relative cursor-pointer rounded-[28px] border-2 border-dashed p-10 text-center transition-all duration-300 sm:p-14 ${
        dragging
          ? "border-purple-500 bg-purple-50/70 scale-[1.01] shadow-[0_24px_60px_rgba(128,0,128,0.12)] dark:bg-purple-950/30"
          : "border-slate-300 bg-white/70 hover:border-purple-400 hover:bg-purple-50/40 dark:border-slate-700 dark:bg-slate-900/50 dark:hover:border-purple-600 dark:hover:bg-purple-950/20"
      } ${isUploading ? "pointer-events-none opacity-60" : ""}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".nessus,.xml,.csv,.xls,.xlsx"
        className="hidden"
        disabled={isUploading}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />

      <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-[24px] bg-gradient-to-br from-purple-500 to-indigo-600 text-white shadow-lg shadow-purple-500/25 transition-transform duration-300 group-hover:scale-105 group-hover:-rotate-3">
        <Upload size={34} strokeWidth={1.8} />
      </div>

      <h3 className="text-xl font-bold text-slate-900 dark:text-slate-100">
        Drag &amp; drop your scanner export
      </h3>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500 dark:text-slate-400">
        or <span className="font-semibold text-purple-600 dark:text-purple-400">browse</span>{" "}
        — Nessus (.nessus / .xml), CSV or Excel (.xls / .xlsx) exports up to{" "}
        {formatBytes(MAX_FILE_SIZE)}.
      </p>

      <div className="mt-6 flex flex-wrap items-center justify-center gap-2 text-[11px] font-semibold">
        {[
          { icon: <FileText size={12} />, label: "Nessus XML", cls: "border-indigo-200 bg-indigo-50 text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-400" },
          { icon: <FileSpreadsheet size={12} />, label: "CSV", cls: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400" },
          { icon: <FileDigit size={12} />, label: "Excel", cls: "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-400" },
          { icon: <Lock size={12} />, label: "Passive · org-scoped", cls: "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400" },
        ].map(({ icon, label, cls }) => (
          <span key={label} className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 ${cls}`}>
            {icon} {label}
          </span>
        ))}
      </div>

      {error && (
        <div className="mx-auto mt-6 flex max-w-lg items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-left text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon, tone, sub }) {
  return (
    <div className={`rounded-2xl border bg-white p-5 shadow-sm transition-transform duration-200 hover:-translate-y-0.5 dark:bg-slate-900 ${tone?.border || "border-slate-200 dark:border-slate-800"}`}>
      <div className="flex items-center gap-4">
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${tone?.iconBg || "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}>
          {icon}
        </div>
        <div className="min-w-0">
          <p className={`text-2xl font-extrabold leading-none ${tone?.text || "text-slate-900 dark:text-slate-100"}`}>{value}</p>
          <p className="mt-1.5 truncate text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</p>
          {sub && <p className="mt-0.5 text-[11px] text-slate-400">{sub}</p>}
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const meta = severityMeta(severity);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${meta.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

function CapabilityCard({ icon, title, description, color = "text-purple-600 bg-purple-50 border-purple-100 dark:bg-purple-950/40 dark:border-purple-900" }) {
  return (
    <div className="flex items-start gap-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md dark:border-slate-800 dark:bg-slate-900">
      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${color}`}>
        {icon}
      </div>
      <div>
        <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">{title}</h4>
        <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{description}</p>
      </div>
    </div>
  );
}

function ChoiceChipGroup({ options, value, onChange, disabled = false }) {
  return (
    <div className={`flex flex-wrap gap-2 ${disabled ? "opacity-70" : ""}`}>
      {options.map((option) => (
        <button
          key={option}
          type="button"
          disabled={disabled}
          onClick={() => onChange(option)}
          className={`rounded-full border px-3 py-2 text-xs font-semibold transition disabled:cursor-not-allowed ${value === option ? "border-violet-600 bg-violet-600 text-white shadow-sm" : "border-slate-200 bg-slate-50 text-slate-700 hover:border-violet-200 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300"}`}
        >
          {option}
        </button>
      ))}
    </div>
  );
}

export default function VaptUpload() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const regionRequestMode = searchParams.get("region_request") === "1";
  const verificationScheduleParam = searchParams.get("verification_schedule") || "";
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileError, setFileError] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [progressMsg, setProgressMsg] = useState("");
  const [preview, setPreview] = useState(null);
  const [uploadError, setUploadError] = useState("");
  const [orgs, setOrgs] = useState([]);
  const [selectedOrgId, setSelectedOrgId] = useState("");
  const [selectedRegion, setSelectedRegion] = useState("");
  const [verificationSchedules, setVerificationSchedules] = useState([]);
  const [selectedVerificationSchedule, setSelectedVerificationSchedule] = useState(verificationScheduleParam);
  const [verificationDisplayName, setVerificationDisplayName] = useState("");
  const [orgsError, setOrgsError] = useState("");
  const [vaptAccessStatus, setVaptAccessStatus] = useState({
    vapt_access_enabled: false,
    requested_regions: [],
    approved_regions: [],
    available_regions: [],
  });
  // Per-question upload state for checklist attachments, keyed by
  // `${sectionId}::${questionId}`. Declared with the other hooks because the
  // component returns early for blocked / ungated users.
  const [attachmentState, setAttachmentState] = useState({});
  const ASSET_COLUMNS = [
    { key: "employee_name", label: "Employee Name" },
    { key: "hostname", label: "Host Name" },
    { key: "ip_address", label: "IP Address" },
    { key: "device", label: "Device", options: ["Laptop", "Desktop"] },
    { key: "os_version", label: "OS/Version" },
    { key: "device_type", label: "Device Type", options: ["Personal", "Office"] },
    { key: "environment", label: "Environment" },
    { key: "remarks", label: "Remarks" },
  ];
  const LEGACY_QUESTION_SECTIONS = [
    {
      id: "general_information",
      title: "Company Details",
      description: "Basic company, contact, location, and testing-scope information.",
      questions: [
        { id: "organization_name", label: "Organization Name", type: "text", short: true, helper: "Organization name.", example: "Example: Acme Finance Pvt Ltd" },
        { id: "primary_contact", label: "Primary Contact Name / Email / Phone", type: "text", short: true, helper: "Primary contact details.", example: "Example: Rahul Sharma | rahul@acme.com | +91 98xxxxxx" },
        { id: "infrastructure_locations", label: "Infrastructure / office locations in scope", type: "text", short: true, helper: "Infrastructure and office locations in scope.", example: "Example: Mumbai, Singapore, AWS ap-south-1" },
        { id: "technical_poc_vapt", label: "Technical POC for VAPT", type: "text", short: true, helper: "Dedicated technical contact for VAPT coordination.", example: "Example: IT Security Manager / +91..." },
        { id: "assets_in_scope", label: "What assets/systems are in scope?", type: "textarea", helper: "List all in-scope assets and systems.", example: "Example: Internal apps, servers, APIs, VPN gateway." },
        { id: "assets_out_of_scope", label: "What assets/systems are explicitly out of scope?", type: "textarea", helper: "List explicitly excluded assets or systems.", example: "Example: Payment gateway, legacy service environment." },
        { id: "third_party_hosted_managed_systems_in_scope", label: "Are any third-party hosted/managed systems in scope?", type: "textarea", helper: "Include third-party hosted or managed systems relevant to the assessment.", example: "Example: SaaS CRM, managed firewall, vendor-hosted app." },
        { id: "previous_vapt_history", label: "Has a VAPT/penetration test previously been performed for the in-scope assets?", type: "textarea", helper: "Provide prior test history if any.", example: "Example: Last test in 2024; issues remediated." },
        { id: "network_diagram_available", label: "Is a network diagram available, if yes then please provide us with one.", type: "textarea", helper: "Provide any network diagram or architecture context.", example: "Example: Internet > WAF > App servers > DB cluster" },
        { id: "network_diagram_upload", label: "Upload your network / infrastructure diagram", type: "upload", required: false, accept: ".pdf,.png,.jpg,.jpeg", helper: "PDF, PNG or JPG up to 25 MB. Optional: upload the diagram here, or email it to your SOC contact quoting your region code.", example: "Topology diagram showing firewalls, servers and network segments" },
        { id: "sensitive_information_handled", label: "Do any in-scope systems handle sensitive information such as customer data, card payments, or health records?", type: "textarea", helper: "Describe the type of sensitive information in general terms. Do not include actual sensitive data.", example: "Example: Customer contact details and payment-related information." },
      ],
    },
    {
      id: "testing_type",
      title: "Type of Testing",
      description: "Define where testing will happen and how much information the testing team receives.",
      questions: [
        { id: "testing_location", label: "Should the systems be tested from inside the office network, from the internet, or both?", type: "choice", options: ["Internal", "External", "Both", "Not sure"], helper: "Internal means testing from inside the office network; external means testing from the internet." },
        { id: "testing_information_level", label: "How much information should we start with: none, some, or full access/details?", type: "choice", options: ["Black box - no information", "Grey box - some information", "White box - full information", "Not sure"], helper: "If unsure, Grey box is usually a practical starting point." },
        { id: "mobile_apps_in_scope", label: "Are any mobile apps for iOS or Android in scope?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "If yes, provide the app name and store link or app file separately." },
        { id: "wireless_network_in_scope", label: "Is the office Wi-Fi/wireless network included in this test?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "If yes, provide the Wi-Fi network names and security type if known." },
        { id: "physical_security_in_scope", label: "Should physical security be tested, such as office or server-room access?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "This covers physical access controls such as locks, badges, and reception checks." },
      ],
    },
    {
      id: "network_infrastructure",
      title: "Your Internet & Network",
      description: "Infrastructure, scanning exposure, and network segmentation details.",
      questions: [
        { id: "internal_ip_ranges", label: "Internal IP ranges / subnets to be scanned", type: "text", short: true, helper: "Internal private ranges to be scanned.", example: "Example: 10.20.0.0/16, 172.16.10.0/24" },
        { id: "network_segments_vlans_inaccessible", label: "Are any network segments/VLANs inaccessible from the scanning location?", type: "textarea", helper: "Describe any inaccessible segments or VLANs.", example: "Example: Finance VLAN is not reachable from the scan source." },
        { id: "network_security_devices_present", label: "What network/security devices are present?", type: "textarea", helper: "List firewalls, IDS/IPS, proxies, load balancers, routers.", example: "Example: Palo Alto firewall, Fortinet IPS, F5 load balancer." },
        { id: "firewall_make_model", label: "Firewall make and model", type: "text", short: true, helper: "Firewall vendor and model.", example: "Example: Palo Alto PA-5220" },
        { id: "office_static_public_ips", label: "Does the organization have office/static public IP addresses?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Check if static or office public IPs exist.", example: "Example: Yes" },
        { id: "applicable_office_public_ip_ranges", label: "If yes, provide the applicable office/static public IP range(s).", type: "text", short: true, helper: "Public office or static IP ranges.", example: "Example: 203.0.113.0/24" },
        { id: "cloud_hosted_public_ips_included", label: "Are there cloud-hosted public IPs included in the VAPT?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Identify if cloud-hosted public IPs are in scope.", example: "Example: Yes" },
        { id: "external_ips_assets_excluded", label: "Are any external IPs/assets explicitly excluded from VAPT?", type: "textarea", helper: "List excluded public IPs/assets.", example: "Example: Customer-facing legacy IPs excluded." },
        { id: "ip_range_dhcp_static", label: "Your IP range is DHCP/Static, if DHCP then the duration of the IPs being released.", type: "text", short: true, helper: "Describe whether IPs are static or DHCP and lease duration.", example: "Example: DHCP, 7-day lease" },
        { id: "total_physical_machine_count", label: "What is the total physical count of machines in the whole organization?", type: "text", short: true, helper: "Total physical machine count across the organization.", example: "Example: 1200" },
        { id: "physical_machine_count_by_type", label: "Please provide the physical machine count by type, if available.", type: "text", short: true, helper: "Machine count by type if available.", example: "Example: Servers: 42, desktops: 650, laptops: 300" },
        { id: "machines_included_in_vapt", label: "How many organization machines are intended to be included in this VAPT?", type: "text", short: true, helper: "Expected scope size for the VAPT.", example: "Example: 180" },
        { id: "asset_inventory_available", label: "Is an asset inventory/list available?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Asset inventory availability.", example: "Example: Yes" },
        { id: "asset_list_upload", label: "Asset list (inventory of in-scope assets)", type: "asset_table", required: true, helper: "Enter each in-scope asset in the table. Device: Laptop or Desktop. Device Type: Personal or Office." },
        { id: "approx_in_scope_servers", label: "Approximate number of in-scope servers", type: "text", short: true, helper: "Approximate count of in-scope servers.", example: "Example: 35" },
        { id: "approx_in_scope_endpoints", label: "Approximate number of in-scope desktops/laptops/endpoints with the type of OS", type: "text", short: true, helper: "Approximate in-scope endpoints and OS types.", example: "Example: 150 Windows, 20 macOS" },
        { id: "wfh_vpn", label: "Are WFH/remote users connected to the organization's office/network through a VPN?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Remote access via VPN.", example: "Example: Yes" },
        { id: "vpn_solution_used", label: "If yes, what VPN solution is used?", type: "text", short: true, helper: "VPN product in use.", example: "Example: Cisco AnyConnect" },
        { id: "vpn_ip_range_for_access_scan", label: "If yes, what VPN IP / IP range should be used to access/scan the WFH users?", type: "text", short: true, helper: "VPN IP or range used for access and scanning.", example: "Example: 172.18.40.0/24" },
        { id: "vpn_access_required_for_isecurify", label: "Is VPN access required for iSecurify to access and scan WFH users?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Need VPN for WFH users.", example: "Example: Yes" },
        { id: "dedicated_vapt_vpn_account", label: "If VPN access is required, will a dedicated VAPT VPN user/account be created for iSecurify?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Dedicated account for VAPT scanner.", example: "Example: Yes" },
        { id: "approx_wfh_remote_users", label: "Approximately how many WFH/remote-user machines are included in the VAPT?", type: "text", short: true, helper: "Remote-user machine count included in scope.", example: "Example: 80" },
        { id: "vpn_restrictions_mfa_whitelisting", label: "Are there any VPN restrictions, MFA requirements or IP whitelisting requirements for the VAPT account?", type: "textarea", helper: "Describe VPN restrictions, MFA, or IP allowlisting.", example: "Example: MFA required; source IP allowlist configured." },
        { id: "storage_file_server_or_nas", label: "Do you have a storage/file server or NAS?", type: "textarea", helper: "Describe file server or NAS usage.", example: "Example: Synology NAS, file server with shares." },
      ],
    },
    {
      id: "web_applications",
      title: "Websites & Online Applications",
      description: "Web applications, APIs, and authentication flow details.",
      questions: [
        { id: "websites_in_scope", label: "Which websites/web applications are in scope?", type: "text", short: true, helper: "List primary in-scope websites or apps.", example: "Example: portal.acme.com, app.acme.in" },
        { id: "in_scope_websites_access_type", label: "Are the in-scope websites/applications Internet-facing, internal, or VPN-accessible?", type: "text", short: true, helper: "Describe accessibility type.", example: "Example: Internet-facing and VPN-accessible" },
        { id: "staging_uat_dev_test_in_scope", label: "Are any staging/UAT/development/test websites or applications in scope?", type: "textarea", helper: "List non-production environments in scope.", example: "Example: Staging environment is in scope; dev is out of scope." },
        { id: "app_requires_authentication", label: "Does the web application require user authentication/login?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Authentication requirement.", example: "Example: Yes" },
        { id: "authentication_method_used", label: "What authentication method is used?", type: "text", short: true, helper: "Authentication method details.", example: "Example: SSO with Azure AD" },
        { id: "user_roles_required_available", label: "Which user roles are required/available for authenticated testing?", type: "textarea", helper: "Required roles and access levels.", example: "Example: Admin, support, finance user roles." },
        { id: "dedicated_vapt_test_accounts", label: "Will dedicated VAPT test account(s) be created for the required roles?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Dedicated VAPT tester accounts.", example: "Example: Yes" },
        { id: "mfa_enabled_for_in_scope_app", label: "Is MFA/2FA enabled for the in-scope web application accounts?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "MFA status for app accounts.", example: "Example: Yes" },
        { id: "mfa_workaround_for_vapt_tester", label: "If MFA is enabled, how will the VAPT tester complete authentication during testing?", type: "textarea", helper: "MFA workaround or test account process.", example: "Example: We will provide a test MFA-protected account and code generator." },
        { id: "authentication_scanning_restrictions", label: "Are there authentication/scanning restrictions?", type: "textarea", helper: "Restrictions for testing or scanning.", example: "Example: No scanning during business hours. MFA required for all test accounts." },
        { id: "apis_in_scope", label: "Are APIs included in the web/application scope?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "API inclusion in scope.", example: "Example: Yes" },
        { id: "api_urls_auth_method", label: "If APIs are in scope, provide API URL(s) and authentication method, if known.", type: "textarea", helper: "List API URLs and auth method.", example: "Example: https://api.acme.com/v1, OAuth2 client credentials" },
        { id: "waf_cdn_reverse_proxy", label: "Is a WAF/CDN/reverse proxy protecting the in-scope website/application?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "WAF/CDN/proxy status.", example: "Example: Yes" },
        { id: "waf_cdn_provider", label: "If yes, which WAF/CDN/provider is used?", type: "text", short: true, helper: "Provider name.", example: "Example: Cloudflare" },
        { id: "waf_rules_rate_limits_bot_protection", label: "Are there WAF rules, rate limits, bot protection, IP restrictions or other controls that may affect scanning?", type: "textarea", helper: "Relevant security controls affecting scanning.", example: "Example: Rate limiting and bot controls enabled." },
        { id: "source_ips_whitelist", label: "Will our source IP(s) used to scan the website need to be whitelisted?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Need IP allowlisting for scanning.", example: "Example: Yes" },
        { id: "third_party_hosted_managed_web_apps", label: "Are any in-scope websites/applications hosted or managed by a third party?", type: "textarea", helper: "Third-party hosting or management status.", example: "Example: Hosted by SaaS vendor; vendor-managed app." },
      ],
    },
    {
      id: "cloud_and_container",
      title: "Cloud Services",
      description: "Cloud platform, relevant services, and access requirements.",
      questions: [
        { id: "cloud_platforms_used", label: "Which cloud platforms are used for assets relevant to the VAPT?", type: "text", short: true, helper: "Cloud vendor(s) used.", example: "Example: AWS, Azure" },
        { id: "cloud_resources_in_scope", label: "Which cloud resources are in scope?", type: "textarea", helper: "List relevant cloud resources in scope.", example: "Example: EC2, RDS, S3, EKS cluster" },
        { id: "cloud_testing_restrictions", label: "Are there cloud-provider-specific testing requirements, restrictions or notifications?", type: "textarea", helper: "Specific cloud testing requirements or restrictions.", example: "Example: AWS abuse notifications required; no public exposure tests on prod." },
        { id: "relevant_platforms_services", label: "What platforms/services are relevant to the VAPT scope?", type: "textarea", helper: "Relevant platforms/services.", example: "Example: Azure AD, GitHub, Kubernetes, Salesforce" },
        { id: "relevant_platforms_internet_accessible", label: "Which relevant platforms are Internet accessible?", type: "textarea", helper: "Internet-accessible relevant platforms.", example: "Example: Azure portal and GitHub are public." },
        { id: "relevant_platforms_mfa_enabled", label: "For relevant platforms, is MFA/2FA enabled?", type: "textarea", helper: "MFA status for relevant platforms.", example: "Example: Azure MFA enabled; GitHub SSO enforced." },
        { id: "privileged_access_required_for_vapt", label: "Are any relevant platforms expected to require privileged/administrator access for VAPT?", type: "textarea", helper: "Privileged access requirements.", example: "Example: Azure admin access may be required for cloud review." },
      ],
    },
    {
      id: "email_and_endpoint_security",
      title: "Email Security",
      description: "Email platform, endpoint security, and logging posture.",
      questions: [
        { id: "email_service_provider", label: "What email service/provider does the organization use?", type: "text", short: true, helper: "Email provider or platform.", example: "Example: Microsoft 365, Google Workspace" },
        { id: "email_domain_same_as_company", label: "Is the email domain the same as the company's main/official domain?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Check if email domain matches company domain.", example: "Example: No" },
        { id: "email_domain_used_if_different", label: "If different, what email domain(s) are used?", type: "text", short: true, helper: "Alternative email domains used.", example: "Example: mail.company.com" },
        { id: "email_security_solution", label: "Is there any email security/anti-phishing solution in use?", type: "textarea", helper: "Email security and anti-phishing protections.", example: "Example: Mimecast and Defender for Office 365." },
        { id: "antivirus_endpoint_security_solution", label: "What antivirus/endpoint security solution is installed on the organization's machines?", type: "text", short: true, helper: "Endpoint AV/EDR solution.", example: "Example: SentinelOne" },
        { id: "edr_xdr_enabled", label: "Is EDR/XDR enabled on the organization's endpoints?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "EDR/XDR coverage.", example: "Example: Yes" },
        { id: "approx_endpoints_antivirus_edr_protection", label: "Approximately how many endpoints have antivirus/EDR protection?", type: "text", short: true, helper: "Endpoint count with antivirus/EDR.", example: "Example: 900 endpoints" },
        { id: "dns_service_provider", label: "What DNS service/provider is used by the organization?", type: "text", short: true, helper: "DNS provider.", example: "Example: AWS Route53" },
        { id: "centralized_logging_siem", label: "Is there any centralized logging/SIEM solution in use?", type: "textarea", helper: "SIEM or logging platform details.", example: "Example: Splunk or Microsoft Sentinel" },
      ],
    },
    {
      id: "access_and_authorization",
      title: "Monitoring & Access",
      description: "Monitoring tools, additional access, and safe access arrangements.",
      questions: [
        { id: "additional_vpn_remote_access_jump_server", label: "Will VAPT require any additional VPN, remote access, jump server or other access besides the WFH VPN described above?", type: "textarea", helper: "Any additional access required beyond WFH VPN.", example: "Example: Jump host required for prod segment access." },
        { id: "additional_credentials_required_for_vapt", label: "Will any additional credentials be required for VAPT?", type: "textarea", helper: "Any extra credentials required.", example: "Example: Root access or firewall admin credentials." },
        { id: "temporary_monitoring_tool_allowed", label: "Can we install a temporary monitoring tool on the machines being tested?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "The tool helps record security-relevant activity during testing and is removed afterward." },
      ],
    },
    {
      id: "company_directory",
      title: "Company Directory / Login System",
      description: "Centralized employee login and directory information.",
      questions: [
        { id: "active_directory_used", label: "Do you use Active Directory or another central directory to manage employee logins?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "This is the central system employees use to sign in to company computers and services." },
        { id: "directory_domain_name", label: "If yes, what is the directory/domain name?", type: "text", short: true, helper: "Example: company.local or company.com" },
        { id: "domain_controller_count", label: "How many servers manage this login system?", type: "text", short: true, helper: "Approximate number of domain controllers or directory servers." },
        { id: "domain_controller_addresses", label: "What are the addresses of the login-management servers?", type: "text", short: true, helper: "Example: 192.168.1.10, 192.168.1.11" },
        { id: "directory_in_scope", label: "Should this login system be included in the security test?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "Confirm whether the directory itself is part of the VAPT scope." },
      ],
    },
    {
      id: "safety_rules",
      title: "Safety & Rules of Engagement",
      description: "Systems to protect, emergency contacts, backups, and testing limits.",
      questions: [
        { id: "fragile_critical_systems", label: "Are any systems old, fragile, or business-critical that we should handle carefully or avoid?", type: "textarea", helper: "Identify systems that could be disrupted by testing." },
        { id: "recent_backup_available", label: "Do you have a recent backup of the systems being tested?", type: "choice", options: ["Yes", "No", "Not sure"], helper: "This is a safety check before testing begins." },
        { id: "avoid_denial_of_service", label: "Should we avoid tests that could overload or crash a system?", type: "choice", options: ["Yes - avoid them", "No - may include them", "Not sure"], helper: "By default, potentially disruptive tests are avoided." },
        { id: "emergency_contact", label: "Is there a separate emergency contact for unexpected issues during testing?", type: "text", helper: "This may be the technical contact or another person available during and after office hours." },
        { id: "third_party_permission_required", label: "Are any in-scope systems owned or managed by a third-party vendor who must give permission?", type: "textarea", helper: "List any vendor and permission requirements." },
      ],
    },
    {
      id: "testing_window_section",
      title: "Scheduling & Approval",
      description: "Scheduling, approval, and engagement constraints.",
      questions: [
        { id: "preferred_vapt_date_window", label: "Preferred VAPT date / window", type: "text", short: true, helper: "Preferred testing date or window.", example: "Example: 9/4/2026, 11:00 PM to 3:00 AM IST" },
        { id: "dates_times_not_perform", label: "Are there any dates/times when VAPT should not be performed?", type: "textarea", helper: "Blackout dates or times.", example: "Example: No testing during payroll week or on weekends." },
        { id: "formal_approver_authorization", label: "Who will provide formal approval/authorization for the VAPT?", type: "text", short: true, helper: "Approver or approval authority.", example: "Example: CTO or Security Head" },
        { id: "rules_of_engagement_authorization_requirements", label: "Are there any Rules of Engagement or authorization requirements that must be completed before testing?", type: "textarea", helper: "ROE or authorization steps required before testing.", example: "Example: Signed authorization document and ROE approval required." },
        { id: "additional_information_requirements", label: "Is there any additional information or requirement we should know before starting the VAPT?", type: "textarea", helper: "Any additional context before starting.", example: "Example: Must avoid testing during peak traffic; production downtime not allowed." },
      ],
    },
  ];

  const q = (id, label, type = "text", extra = {}) => ({ id, label, type, ...extra });
  const choice = (id, label, options = ["Yes", "No", "Not sure"], extra = {}) => q(id, label, "choice", { options, ...extra });
  const answerSections = [
    {
      id: "company_details", title: "Company Details", description: "Company, contacts, locations, and scope.",
      questions: [
        q("organization_name", "Organization name", "text", { helper: "Legal / registered name of your company." }),
        q("primary_contact", "Primary contact - name, email and phone", "text", { helper: "The main person we should reach out to for this project (could be you)." }),
        q("office_locations", "Office / location(s) to be tested", "text", { helper: "Which office address(es) have the computers, network or systems we'll be testing?" }),
        q("technical_contact", "Technical contact for this VAPT (name, email, phone)", "text", { helper: "The person who looks after your computers, internet or website - this could be an in-house IT person, or an outside IT company/vendor you use. If you don't have anyone, tell us and we'll guide the business contact directly." }),
        q("assets_in_scope", "What are we testing? (assets/systems in scope)", "textarea", { helper: "In plain words, what should we test? Example: office laptops, desktops, CCTV cameras, printers, Wi-Fi router, your website. A detailed list can be added later." }),
        q("previous_vapt", "Has there been any VAPT before (a VAPT / security test)?", "textarea", { helper: "Yes / No / Not Sure - has anyone done a security test on these systems in the past?" }),
        q("network_diagram", "Do you have a network diagram or map of your systems?", "choice", { options: ["Yes", "No", "N/A"], helper: "This is simply a drawing/picture showing how your computers, internet and devices connect to each other. If you have one (even a rough one made by your IT vendor), please attach it. If not, write 'Not available'." }),
        q("network_diagram_upload", "Upload the network diagram or map", "upload", { required: false, hidden: true, inlineFor: "network_diagram", accept: ".pdf,.png,.jpg,.jpeg", helper: "PDF, PNG or JPG." }),
        q("sensitive_information", "Do any of these systems handle sensitive information such as customer data, card payments, or health records?", "textarea", { helper: "This helps us understand what's at stake and prioritize testing accordingly. Just describe in general terms - no need to share the actual data." }),
      ],
    },
    {
      id: "type_of_testing", title: "Type of Testing", description: "Testing location, access level, mobile, wireless, and physical scope.",
      questions: [
        choice("testing_location", "Should the systems be tested from inside your office network, from the internet, or both?", ["Internal", "External", "Both", "Not sure"], { helper: "'Internal' means testing as if someone were already inside your office network. 'External' means testing as an outsider would, from the internet. Most companies want both." }),
        choice("testing_information_level", "How much information should we start with - none, some, or full access/details?", ["Black box", "Grey box", "White box", "Not sure"], { helper: "This is sometimes called Black box (we start with no information, like a real attacker), Grey box (we're given some basic details/logins), or White box (we're given full access/details upfront). If unsure, we usually recommend Grey box - we can decide together on the call." }),
        choice("mobile_apps_in_scope", "Are any mobile apps (iOS/Android) in scope?", ["Yes", "No", "Not sure"], { helper: "Yes / No. If yes, please share the app name and a link to it (App Store/Play Store), or the app file if it's not public." }),
        choice("wireless_in_scope", "Is your office Wi-Fi (wireless network) included in this test?", ["Yes", "No", "Not sure"], { helper: "Yes / No. If yes, please share the Wi-Fi network name(s) (SSID) and what type of Wi-Fi security is used, if known." }),
        choice("physical_security_in_scope", "Should physical security be tested, such as office or server-room access?", ["Yes", "No", "Not sure"], { helper: "Yes / No. This checks physical access controls like door locks, ID badges or reception checks." }),
      ],
    },
    {
      id: "internet_network", title: "Your Internet & Network", description: "Internet addresses, devices, and DNS.",
      questions: [
        q("internal_ip_ranges", "Internal computer address ranges to be scanned (IP ranges)", "text", { helper: "Every device on your office network has an internal address, e.g. 192.168.1.1 to 192.168.1.254. If you don't know this, ask whoever set up your office Wi-Fi/network (your IT vendor) - they will have this information." }),
        q("network_devices", "What network devices do you have?", "textarea", { helper: "Example: Firewall (security box for internet), Router, Switch, Wi-Fi Access Point. If unsure, ask your internet/IT provider what hardware they installed." }),
        q("firewall_make_model", "Firewall brand and model (if known)", "text", { helper: "A firewall is a device/software that protects your network from the internet. Example: FortiGate 100F. Leave blank if unknown." }),
        choice("static_public_ips", "Do you have fixed/public internet (static IP) addresses for your office?", ["Yes", "No", "Not sure"], { helper: "Yes / No. This is the address your office uses to connect to the internet, given by your Internet Service Provider (ISP). If yes, please share it - your ISP or IT vendor can provide this." }),
        q("cloud_public_addresses", "Are any cloud-hosted systems included, with their public addresses?", "textarea", { helper: "If any of your systems/website run on a cloud service (like AWS, Azure, Google Cloud) and have their own internet address, please share it if known." }),
        q("internet_address_type", "Is your internet address fixed or does it change automatically?", "text", { helper: "In simple terms: does your office internet address stay the same always (Static), or change from time to time (DHCP)? If it changes, roughly how often? Your internet provider or IT vendor will know this." }),
        q("dns_provider", "What service manages your website addresses (DNS provider)?", "text", { helper: "DNS is like the 'phonebook' of the internet that turns your website name into an address. Example: GoDaddy, Cloudflare, Google DNS. Ask whoever manages your website/domain if unsure." }),
      ],
    },
    {
      id: "computers_servers", title: "Computers, Laptops & Servers", description: "Company devices, servers, endpoints, and shared storage.",
      questions: [
        q("total_machines", "Total number of computers/machines in the whole company. Breakdown by type and OS, if known", "textarea", { helper: "A rough total count across the entire organization (not just the ones being tested). Example: 20 desktops, 15 laptops, 5 servers. Mention OS as well for these. Approximate numbers are fine." }),
        q("machines_in_scope", "How many of these will actually be tested in this project?", "text", { helper: "The number of machines that should be included in this specific security test." }),
        choice("asset_inventory", "Do you have a list of all your devices (an asset list)?", ["Yes", "No", "Will provide"], { helper: "Yes / No / Will provide. This is simply a list of computers/devices your company owns, if one exists." }),
        q("servers_in_scope", "Roughly how many servers are included in this test?", "text", { helper: "A server is a computer that runs shared services (like email, files, or a website) for your company." }),
        q("endpoints_by_os", "Roughly how many desktops/laptops are included, and what type (Windows/Mac/Linux)?", "textarea", { helper: "Example: 80 Windows laptops, 10 Apple (Mac) laptops, 5 Linux computers." }),
        q("asset_list_upload", "Upload the asset list", "asset_table", { required: true, helper: "Enter each in-scope asset in the table. Device: Laptop or Desktop. Device Type: Personal or Office. You can also download the Excel template." }),
        choice("nas_or_file_server", "Do you have a shared storage device or file server (NAS)?", ["Yes", "No", "Not sure"], { helper: "Yes / No. This is a device that stores shared company files, separate from individual computers. Share its address/name if you know it." }),
      ],
    },
    {
      id: "remote_access", title: "Remote / Work-from-Home Access", description: "VPN, remote devices, and remote test-account requirements.",
      questions: [
        choice("remote_vpn_used", "Do employees working from home connect to office systems using a VPN?", ["Yes", "No", "Not sure"], { helper: "A VPN is a secure private connection that lets remote/work-from-home staff safely reach office systems over the internet. Yes / No." }),
        q("vpn_service", "If yes, which VPN service/software is used?", "text", { helper: "Example: Cisco AnyConnect, FortiClient, OpenVPN. Ask your IT vendor if unsure." }),
        q("remote_vpn_range", "What address range is used for remote/work-from-home users on the VPN?", "text", { helper: "If known, provide the range of addresses assigned to people connecting remotely. Example: 10.10.50.10 to 10.10.50.100." }),
        choice("vpn_access_for_testing", "Will our testing team need VPN access to reach and test remote/WFH machines?", ["Yes", "No", "Not sure"], { helper: "Yes / No. If yes, we'll arrange the access details together with your IT contact." }),
        choice("separate_vpn_test_account", "If VPN access is needed, will a separate test account be created for us?", ["Yes", "No", "Not sure"], { helper: "Yes / No. Please do not write any passwords or login details in this sheet - these will be shared securely and separately." }),
        q("remote_machine_count", "Roughly how many remote/work-from-home machines does your company have?", "text", { helper: "An approximate number of laptops/computers used by staff working outside the office." }),
        choice("remote_machine_ownership", "Are these remote machines company-owned, personal (employee-owned), or a mix?", ["Company-owned", "Personal", "A mix", "Not sure"], { helper: "Let us know roughly how many fall into each category, if possible." }),
        q("remote_login_rules", "Any special login rules for our test account? (e.g. extra verification codes, or only certain addresses allowed)", "textarea", { helper: "This refers to things like two-step verification (MFA/OTP) or address restrictions on the VPN login. Mention anything your IT vendor has set up." }),
      ],
    },
    {
      id: "web_applications", title: "Websites & Online Applications", description: "Websites, applications, APIs, authentication, and protections.",
      questions: [
        q("websites_in_scope", "Which websites or web applications should be tested?", "textarea", { helper: "Give the name and web address (URL) of each site/app. Example: Company Website - www.example.com, HR Portal - hr.example.com." }),
        q("website_access_type", "Are these websites open to the public internet, only inside the office, or reachable only via VPN?", "text", { helper: "Just describe how each one is normally accessed - anyone on the internet, only office computers, or only after connecting via VPN." }),
        choice("staging_in_scope", "Are any test/practice versions included (staging, UAT, development)?", ["Yes", "No", "Not sure"], { helper: "Yes / No. These are 'draft' or 'testing' copies of a website used before it goes live. If yes, share their web address too." }),
        choice("web_login_required", "Do users need to log in (with a username/password) to use the website/app?", ["Yes", "No", "Not sure"], { helper: "Yes / No." }),
        q("web_login_method", "How do people log in?", "text", { helper: "Example: Username & Password, 'Sign in with Google/Microsoft' (SSO), or an extra verification code (MFA/2FA/OTP)." }),
        q("web_user_roles", "What types of user accounts exist on the website/app?", "text", { helper: "Example: Regular Employee, Manager, Administrator. Just list the different levels of access that exist." }),
        choice("web_test_accounts", "Will separate test accounts be created for each account type?", ["Yes", "No", "Not sure"], { helper: "Yes / No. Please do not write any usernames/passwords in this sheet." }),
        choice("web_mfa_enabled", "Is extra login verification (like an OTP/authenticator code) turned on for the test account?", ["Yes", "No", "Partially", "Not sure"], { helper: "Yes / No / Partially / Not Sure. If yes, let us know how we'll receive that code during testing (this can be worked out on the call)." }),
        choice("apis_in_scope", "Are there any APIs in scope (a way other software connects to your app)?", ["Yes", "No", "Not sure"], { helper: "Yes / No. An API lets other computer programs talk to your website/app automatically. If yes, share the web address if known - do not share any access keys here." }),
        choice("waf_or_security_service", "Is the website protected by any extra security service (e.g. Cloudflare) that might block our scan?", ["Yes", "No", "Not sure"], { helper: "Yes / No / Not Sure. Some websites use a protective service in front of them that can mistake our security test for an attack and block it. If you use one, let us know its name so it can allow our testing." }),
      ],
    },
    {
      id: "cloud_services", title: "Cloud Services", description: "Cloud platforms, systems, approvals, and access.",
      questions: [
        q("cloud_platforms", "Do you use any cloud computing service? (e.g. Amazon AWS, Microsoft Azure, Google Cloud)", "text", { helper: "Write 'None' if you don't use any cloud service." }),
        q("cloud_systems_in_scope", "Which cloud-based systems are included in this test?", "textarea", { helper: "Example: a website hosted online, an online server, cloud storage." }),
        q("cloud_provider_approval", "Does your cloud provider need to approve or be informed about security testing first?", "text", { helper: "Some cloud companies require permission before a security test is run on systems hosted with them. Write 'None / Not Sure' if you don't know." }),
        q("online_business_tools", "What other online business tools/platforms do you use?", "textarea", { helper: "Example: Google Workspace, an accounting/CRM/HR system, a remote-access tool." }),
        q("cloud_tools_mfa", "Is extra login verification (MFA/2FA) turned on for these tools?", "textarea", { helper: "Example: Google Workspace - Yes; Accounting Software - No." }),
        choice("cloud_admin_access", "Will any of these need admin-level (highest) access for our testing?", ["Yes", "No", "Not sure"], { helper: "Yes / No / Not Sure." }),
      ],
    },
    {
      id: "email_security", title: "Email Security", description: "Email platform, domain, and anti-phishing protection.",
      questions: [
        q("email_service", "What email service do you use?", "text", { helper: "Example: Microsoft 365 / Outlook, Google Workspace / Gmail, Zoho Mail." }),
        choice("email_domain_matches", "Is your email address the same as your main company website address?", ["Yes", "No", "Not sure"], { helper: "Example: website is company.com and email is name@company.com = Yes. If email is name@companymail.com instead = No." }),
        q("email_domains", "If different, what email address(es)/domain(s) do you use?", "text", { helper: "Example: companymail.com" }),
        q("email_security_protection", "Do you use any email security or anti-phishing protection?", "textarea", { helper: "Yes / No. This is a service that filters spam/scam emails before they reach your inbox. Give its name if known." }),
      ],
    },
    {
      id: "endpoint_protection", title: "Antivirus & Device Protection", description: "Antivirus, EDR/XDR, and endpoint coverage.",
      questions: [
        q("antivirus_solution", "What antivirus / protection software is installed on your computers?", "text", { helper: "Example: Microsoft Defender, Norton, Quick Heal, CrowdStrike, SentinelOne." }),
        q("edr_xdr_solution", "Is any advanced threat-monitoring software (EDR/XDR) installed?", "text", { helper: "This is a more advanced type of antivirus that actively watches for suspicious activity. Yes / No / Not Sure - give the name if known." }),
        q("protected_machine_count", "Roughly how many computers have this protection installed?", "text", { helper: "An approximate number or percentage of your machines that are protected." }),
      ],
    },
    {
      id: "company_directory", title: "Company Directory / Login System", description: "Centralized employee login and directory information.",
      questions: [
        choice("active_directory_used", "Do you use 'Active Directory' to manage employee logins centrally?", ["Yes", "No", "Not sure"], { helper: "This is a system many offices use so employees log into any office computer with one company account. Yes / No / Not Sure." }),
        q("directory_domain", "If yes, what is its domain name?", "text", { helper: "Example: company.local or company.com" }),
        q("domain_controller_count", "How many servers manage this login system (Domain Controllers)?", "text", { helper: "An approximate count. Example: 2." }),
        q("domain_controller_addresses", "What are the addresses of these login-management servers?", "text", { helper: "Example: 192.168.1.10, 192.168.1.11" }),
        choice("directory_in_scope", "Should this login system be included in the security test?", ["Yes", "No", "Not sure"], { helper: "Yes / No / Not Sure." }),
      ],
    },
    {
      id: "monitoring_access", title: "Monitoring & Access", description: "Monitoring tools and additional testing access.",
      questions: [
        q("siem_solution", "Do you use any centralized security-monitoring software (SIEM)?", "text", { helper: "This is software that collects alerts from across your systems in one place. Yes / No - name it if known." }),
        choice("temporary_monitoring_tool", "Can we install a temporary monitoring tool on the machines being tested?", ["Yes", "No", "Not sure"], { helper: "This small tool helps us record security-relevant activity during the test, and is removed afterward. Yes / No / Not Sure." }),
        q("additional_testing_access", "Will any extra login access be needed for our team to complete the testing?", "textarea", { helper: "Example: VPN, a jump server, or accounts for specific applications. Please do not write any passwords here - these are shared securely, separately." }),
      ],
    },
    {
      id: "safety_rules", title: "Safety & Rules of Engagement", description: "Systems to protect, backups, emergency contacts, and testing limits.",
      questions: [
        q("fragile_critical_systems", "Are there any systems that are old, fragile, or business-critical that we should be extra careful with (or avoid)?", "textarea", { helper: "Example: an old billing server that crashes easily, or a machine running 24x7 production. This helps us test safely without disrupting your business." }),
        choice("recent_backup", "Do you have a recent backup of the systems being tested, in case something needs to be restored?", ["Yes", "No", "Not sure"], { helper: "Yes / No / Not Sure. This is just a safety check - testing is done carefully, but it's good practice to have a recent backup beforehand." }),
        choice("avoid_dos_tests", "Should we avoid tests that could overload or crash a system (Denial-of-Service style tests)?", ["Yes - avoid", "No - may include", "Not sure"], { helper: "By default we avoid anything that could crash your systems unless you specifically ask us to include it. Yes (avoid) / No (can include) / Not Sure." }),
        q("emergency_contact", "Is there a separate emergency contact to reach if something unexpected happens during testing?", "text", { helper: "This can be the same as your technical contact, or someone else who can be reached quickly (including after office hours) if needed." }),
        q("third_party_permission", "Are any of the in-scope systems owned/managed by a third-party vendor who would also need to give permission?", "textarea", { helper: "Example: a website hosted by an outside web development company. If yes, please mention who they are - we may need their sign-off too." }),
      ],
    },
    {
      id: "scheduling_approval", title: "Scheduling & Approval", description: "Preferred dates, final approval, and required sign-offs.",
      questions: [
        q("preferred_testing_window", "When would you prefer the testing to happen? (dates & time window)", "text", { helper: "Example: 1-5 Sept, during office hours (10 AM - 6 PM)." }),
        q("testing_blackout_times", "Are there any dates/times we should avoid?", "textarea", { helper: "Example: month-end billing days, a big company event, festival holidays." }),
        q("final_testing_approver", "Who will give the final go-ahead/approval for this test?", "text", { helper: "Name, designation and email of the person authorized to approve the testing." }),
        q("approval_documents", "Are there any approval documents or sign-offs needed before we start?", "textarea", { helper: "Example: an authorization letter, or approval from a third-party vendor whose system is involved." }),
      ],
    },
  ];
  const QUESTION_SECTIONS = answerSections;

  const buildEmptyChecklistAnswers = () => {
    const result = {};
    QUESTION_SECTIONS.forEach((section) => {
      result[section.id] = {};
      section.questions.forEach((question) => {
        result[section.id][question.id] = {
          question: question.label,
          answer: "",
          na: false,
        };
      });
    });
    return result;
  };

  const normalizeChecklistAnswers = (source = {}) => {
    const normalized = buildEmptyChecklistAnswers();
    QUESTION_SECTIONS.forEach((section) => {
      const sectionData = source?.[section.id] || {};
      section.questions.forEach((question) => {
        const item = sectionData?.[question.id] || {};
        const attachment = item?.attachment;
        normalized[section.id][question.id] = {
          question: question.label,
          answer: typeof item.answer === "string" ? item.answer : "",
          na: Boolean(item.na),
          ...(Array.isArray(item.rows) ? { rows: item.rows } : {}),
          // Attachment metadata lives in the answer itself, so it must survive
          // normalization — otherwise every re-render would drop the upload.
          ...(attachment && attachment.id ? { attachment } : {}),
        };
      });
    });
    return normalized;
  };

  const extractPrimaryContactInfo = (value = "") => {
    const raw = String(value || "").trim();
    if (!raw) return { name: "", email: "" };

    const emailMatch = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    const email = emailMatch ? emailMatch[0] : "";
    const withoutEmail = email ? raw.replace(email, "").trim() : raw;
    const name = withoutEmail
      .replace(/[|/]/g, " ")
      .replace(/\s+/g, " ")
      .replace(/\s*:\s*$/, "")
      .trim();

    return { name: name || raw, email };
  };

  const syncDerivedOnboardingFields = useCallback((nextOnboarding) => {
    const generalAnswers = nextOnboarding?.checklist_answers?.company_details || {};
    const primaryContactAnswer = generalAnswers.primary_contact?.answer || "";
    const derivedContact = extractPrimaryContactInfo(primaryContactAnswer);
    const testingAuthorizationAnswer = generalAnswers.testing_authorization?.answer || "";

    const scopeIpRanges = nextOnboarding?.scope_ip_ranges || nextOnboarding?.checklist_answers?.internet_network?.internal_ip_ranges?.answer || "";
    const derived = {
      ...nextOnboarding,
      scope_ip_ranges: scopeIpRanges,
      authorization_confirmed: Boolean(nextOnboarding?.authorization_confirmed) || testingAuthorizationAnswer.toLowerCase() === "yes",
      tech_contact_name: nextOnboarding?.tech_contact_name || derivedContact.name || "",
      tech_contact_email: nextOnboarding?.tech_contact_email || derivedContact.email || "",
    };

    if (!derived.tech_contact_name && derivedContact.name) {
      derived.tech_contact_name = derivedContact.name;
    }
    if (!derived.tech_contact_email && derivedContact.email) {
      derived.tech_contact_email = derivedContact.email;
    }

    return derived;
  }, []);

  const getQuestionNumber = (sectionId, questionId) => {
    const section = QUESTION_SECTIONS.find((s) => s.id === sectionId);
    if (!section) return 0;
    const idx = section.questions.findIndex((q) => q.id === questionId);
    return idx >= 0 ? idx + 1 : section.questions.length;
  };

  const [emptyOnboarding] = useState(() => ({
    completed: false,
    review_status: "pending",
    review_note: "",
    review_flags: [],
    scope_ip_ranges: "",
    authorization_confirmed: false,
    tech_contact_name: "",
    tech_contact_email: "",
    tech_contact_phone: "",
    testing_window: "",
    testing_start_at: "",
    testing_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    out_of_scope_systems: "",
    checklist_answers: buildEmptyChecklistAnswers(),
  }));
  const [onboarding, setOnboarding] = useState(() => emptyOnboarding);
  const timezoneOptions = Array.from(new Set([Intl.DateTimeFormat().resolvedOptions().timeZone, "UTC", "Asia/Kolkata", "Asia/Dubai", "Asia/Singapore", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Australia/Sydney"].filter(Boolean)));
  const [hasScans, setHasScans] = useState(true);
  const [accessCode, setAccessCode] = useState("");
  const [accessName, setAccessName] = useState("");
  const [requestRegionCode, setRequestRegionCode] = useState("");
  const [requestRegionName, setRequestRegionName] = useState("");
  const [requestSubmitting, setRequestSubmitting] = useState(false);
  const [requestMessage, setRequestMessage] = useState("");
  const [checklistSubmitting, setChecklistSubmitting] = useState(false);
  const [checklistMessage, setChecklistMessage] = useState("");
  const [socReviewNote, setSocReviewNote] = useState("");
  // True while SOC has sent the checklist back for changes: only the flagged
  // items stay editable, everything else is locked (already reviewed).
  const [restrictToFlagged, setRestrictToFlagged] = useState(false);
  const [activeSection, setActiveSection] = useState("company_details");
  const [saveState, setSaveState] = useState("saved");
  const sectionNumberMap = Object.fromEntries(QUESTION_SECTIONS.map((section, index) => [section.id, index + 1]));

  const [currentUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("user") || "null");
    } catch {
      return null;
    }
  });
  // Only SOC analysts upload VAPT reports — platform admins manage users/approvals
  // and just view the library.
  const canUpload = Boolean(currentUser && currentUser.role === "soc_analyst");
  const libraryPath = "/admin/vapt-reports";
  const selectedOrg = orgs.find((o) => o.org_id === selectedOrgId) || null;
  // SOC flags for a "changes requested" review, keyed by `${section}::${question}`.
  // The client only needs to amend these items; everything else is preserved.
  const reviewFlagMap = Object.fromEntries(
    (onboarding?.review_flags || [])
      .filter((flag) => flag?.question_id)
      .map((flag) => [`${flag.section}::${flag.question_id}`, flag]),
  );
  const flagFor = (sectionId, questionId) => reviewFlagMap[`${sectionId}::${questionId}`];
  const clearFlaggedAnswers = (answers, flags) => {
    const nextAnswers = normalizeChecklistAnswers(answers || {});
    (flags || []).forEach((flag) => {
      const entry = nextAnswers?.[flag.section]?.[flag.question_id];
      if (!entry) return;
      entry.answer = "";
      entry.na = false;
      delete entry.attachment;
      delete entry.rows;
    });
    return nextAnswers;
  };
  // Locking only kicks in when SOC actually flagged something: a "more info"
  // request carrying only free-text remarks keeps the whole form editable.
  const lockUnflagged = restrictToFlagged && Object.keys(reviewFlagMap).length > 0;
  const isQuestionLocked = (sectionId, questionId) => lockUnflagged && !flagFor(sectionId, questionId);
  const clientAccessState = getClientVaptAccessState({
    vaptAccessEnabled: !!vaptAccessStatus.vapt_access_enabled,
    hasScans,
    onboarding: onboarding || emptyOnboarding,
  });

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token || canUpload) return;

    const DEFAULT_STATUS = { vapt_access_enabled: false, requested_regions: [], approved_regions: [], available_regions: [] };

    // Poll access status so that when the admin approves the request the user
    // sees the unlocked option immediately, without needing to reload the page.
    let cancelled = false;
    const fetchStatus = () => {
      getVaptAccessStatus(token)
        .then((status) => {
          if (cancelled) return;
          const normalized = status || DEFAULT_STATUS;
          setVaptAccessStatus((prev) =>
            JSON.stringify({
              enabled: prev.vapt_access_enabled,
              requested: prev.requested_regions || [],
              approved: prev.approved_regions || [],
              pending: prev.pending_regions || [],
            }) === JSON.stringify({
              enabled: normalized.vapt_access_enabled,
              requested: normalized.requested_regions || [],
              approved: normalized.approved_regions || [],
              pending: normalized.pending_regions || [],
            })
              ? prev
              : normalized,
          );
        })
        .catch(() => {
          // Keep the last known status on transient errors so an approved
          // user isn't flicked back to the request screen.
        });
    };

    fetchStatus();
    const intervalId = setInterval(fetchStatus, 15000);
    const onFocus = () => fetchStatus();
    window.addEventListener("focus", onFocus);
    return () => {
      cancelled = true;
      clearInterval(intervalId);
      window.removeEventListener("focus", onFocus);
    };
  }, [canUpload]);

  useEffect(() => {
    if (canUpload || typeof window === "undefined" || !window.WebSocket) return;
    const token = localStorage.getItem("token");
    const profile = JSON.parse(localStorage.getItem("user") || "null");
    if (!token || !profile?.org_id) return;
    const ws = new WebSocket(getWebSocketUrl(profile.org_id));
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (["vapt_access_reviewed", "vapt_region_reviewed", "vapt_initial_date_proposed", "vapt_initial_date_decided"].includes(message.event)) {
          getVaptAccessStatus(token).then((status) => setVaptAccessStatus(status || {})).catch(() => {});
          getVaptOnboarding(token).then((data) => setOnboarding((prev) => ({ ...prev, ...(data || {}) }))).catch(() => {});
        }
      } catch {
        // Ignore malformed realtime messages.
      }
    };
    return () => ws.close();
  }, [canUpload]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/auth", { replace: true });
    }
  }, [navigate]);

  // Detect user changes by watching the token - reset form when user logs out/in
  useEffect(() => {
    const handleStorageChange = () => {
      // When token changes (user logout/login), reset form data
      setOnboarding(emptyOnboarding);
      setRequestRegionCode("");
      setRequestRegionName("");
      setChecklistMessage("");
      setActiveSection("company_details");
      setSocReviewNote("");
    };
    
    // Listen for logout events
    window.addEventListener("logout", handleStorageChange);
    return () => window.removeEventListener("logout", handleStorageChange);
  }, [emptyOnboarding]);

  // Only fully approved clients can leave the onboarding flow for the report
  // library. If the checklist is incomplete or SOC has not approved it yet,
  // we stay on the VAPT onboarding/request screens to avoid the flicker loop.
  useEffect(() => {
    if (canUpload) return;

    const onboardingApproved = (onboarding?.review_status || "pending").toLowerCase() === "approved";
    const onboardingReady = Boolean(onboarding?.completed) && onboardingApproved;
    if (regionRequestMode || !vaptAccessStatus.vapt_access_enabled || !onboardingReady) return;

    navigate("/vapt/reports", { replace: true });
  }, [canUpload, onboarding, regionRequestMode, vaptAccessStatus.vapt_access_enabled, navigate]);

  // Check onboarding status for org users (not SOC analysts)
  useEffect(() => {
    if (canUpload) return; // SOC analysts skip onboarding
    const token = localStorage.getItem("token");
    if (!token) return;
    (async () => {
      try {
        const [onbData, scanData] = await Promise.all([
          getVaptOnboarding(token),
          getHasCompletedScans(token),
        ]);
        
        const nextOnboarding = {
          ...emptyOnboarding,
          ...(onbData || {}),
          testing_start_at: toDatetimeLocal(onbData?.testing_start_at),
          proposed_start_at: onbData?.proposed_start_at || "",
          proposed_end_at: onbData?.proposed_end_at || "",
          checklist_answers: normalizeChecklistAnswers((onbData || {}).checklist_answers),
        };

        // For rejected submissions, reset completed flag so user can resubmit
        if ((onbData?.review_status || "").toLowerCase() === "rejected") {
          nextOnboarding.completed = false;
          setActiveSection("company_details");
          setChecklistMessage("");
        }

        // Changes requested: answers are preserved, so land the client on the
        // first section SOC flagged instead of making them hunt for it.
        const orgChangesRequested = (onbData?.review_status || "").toLowerCase() === "changes_requested";
        if (orgChangesRequested) {
          nextOnboarding.checklist_answers = clearFlaggedAnswers(nextOnboarding.checklist_answers, onbData?.review_flags || []);
          const firstFlag = (onbData?.review_flags || []).find((flag) => flag?.section);
          if (firstFlag?.section) setActiveSection(firstFlag.section);
          setChecklistMessage("");
        }
        setRestrictToFlagged(orgChangesRequested);

        setOnboarding(nextOnboarding);
        setSocReviewNote((onbData || {})?.review_note || "");
        setHasScans(!!scanData?.has_completed_scans);

        // For region requests: if SOC sent this region's checklist back asking
        // for more information, prefill it and highlight the flagged items so
        // the client only fixes what is actually missing.
        if (regionRequestMode) {
          const status = await getVaptAccessStatus(token).catch(() => null);
          const pending = (status?.pending_regions || []).find(
            (region) => region.checklist_review_status === "changes_requested",
          );
          setRestrictToFlagged(Boolean(pending));
          if (pending) {
            const submission = pending.checklist_submission || {};
            setRequestRegionCode(pending.code || "");
            setRequestRegionName(pending.name || "");
            setSocReviewNote(pending.checklist_review_note || "");
            setOnboarding((prev) => ({
              ...prev,
              ...submission,
              checklist_answers: clearFlaggedAnswers(submission.checklist_answers || {}, pending.checklist_flags || []),
              testing_start_at: toDatetimeLocal(pending.testing_start_at) || prev.testing_start_at,
              testing_timezone: pending.testing_timezone || prev.testing_timezone,
              review_flags: pending.checklist_flags || [],
              completed: false,
              review_status: "pending",
            }));
            setActiveSection(pending.checklist_flags?.[0]?.section || "company_details");
          } else {
            setOnboarding((prev) => ({
              ...prev,
              checklist_answers: buildEmptyChecklistAnswers(),
              testing_start_at: "",
              testing_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
              completed: false,
              review_status: "pending",
              review_flags: [],
            }));
            setRequestRegionCode("");
            setRequestRegionName("");
            setActiveSection("company_details");
          }
          setChecklistMessage("");
        }
      } catch {
        // If onboarding endpoint doesn't exist yet, allow through
        setHasScans(true);
      }
    })();
  // These helpers are local form normalizers and intentionally use the initial render scope.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canUpload, regionRequestMode]);

  useEffect(() => {
    if (!canUpload) return;
    const token = localStorage.getItem("token");
    if (!token) return;
    Promise.all([getVaptOrganizations(token), getAdminVaptRescanRequests(token)])
      .then(([organizationData, scheduleData]) => {
        setOrgs(Array.isArray(organizationData) ? organizationData : []);
        setVerificationSchedules(
          (Array.isArray(scheduleData) ? scheduleData : []).filter((schedule) => schedule.status === "approved"),
        );
      })
      .catch(() => setOrgsError("Could not load organizations or approved rescans. Please try again."));
  }, [canUpload]);

  const submitVaptRequest = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token) return;
    const code = (accessCode || "").trim().toUpperCase();
    const name = (accessName || "").trim();
    if (!code || !name) {
      setRequestMessage("Please enter both the region code and region name (e.g. ACC-IND / Accenture India).");
      return;
    }
    setRequestSubmitting(true);
    setRequestMessage("");
    try {
      await requestVaptAccess([{ code, name }], token);
      const nextStatus = await getVaptAccessStatus(token);
      setVaptAccessStatus(nextStatus || { vapt_access_enabled: false, requested_regions: [], approved_regions: [], available_regions: [] });
      setAccessCode("");
      setAccessName("");
      setRequestMessage(`VAPT request for ${code} (${name}) has been submitted. Please wait for admin approval.`);
    } catch (err) {
      setRequestMessage(err?.message || "Unable to submit VAPT request.");
    } finally {
      setRequestSubmitting(false);
    }
  }, [accessCode, accessName]);

  const handleFile = useCallback((file) => {
    setUploadError("");
    const err = validateVaptFile(file);
    if (err) {
      setFileError(err);
      setSelectedFile(null);
      return;
    }
    setFileError("");
    setSelectedFile(file);
  }, []);

  const handleUpload = useCallback(async () => {
    if (!selectedFile || isUploading) return;
    if (!selectedVerificationSchedule && !selectedOrgId) {
      setUploadError("Please select the organization this report belongs to.");
      return;
    }
    if (!selectedVerificationSchedule && !selectedRegion) {
      setUploadError("Please select the assessment region for this report.");
      return;
    }
    const token = localStorage.getItem("token");
    if (!token) return;

    setIsUploading(true);
    setUploadError("");
    setProgressMsg("Parsing, scoring and normalizing findings…");
    try {
      const result = selectedVerificationSchedule
        ? await uploadVaptVerificationReport(selectedFile, selectedVerificationSchedule, token, verificationDisplayName)
        : await uploadVaptReport(selectedFile, token, selectedOrgId, selectedRegion);
      setPreview(result);
      setProgressMsg("");
    } catch (err) {
      setUploadError(err?.message || "Upload failed. Please try again.");
      setProgressMsg("");
    } finally {
      setIsUploading(false);
    }
  }, [selectedFile, isUploading, selectedOrgId, selectedRegion, selectedVerificationSchedule, verificationDisplayName]);

  const handleDownloadPdf = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token || !preview) return;
    try {
      if (canUpload) {
        // Staff publish to any org, so download via the platform-scoped endpoint
        // (the org-scoped one is gated by VAPT approval and would 403/404 here).
        await downloadVaptReportAdmin(preview.import_id, token);
      } else {
        await downloadVaptReport(preview.import_id, token);
      }
    } catch (err) {
      setUploadError(err?.message || "Failed to download the PDF report.");
    }
  }, [preview, canUpload]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (regionRequestMode || !token || !onboarding || !onboarding.checklist_answers) return;
    const timer = setTimeout(async () => {
      try {
        await updateVaptOnboarding(onboarding, token);
        setSaveState("saved");
      } catch {
        setSaveState("error");
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [onboarding, regionRequestMode]);

  if (!canUpload && vaptAccessStatus.vapt_blocked) {
    return (
      <div className="mx-auto max-w-2xl rounded-[2rem] border border-red-200 bg-white p-8 shadow-sm dark:border-red-900 dark:bg-slate-900">
        <div className="mb-6 flex items-center gap-3">
          <span className="material-symbols-outlined text-red-600 dark:text-red-400">block</span>
          <span className="text-xs font-black uppercase tracking-[0.28em] text-red-700 dark:text-red-400">VAPT access</span>
        </div>
        <h2 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">VAPT access blocked</h2>
        <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">
          Your admin has blocked VAPT access for this account. Contact your admin if you believe
          this is a mistake.
        </p>
      </div>
    );
  }

  if (!canUpload && clientAccessState === "approval_required") {
    return (
      <div className="mx-auto max-w-2xl rounded-[2rem] border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 flex items-center gap-3">
          <span className="material-symbols-outlined text-purple-600">fact_check</span>
          <span className="text-xs font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">VAPT access</span>
        </div>
        <h2 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">VAPT access is not enabled</h2>
        <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">
          An administrator must approve VAPT access for your account before you can use this module. Contact your administrator.
        </p>
      </div>
    );
  }

  if (!canUpload && clientAccessState === "region_required") {
    return (
      <div className="mx-auto max-w-2xl rounded-[2rem] border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 flex items-center gap-3">
          <span className="material-symbols-outlined text-purple-600">fact_check</span>
          <span className="text-xs font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">VAPT access</span>
        </div>
        <h2 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">Request VAPT access</h2>
        <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">
          Your account does not have an approved region yet. Request the region you need, then wait for your admin or SOC team to approve it — the onboarding checklist unlocks once your region is approved.
        </p>

        <div className="mt-6 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <label htmlFor="vapt-access-code" className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                Region code
              </label>
              <input
                id="vapt-access-code"
                type="text"
                value={accessCode}
                onChange={(e) => setAccessCode(e.target.value.toUpperCase())}
                placeholder="e.g. ACC-IND"
                className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 font-mono text-sm font-semibold uppercase tracking-wide text-slate-900 outline-none transition placeholder:font-sans placeholder:font-normal placeholder:normal-case placeholder:text-slate-400 focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="vapt-access-name" className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                Region name
              </label>
              <input
                id="vapt-access-name"
                type="text"
                value={accessName}
                onChange={(e) => setAccessName(e.target.value)}
                placeholder="e.g. Accenture India"
                className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
              />
            </div>
          </div>
          <p className="text-xs leading-5 text-slate-500 dark:text-slate-400">
            Code: <b className="text-slate-700 dark:text-slate-200">first 3 letters of your company</b> +{" "}
            <b className="text-slate-700 dark:text-slate-200">“-”</b> + <b className="text-slate-700 dark:text-slate-200">region</b>. You type both the code and
            the name yourself — nothing is preset. Example: <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] font-bold text-purple-700 dark:bg-slate-800 dark:text-purple-300">ACC-IND</code>{" "}
            / <b className="text-slate-700 dark:text-slate-200">Accenture India</b>. Once submitted, the request is sent to your admin for approval.
          </p>

          <button
            type="button"
            onClick={submitVaptRequest}
            disabled={requestSubmitting || !(accessCode || "").trim() || !(accessName || "").trim()}
            className="inline-flex items-center justify-center rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 px-5 py-3 text-sm font-bold text-white shadow-lg shadow-purple-500/15 transition hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {requestSubmitting ? "Submitting request..." : "Send request"}
          </button>

          {requestMessage && (
            <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300">
              {requestMessage}
            </div>
          )}

          {(vaptAccessStatus.requested_regions || []).length > 0 && !vaptAccessStatus.vapt_access_enabled && (
            <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300">
              Current request: <span className="font-bold">{(vaptAccessStatus.requested_regions || []).join(", ")}</span>
            </div>
          )}
        </div>
      </div>
    );
  }

  const dist = preview?.severity_distribution || {};
  const totalReal = preview?.total_findings ?? 0;
  const summary = preview?.summary || {};
  const excludedInfo = summary.excluded_info_findings ?? 0;
  const rawParsed = summary.raw_findings_parsed ?? 0;
  const riskMeta = riskTone(preview?.risk_score ?? 0);

  const previewRows = (preview?.findings || []).slice(0, 12);
  // A question marked `required: false` is recorded when answered but never
  // blocks the submission. An upload question counts as answered once a file is
  // attached (or the client marks it N/A).
  const isQuestionProvided = (question, entry) => {
    if (entry?.na) return true;
    if (question?.type === "asset_table") {
      return Boolean(entry?.attachment?.id) || (Array.isArray(entry?.rows) && entry.rows.some((row) => Object.values(row || {}).some((value) => String(value || "").trim())));
    }
    if (String(entry?.answer ?? "").trim()) return true;
    return question?.type === "upload" && Boolean(entry?.attachment?.id);
  };
  const requiredQuestionsOf = (section) => section.questions.filter((question) => !question.hidden && question.required !== false);
  const totalChecklistItems = QUESTION_SECTIONS.reduce((sum, section) => sum + requiredQuestionsOf(section).length, 0);
  const answeredChecklistCount = QUESTION_SECTIONS.reduce((sum, section) => {
    const sectionAnswers = normalizeChecklistAnswers(onboarding.checklist_answers || {})[section.id] || {};
    return sum + requiredQuestionsOf(section).filter((question) => isQuestionProvided(question, sectionAnswers[question.id])).length;
  }, 0);
  const allChecklistComplete = answeredChecklistCount >= totalChecklistItems;
  const flaggedQuestionsComplete = Object.keys(reviewFlagMap).every((key) => {
    const [sectionId, questionId] = key.split("::");
    const question = QUESTION_SECTIONS.find((section) => section.id === sectionId)?.questions.find((item) => item.id === questionId);
    const entry = onboarding.checklist_answers?.[sectionId]?.[questionId];
    return question && !entry?.na && isQuestionProvided(question, entry);
  });

  const requiredFieldsComplete = [
    onboarding.testing_start_at,
    onboarding.testing_timezone,
  ].every((value) => value !== "" && value != null);
  const canSubmitChecklist = allChecklistComplete && requiredFieldsComplete && flaggedQuestionsComplete;

  // ── Onboarding checklist for first-time org users ──
  const attachmentKey = (sectionId, questionId) => `${sectionId}::${questionId}`;

  const handleAttachmentSelected = async (sectionId, question, file) => {
    if (!file || isQuestionLocked(sectionId, question.id)) return;
    const key = attachmentKey(sectionId, question.id);
    setAttachmentState((prev) => ({ ...prev, [key]: { uploading: true, error: "" } }));
    try {
      const meta = await uploadVaptChecklistAttachment(
        file,
        {
          sectionId,
          questionId: question.id,
          regionCode: regionRequestMode ? (requestRegionCode || "").trim().toUpperCase() : "",
        },
        localStorage.getItem("token"),
      );
      setOnboarding((prev) => {
        const nextAnswers = normalizeChecklistAnswers(prev.checklist_answers || {});
        nextAnswers[sectionId] = { ...(nextAnswers[sectionId] || {}) };
        nextAnswers[sectionId][question.id] = {
          ...(nextAnswers[sectionId][question.id] || {}),
          answer: meta?.filename || file.name,
          na: false,
          attachment: meta,
        };
        return syncDerivedOnboardingFields({ ...prev, checklist_answers: nextAnswers });
      });
      setAttachmentState((prev) => ({ ...prev, [key]: { uploading: false, error: "" } }));
      setSaveState("saving");
    } catch (err) {
      setAttachmentState((prev) => ({
        ...prev,
        [key]: { uploading: false, error: err?.message || "Upload failed. Please try again." },
      }));
    }
  };

  const handleAssetTemplateDownload = async () => {
    try {
      await downloadVaptAssetListTemplate(localStorage.getItem("token"));
    } catch (err) {
      setChecklistMessage(err?.message || "Unable to download the asset list template.");
    }
  };

  const handleAttachmentRemove = async (sectionId, question) => {
    if (isQuestionLocked(sectionId, question.id)) return;
    const attachmentId = normalizeChecklistAnswers(onboarding.checklist_answers || {})[sectionId]?.[question.id]?.attachment?.id;
    setOnboarding((prev) => {
      const nextAnswers = normalizeChecklistAnswers(prev.checklist_answers || {});
      nextAnswers[sectionId] = { ...(nextAnswers[sectionId] || {}) };
      const { attachment: _removed, ...rest } = nextAnswers[sectionId][question.id] || {};
      nextAnswers[sectionId][question.id] = { ...rest, answer: "", na: false };
      return syncDerivedOnboardingFields({ ...prev, checklist_answers: nextAnswers });
    });
    setSaveState("saving");
    if (!attachmentId) return;
    try {
      await deleteVaptChecklistAttachment(attachmentId, localStorage.getItem("token"));
    } catch {
      // The reference is already gone locally; a stale server copy is harmless.
    }
  };

  const updateQuestionAnswer = (sectionId, questionId, value, na = false) => {
    if (isQuestionLocked(sectionId, questionId)) return;
    setOnboarding((prev) => {
      const nextAnswers = normalizeChecklistAnswers(prev.checklist_answers || {});
      nextAnswers[sectionId] = { ...(nextAnswers[sectionId] || {}) };
      nextAnswers[sectionId][questionId] = {
        ...(nextAnswers[sectionId][questionId] || {}),
        answer: value,
        na,
      };
      return syncDerivedOnboardingFields({ ...prev, checklist_answers: nextAnswers });
    });
    setSaveState("saving");
  };

  const updateAssetRows = (sectionId, questionId, rows) => {
    const meaningfulRows = rows.filter((row) => Object.values(row || {}).some((value) => String(value || "").trim()));
    setOnboarding((prev) => {
      const nextAnswers = normalizeChecklistAnswers(prev.checklist_answers || {});
      nextAnswers[sectionId] = { ...(nextAnswers[sectionId] || {}) };
      nextAnswers[sectionId][questionId] = {
        ...(nextAnswers[sectionId][questionId] || {}),
        answer: meaningfulRows.length ? JSON.stringify(meaningfulRows) : "",
        na: false,
        rows,
      };
      return syncDerivedOnboardingFields({ ...prev, checklist_answers: nextAnswers });
    });
    setSaveState("saving");
  };

  const toggleNa = (sectionId, questionId) => {
    if (isQuestionLocked(sectionId, questionId)) return;
    const current = onboarding.checklist_answers?.[sectionId]?.[questionId];
    const isNa = !current?.na;
    updateQuestionAnswer(sectionId, questionId, isNa ? "N/A" : "", isNa);
  };

  const getSectionProgress = (section) => {
    const sectionAnswers = normalizeChecklistAnswers(onboarding.checklist_answers || {})[section.id] || {};
    const requiredQuestions = requiredQuestionsOf(section);
    const total = requiredQuestions.length;
    if (total === 0) return { answered: 0, total: 0, percent: 0 };
    const answered = requiredQuestions.filter((question) => isQuestionProvided(question, sectionAnswers[question.id])).length;
    return {
      answered,
      total,
      percent: Math.round((answered / total) * 100),
    };
  };

  const handleSubmitOnboarding = async () => {
    const token = localStorage.getItem("token");
    if (!token) return;

    const regionCode = (requestRegionCode || "").trim().toUpperCase();
    const regionName = (requestRegionName || "").trim();
    if (!regionCode || !regionName) {
      setChecklistMessage("Please add the region code and region name before submitting the checklist.");
      return;
    }

    const derivedScopeIpRanges = onboarding.scope_ip_ranges || onboarding.checklist_answers?.internet_network?.internal_ip_ranges?.answer || "";
    const derivedPrimaryContact = extractPrimaryContactInfo(onboarding.checklist_answers?.company_details?.primary_contact?.answer || "");
    const derivedAuthorizationConfirmed = Boolean(onboarding.authorization_confirmed);
    const requiredFields = {
      testing_start_at: onboarding.testing_start_at,
      testing_timezone: onboarding.testing_timezone,
    };

    const missing = Object.entries(requiredFields).filter(([, value]) => value === "" || value === false || value == null);
    const normalizedAnswers = normalizeChecklistAnswers(onboarding.checklist_answers || {});
    const unansweredQuestion = QUESTION_SECTIONS.flatMap((section) =>
      section.questions.map((question) => ({ ...question, sectionId: section.id })),
    ).find((question) => {
      const entry = normalizedAnswers?.[question.sectionId]?.[question.id];
      return question.required !== false && !isQuestionProvided(question, entry);
    });

    if (missing.length > 0) {
      setChecklistMessage(`Please complete the required fields: ${missing.map(([field]) => field.replaceAll("_", " ")).join(", ")}.`);
      return;
    }

    if (unansweredQuestion) {
      setChecklistMessage("Please answer every mandatory question before submitting the form.");
      return;
    }

    if (!flaggedQuestionsComplete) {
      setChecklistMessage("Update every SOC-flagged question before submitting the form.");
      return;
    }

    const payload = {
      scope_ip_ranges: derivedScopeIpRanges,
      authorization_confirmed: derivedAuthorizationConfirmed,
      tech_contact_name: onboarding.tech_contact_name || derivedPrimaryContact.name || "",
      tech_contact_email: onboarding.tech_contact_email || derivedPrimaryContact.email || "",
      tech_contact_phone: onboarding.tech_contact_phone,
      testing_window: onboarding.testing_window,
      testing_start_at: new Date(onboarding.testing_start_at).toISOString(),
      testing_timezone: onboarding.testing_timezone,
      out_of_scope_systems: onboarding.out_of_scope_systems,
      checklist_answers: normalizedAnswers,
    };

      // An additional region carries its own checklist so SOC reviews the region
      // and the checklist together. The initial region follows the same combined
      // request path after the administrator grants account access.
    if (regionRequestMode) {
      setChecklistSubmitting(true);
      setChecklistMessage("");
      try {
        await requestVaptRegion({
          region_code: regionCode,
          region_name: regionName,
          ...payload,
        }, token);
        setVaptAccessStatus(await getVaptAccessStatus(token));
        // Flags are resolved by this submission, so unlock the form again.
        setOnboarding((prev) => ({ ...prev, review_flags: [] }));
        setRestrictToFlagged(false);
        setChecklistMessage("The new region request and its checklist have been submitted. SOC will review them together.");
      } catch (err) {
        setChecklistMessage(err?.message || "Unable to submit the region request. Please try again.");
      } finally {
        setChecklistSubmitting(false);
      }
      return;
    }

    setChecklistSubmitting(true);
    setChecklistMessage("");
    try {
      // Initial access approval unlocks this form; the region and checklist
      // are submitted together for the administrator's review.
      const response = await requestVaptAccess([{ code: regionCode, name: regionName }], token, payload);
      setOnboarding((prev) => ({
        ...prev,
        ...payload,
        completed: true,
        review_status: "pending",
      }));
      if (response) {
        setVaptAccessStatus(response);
      }
      setChecklistMessage("Your checklist and region request have been submitted. The administrator will review them together.");
    } catch (err) {
      setChecklistMessage(err?.message || "Unable to submit the checklist. Please try again.");
    } finally {
      setChecklistSubmitting(false);
    }
  };

  if (!canUpload && regionRequestMode && clientAccessState === "allowed") {
    return (
      <div className="mx-auto max-w-2xl rounded-[2rem] border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 flex items-center justify-between gap-4">
          <span className="material-symbols-outlined text-purple-600">public</span>
          <button
            type="button"
            onClick={() => navigate("/vapt/reports")}
            aria-label="Back to VAPT reports"
            title="Back to VAPT reports"
            className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-3 py-2 text-sm font-bold text-blue-700 shadow-sm transition hover:border-blue-400 hover:bg-blue-100 dark:border-blue-800 dark:bg-blue-950/40 dark:text-blue-300"
          >
            <ArrowLeft size={16} aria-hidden="true" />
            <span>Back to reports</span>
          </button>
        </div>
        <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100 sm:text-3xl">Request New Region</h2>
        <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">Request an additional testing region without repeating the organization onboarding checklist.</p>
        <div className="mt-8 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <label htmlFor="request-region-code" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Region code</label>
              <input id="request-region-code" type="text" value={requestRegionCode} onChange={(e) => setRequestRegionCode(e.target.value.toUpperCase())} placeholder="e.g. ACC-SG" className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 font-mono text-sm uppercase dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100" />
            </div>
            <div className="space-y-2">
              <label htmlFor="request-region-name" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Region name</label>
              <input id="request-region-name" type="text" value={requestRegionName} onChange={(e) => setRequestRegionName(e.target.value)} placeholder="e.g. Singapore" className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100" />
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <label htmlFor="region-testing-start-at" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Testing start</label>
              <input id="region-testing-start-at" type="datetime-local" value={onboarding.testing_start_at || ""} onChange={(e) => setOnboarding((prev) => ({ ...prev, testing_start_at: e.target.value }))} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100" />
            </div>
            <div className="space-y-2">
              <label htmlFor="region-testing-timezone" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Timezone</label>
              <select id="region-testing-timezone" value={onboarding.testing_timezone || "UTC"} onChange={(e) => setOnboarding((prev) => ({ ...prev, testing_timezone: e.target.value }))} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100">
                {timezoneOptions.map((timezone) => <option key={timezone} value={timezone}>{timezone}</option>)}
              </select>
            </div>
          </div>
          <button type="button" onClick={handleSubmitOnboarding} disabled={checklistSubmitting || !(requestRegionCode || "").trim() || !(requestRegionName || "").trim() || !onboarding.testing_start_at} className="inline-flex items-center justify-center rounded-xl bg-purple-600 px-5 py-3 text-sm font-bold text-white shadow-lg shadow-purple-500/15 transition hover:bg-purple-700 disabled:cursor-not-allowed disabled:opacity-50">
            {checklistSubmitting ? "Submitting request..." : "Request region"}
          </button>
          {checklistMessage && <div className="rounded-xl border border-violet-200 bg-violet-50 px-4 py-3 text-sm text-violet-800 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-200">{checklistMessage}</div>}
        </div>
      </div>
    );
  }

  if (!canUpload && clientAccessState === "checklist_required") {
    return (
      <div className="mx-auto max-w-2xl rounded-[2rem] border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 flex items-center justify-between gap-4">
          <span className="material-symbols-outlined text-purple-600">fact_check</span>
          <button
            type="button"
            onClick={() => navigate(regionRequestMode ? "/vapt/reports" : "/scan-dashboard")}
            aria-label={regionRequestMode ? "Back to VAPT reports" : "Back to dashboard"}
            title={regionRequestMode ? "Back to VAPT reports" : "Back to dashboard"}
            className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-3 py-2 text-sm font-bold text-blue-700 shadow-sm transition hover:border-blue-400 hover:bg-blue-100 focus:outline-none focus:ring-2 focus:ring-blue-200 dark:border-blue-800 dark:bg-blue-950/40 dark:text-blue-300 dark:hover:border-blue-600 dark:hover:bg-blue-900/60 dark:focus:ring-blue-900"
          >
            <ArrowLeft size={16} aria-hidden="true" />
            <span>{regionRequestMode ? "Back to reports" : "Back to dashboard"}</span>
          </button>
        </div>
        <h2 className="break-words text-2xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100 sm:text-3xl">{regionRequestMode ? "Request New Region" : "VAPT Onboarding Checklist"}</h2>
        <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">
          {regionRequestMode
            ? socReviewNote
              ? "Only the items SOC flagged below can be edited — everything else is locked and already reviewed. Fix the flagged items and resubmit."
              : "Complete the VAPT form again for this region. SOC will review the region, checklist, and testing start together."
            : onboarding.review_status === "changes_requested"
              ? "Only the items SOC flagged below can be edited — everything else is locked and already reviewed. Fix the flagged items and resubmit."
              : "Complete this one-time checklist so your security team knows how to scope and schedule your first scan."}
        </p>

        <div className="mt-8 space-y-6">
          <div className="rounded-2xl border border-violet-200 bg-violet-50 px-4 py-3 text-sm text-violet-800 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-200">
            This intake is structured by section so it stays manageable. Progress saves automatically as you go, and you can return later without losing work.
          </div>

          {socReviewNote && (regionRequestMode || onboarding.review_status === "rejected" || onboarding.review_status === "changes_requested") && (
            <div
              className={`rounded-xl border px-4 py-3 text-sm ${
                onboarding.review_status === "rejected" && !regionRequestMode
                  ? "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
                  : "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300"
              }`}
            >
              <p className="font-bold">
                {onboarding.review_status === "rejected" && !regionRequestMode ? "SOC review feedback" : "SOC requested more information"}
              </p>
              <p className="mt-1 whitespace-pre-wrap">{socReviewNote}</p>
            </div>
          )}

          <div className="mx-auto w-full max-w-6xl rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="mb-5 grid gap-4 rounded-2xl border border-violet-200 bg-violet-50 p-4 dark:border-violet-900 dark:bg-violet-950/30 md:grid-cols-2">
              {regionRequestMode ? (
                <>
                  <div className="space-y-2">
                    <label htmlFor="request-region-code" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Region code</label>
                    <input
                      id="request-region-code"
                      type="text"
                      value={requestRegionCode}
                      onChange={(e) => setRequestRegionCode(e.target.value.toUpperCase())}
                      placeholder="e.g. ACC-IND"
                      className="w-full rounded-xl border border-violet-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-violet-900 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-violet-500 dark:focus:ring-violet-900/40"
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="request-region-name" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Region name</label>
                    <input
                      id="request-region-name"
                      type="text"
                      value={requestRegionName}
                      onChange={(e) => setRequestRegionName(e.target.value)}
                      placeholder="e.g. Accenture India"
                      className="w-full rounded-xl border border-violet-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-violet-900 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-violet-500 dark:focus:ring-violet-900/40"
                    />
                  </div>
                </>
              ) : (
                <>
                  <div className="space-y-2">
                    <label htmlFor="initial-region-code" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Region code</label>
                    <input
                      id="initial-region-code"
                      type="text"
                      value={requestRegionCode}
                      onChange={(e) => setRequestRegionCode(e.target.value.toUpperCase())}
                      placeholder="e.g. ACC-IND"
                      className="w-full rounded-xl border border-violet-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-violet-900 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500"
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="initial-region-name" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Region name</label>
                    <input
                      id="initial-region-name"
                      type="text"
                      value={requestRegionName}
                      onChange={(e) => setRequestRegionName(e.target.value)}
                      placeholder="e.g. Accenture India"
                      className="w-full rounded-xl border border-violet-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-violet-900 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500"
                    />
                  </div>
                </>
              )}
              <div className="space-y-2">
                <label htmlFor="testing-start-at" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Testing start</label>
                <input id="testing-start-at" type="datetime-local" value={onboarding.testing_start_at || ""} onChange={(e) => setOnboarding((prev) => ({ ...prev, testing_start_at: e.target.value }))} className="w-full rounded-xl border border-violet-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-violet-900 dark:bg-slate-950 dark:text-slate-100" />
              </div>
              <div className="space-y-2">
                <label htmlFor="testing-timezone" className="text-sm font-semibold text-slate-700 dark:text-slate-300">Timezone</label>
                <select id="testing-timezone" value={onboarding.testing_timezone || "UTC"} onChange={(e) => setOnboarding((prev) => ({ ...prev, testing_timezone: e.target.value }))} className="w-full rounded-xl border border-violet-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-violet-900 dark:bg-slate-950 dark:text-slate-100">
                  {timezoneOptions.map((timezone) => <option key={timezone} value={timezone}>{timezone}</option>)}
                </select>
              </div>
            </div>
            <div className="mb-5 rounded-2xl border border-slate-200 bg-slate-50/90 p-4 shadow-sm dark:border-slate-700 dark:bg-slate-950/40">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-[10px] font-black uppercase tracking-[0.22em] text-slate-500 dark:text-slate-400">Progress</p>
                  <p className="mt-1 text-sm font-semibold text-slate-800 dark:text-slate-100">
                    {Object.values(onboarding.checklist_answers || {}).reduce((total, section) => total + Object.values(section || {}).length, 0)} fields across {QUESTION_SECTIONS.length} sections
                  </p>
                </div>
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-600 dark:text-slate-300">
                  <span className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1.5 text-emerald-700 shadow-sm dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400">
                    <span className="text-[11px]">{saveState === "saved" ? "✓" : saveState === "saving" ? "•" : "↻"}</span>
                    {saveState === "saved" ? "Saved" : saveState === "saving" ? "Saving..." : "Try again"}
                  </span>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <nav aria-label="VAPT checklist sections" className="w-full rounded-[1.75rem] border border-slate-200 bg-gradient-to-b from-slate-50 to-white p-4 shadow-[0_10px_30px_rgba(15,23,42,0.04)] dark:border-slate-700 dark:from-slate-900 dark:to-slate-950">
                <div className="relative">
                  <div className="absolute left-5 right-5 top-5 hidden h-0.5 bg-slate-200 md:block dark:bg-slate-700" />
                  <div className="grid grid-cols-2 gap-x-2 gap-y-4 sm:grid-cols-4 md:grid-cols-7">
                    {QUESTION_SECTIONS.map((section) => {
                      const progress = getSectionProgress(section);
                      const isActive = activeSection === section.id;
                      const isComplete = progress.answered === progress.total && progress.total > 0;
                      return (
                        <button
                          key={section.id}
                          type="button"
                          onClick={() => setActiveSection(section.id)}
                          aria-current={isActive ? "step" : undefined}
                          className="group relative flex min-w-0 flex-col items-center gap-2 text-center"
                        >
                          <span className="relative z-10 flex h-10 w-10 items-center justify-center rounded-full border-2 text-sm font-black transition-all duration-200 md:h-11 md:w-11">
                            <span className={`flex h-full w-full items-center justify-center rounded-full ${isActive ? "bg-gradient-to-br from-blue-600 to-indigo-600 text-white shadow-lg shadow-blue-600/20 ring-4 ring-blue-100 dark:ring-blue-900/30" : isComplete ? "border-emerald-500 bg-emerald-50 text-emerald-700 dark:border-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-300" : "border-slate-300 bg-white text-slate-500 group-hover:border-blue-400 group-hover:text-blue-600 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-300 dark:group-hover:border-blue-500 dark:group-hover:text-blue-300"}`}>
                              {isComplete ? "✓" : sectionNumberMap[section.id]}
                            </span>
                          </span>
                          <span className={`max-w-[92px] text-[10px] font-bold leading-[1.2] tracking-wide ${isActive ? "text-blue-700 dark:text-blue-300" : isComplete ? "text-emerald-700 dark:text-emerald-300" : "text-slate-600 dark:text-slate-300"}`}>
                            {section.title}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              </nav>

              <div className="space-y-5">
                {QUESTION_SECTIONS.filter((section) => section.id === activeSection).map((section) => {
                  const currentSectionIndex = QUESTION_SECTIONS.findIndex((s) => s.id === activeSection);
                  const isLastSection = currentSectionIndex === QUESTION_SECTIONS.length - 1;
                  return (
                  <div key={section.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-950/40">
                    <div className="mb-4 flex items-center justify-between gap-3">
                      <div>
                        <p className="text-[11px] font-black uppercase tracking-[0.2em] text-violet-700 dark:text-violet-400">{sectionNumberMap[section.id]}. {section.title}</p>
                        <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{section.description}</p>
                      </div>
                      <div className="rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.15em] text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
                        {getSectionProgress(section).answered}/{getSectionProgress(section).total}
                      </div>
                    </div>

                    <div className="space-y-4">
                      {(() => {
                        const visibleQuestions = section.questions.filter((question) => !question.hidden);
                        const twoColumnQuestions = [];
                        const fullWidthQuestions = visibleQuestions;

                        return (
                          <>
                            {twoColumnQuestions.length > 0 && (
                              <div className="grid gap-4 md:grid-cols-2">
                                {twoColumnQuestions.map((question) => {
                                  const condition = question.condition;
                                  const isVisible = !condition || onboarding.checklist_answers?.[condition.sectionId]?.[condition.field]?.answer === condition.value;
                                  if (!isVisible) return null;
                                  const entry = onboarding.checklist_answers?.[section.id]?.[question.id] || { answer: "", na: false };
                                  const baseClass = "w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 shadow-sm outline-none transition placeholder:text-slate-400 focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-violet-500 dark:focus:ring-violet-900/30";
                                  const wrapClass = "rounded-xl border border-slate-200 bg-white p-3 shadow-[0_2px_8px_rgba(15,23,42,0.04)] transition hover:-translate-y-px hover:shadow-md focus-within:border-l-4 focus-within:border-l-violet-500 focus-within:pl-[11px] dark:border-slate-700 dark:bg-slate-900 dark:shadow-none dark:hover:shadow-lg dark:hover:shadow-black/20";

                                  return (
                                    <div key={question.id} className={flagFor(section.id, question.id) ? `${wrapClass} border-amber-300 ring-2 ring-amber-200 dark:border-amber-800 dark:ring-amber-900/50` : isQuestionLocked(section.id, question.id) ? `${wrapClass} opacity-70` : wrapClass}>
                                      <div className="mb-2 flex items-center justify-between gap-3">
                                        <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">
                                          <span className="inline-flex items-center gap-1.5">
                                            <span className="text-violet-700 dark:text-violet-300">{getQuestionNumber(section.id, question.id)}.</span>
                                            <span>{question.label}</span>
                                            {question.required !== false && <span className="text-red-500">*</span>}
                                          </span>
                                        </label>
                                        <button
                                          type="button"
                                          onClick={() => toggleNa(section.id, question.id)}
                                          disabled={isQuestionLocked(section.id, question.id)}
                                          title={isQuestionLocked(section.id, question.id) ? "Already reviewed — only flagged items can be edited" : undefined}
                                          className={`rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.15em] disabled:cursor-not-allowed disabled:opacity-40 ${entry.na ? "border-slate-700 bg-slate-800 text-white dark:border-slate-200 dark:bg-slate-100 dark:text-slate-900" : "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300"}`}
                                        >
                                          N/A
                                        </button>
                                      </div>

                                      {question.helper && (
                                        <p className="mb-2 text-[11px] leading-5 text-slate-500 dark:text-slate-400">{question.helper}</p>
                                      )}

                                      {flagFor(section.id, question.id) && (
                                        <p className="mb-2 rounded-lg border border-amber-300 bg-amber-50 px-2.5 py-1.5 text-[11px] font-semibold text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300">
                                          SOC requested more information
                                          {flagFor(section.id, question.id)?.note ? `: ${flagFor(section.id, question.id).note}` : " for this item"}.
                                        </p>
                                      )}

                                      {question.type === "choice" ? (
                                        <>
                                          <ChoiceChipGroup
                                            options={question.options}
                                            value={entry.answer}
                                            disabled={isQuestionLocked(section.id, question.id)}
                                            onChange={(option) => updateQuestionAnswer(section.id, question.id, option, false)}
                                          />
                                          {question.id === "network_diagram" && entry.answer === "Yes" && (() => {
                                            const uploadQuestion = section.questions.find((item) => item.inlineFor === question.id);
                                            const uploadState = uploadQuestion && attachmentState[attachmentKey(section.id, uploadQuestion.id)];
                                            if (!uploadQuestion) return null;
                                            return (
                                              <div className="mt-3 rounded-xl border border-dashed border-violet-300 bg-violet-50/70 p-3 dark:border-violet-800 dark:bg-violet-950/30">
                                                <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-violet-300 bg-white px-3 py-2 text-xs font-bold text-violet-700 transition hover:bg-violet-100 dark:border-violet-700 dark:bg-slate-900 dark:text-violet-300 dark:hover:bg-violet-950/60">
                                                  <FileUp size={15} />
                                                  {uploadState?.uploading ? "Uploading..." : onboarding.checklist_answers?.[section.id]?.[uploadQuestion.id]?.attachment?.filename || "Upload network diagram"}
                                                  <input
                                                    type="file"
                                                    accept={uploadQuestion.accept}
                                                    className="hidden"
                                                    disabled={uploadState?.uploading || isQuestionLocked(section.id, question.id)}
                                                    onChange={(event) => {
                                                      handleAttachmentSelected(section.id, uploadQuestion, event.target.files?.[0]);
                                                      event.target.value = "";
                                                    }}
                                                  />
                                                </label>
                                                <p className="mt-2 text-[11px] text-slate-500 dark:text-slate-400">PDF, PNG or JPG. Optional if the diagram is not available.</p>
                                                {uploadState?.error && <p className="mt-2 text-xs font-semibold text-red-600">{uploadState.error}</p>}
                                              </div>
                                            );
                                          })()}
                                        </>
                                      ) : (
                                        <input
                                          type="text"
                                          value={entry.na ? "N/A" : entry.answer}
                                          disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                          onChange={(e) => updateQuestionAnswer(section.id, question.id, e.target.value, false)}
                                          className={baseClass}
                                          placeholder={question.example || "Type answer"}
                                        />
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            )}

                            {fullWidthQuestions.length > 0 && (
                              <div className="space-y-4">
                                {fullWidthQuestions.map((question) => {
                                  const condition = question.condition;
                                  const isVisible = !condition || onboarding.checklist_answers?.[condition.sectionId]?.[condition.field]?.answer === condition.value;
                                  if (!isVisible) return null;
                                  const entry = onboarding.checklist_answers?.[section.id]?.[question.id] || { answer: "", na: false };
                                  const baseClass = "w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 shadow-sm outline-none transition placeholder:text-slate-400 focus:border-violet-400 focus:ring-2 focus:ring-violet-100 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-violet-500 dark:focus:ring-violet-900/30";
                                  const wrapClass = "rounded-xl border border-slate-200 bg-white p-3 shadow-[0_2px_8px_rgba(15,23,42,0.04)] transition hover:-translate-y-px hover:shadow-md focus-within:border-l-4 focus-within:border-l-violet-500 focus-within:pl-[11px] dark:border-slate-700 dark:bg-slate-900 dark:shadow-none dark:hover:shadow-lg dark:hover:shadow-black/20";

                                  return (
                                    <div key={question.id} className={flagFor(section.id, question.id) ? `${wrapClass} border-amber-300 ring-2 ring-amber-200 dark:border-amber-800 dark:ring-amber-900/50` : isQuestionLocked(section.id, question.id) ? `${wrapClass} opacity-70` : wrapClass}>
                                      <div className="mb-2 flex items-center justify-between gap-3">
                                        <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">
                                          <span className="inline-flex items-center gap-1.5">
                                            <span className="text-violet-700 dark:text-violet-300">{getQuestionNumber(section.id, question.id)}.</span>
                                            <span>{question.label}</span>
                                            {question.required !== false && <span className="text-red-500">*</span>}
                                          </span>
                                        </label>
                                        <button
                                          type="button"
                                          onClick={() => toggleNa(section.id, question.id)}
                                          disabled={isQuestionLocked(section.id, question.id)}
                                          title={isQuestionLocked(section.id, question.id) ? "Already reviewed — only flagged items can be edited" : undefined}
                                          className={`rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.15em] disabled:cursor-not-allowed disabled:opacity-40 ${entry.na ? "border-slate-700 bg-slate-800 text-white dark:border-slate-200 dark:bg-slate-100 dark:text-slate-900" : "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300"}`}
                                        >
                                          N/A
                                        </button>
                                      </div>

                                      {question.helper && (
                                        <p className="mb-2 text-[11px] leading-5 text-slate-500 dark:text-slate-400">{question.helper}</p>
                                      )}

                                      {flagFor(section.id, question.id) && (
                                        <p className="mb-2 rounded-lg border border-amber-300 bg-amber-50 px-2.5 py-1.5 text-[11px] font-semibold text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300">
                                          SOC requested more information
                                          {flagFor(section.id, question.id)?.note ? `: ${flagFor(section.id, question.id).note}` : " for this item"}.
                                        </p>
                                      )}

                                      {question.type === "choice" ? (
                                        <>
                                          <ChoiceChipGroup
                                            options={question.options}
                                            value={entry.answer}
                                            disabled={isQuestionLocked(section.id, question.id)}
                                            onChange={(option) => updateQuestionAnswer(section.id, question.id, option, false)}
                                          />
                                          {question.id === "network_diagram" && entry.answer === "Yes" && (() => {
                                            const uploadQuestion = section.questions.find((item) => item.inlineFor === question.id);
                                            const uploadState = uploadQuestion && attachmentState[attachmentKey(section.id, uploadQuestion.id)];
                                            if (!uploadQuestion) return null;
                                            return (
                                              <div className="mt-3 rounded-xl border border-dashed border-violet-300 bg-violet-50/70 p-3 dark:border-violet-800 dark:bg-violet-950/30">
                                                <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-violet-300 bg-white px-3 py-2 text-xs font-bold text-violet-700 transition hover:bg-violet-100 dark:border-violet-700 dark:bg-slate-900 dark:text-violet-300">
                                                  <FileUp size={15} />
                                                  {uploadState?.uploading ? "Uploading..." : onboarding.checklist_answers?.[section.id]?.[uploadQuestion.id]?.attachment?.filename || "Upload network diagram"}
                                                  <input type="file" accept={uploadQuestion.accept} className="hidden" disabled={uploadState?.uploading || isQuestionLocked(section.id, question.id)} onChange={(event) => { handleAttachmentSelected(section.id, uploadQuestion, event.target.files?.[0]); event.target.value = ""; }} />
                                                </label>
                                                <p className="mt-2 text-[11px] text-slate-500 dark:text-slate-400">PDF, PNG or JPG. Optional if the diagram is not available.</p>
                                                {uploadState?.error && <p className="mt-2 text-xs font-semibold text-red-600">{uploadState.error}</p>}
                                              </div>
                                            );
                                          })()}
                                        </>
                                      ) : question.type === "asset_table" ? (
                                        <div className="space-y-3">
                                          <div className="flex flex-wrap items-center gap-2">
                                            <button
                                              type="button"
                                              onClick={handleAssetTemplateDownload}
                                              className="inline-flex items-center gap-2 rounded-xl border border-emerald-300 bg-emerald-50 px-3 py-2 text-xs font-semibold text-emerald-700 hover:bg-emerald-100 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                                            >
                                              <FileSpreadsheet size={15} /> Open Excel template
                                            </button>
                                            <label className="inline-flex cursor-pointer items-center gap-2 rounded-xl border border-violet-300 bg-violet-50 px-3 py-2 text-xs font-semibold text-violet-700 hover:bg-violet-100 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300">
                                              <FileUp size={15} /> Upload Excel/PDF
                                              <input
                                                type="file"
                                                accept=".xlsx,.xls,.csv,.pdf"
                                                className="hidden"
                                                disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                                onChange={(event) => {
                                                  handleAttachmentSelected(section.id, question, event.target.files?.[0]);
                                                  event.target.value = "";
                                                }}
                                              />
                                            </label>
                                          </div>
                                          {entry.attachment?.id && (
                                            <p className="flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-semibold text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">
                                              <CheckCircle2 size={14} /> {entry.attachment.filename}
                                            </p>
                                          )}
                                          <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700">
                                          <table className="min-w-[1060px] w-full text-left text-xs">
                                            <thead className="bg-slate-100 text-[10px] font-black uppercase tracking-[0.12em] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                                              <tr>
                                                {ASSET_COLUMNS.map((column) => <th key={column.key} className="whitespace-nowrap px-2 py-2">{column.label}</th>)}
                                                <th className="px-2 py-2"> </th>
                                              </tr>
                                            </thead>
                                            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                                              {(entry.rows?.length ? entry.rows : [{}]).map((row, rowIndex) => (
                                                <tr key={`${question.id}-${rowIndex}`} className="bg-white dark:bg-slate-950">
                                                  {ASSET_COLUMNS.map((column) => (
                                                    <td key={column.key} className="p-1.5 align-top">
                                                      {column.options ? (
                                                        <select
                                                          value={row[column.key] || ""}
                                                          disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                                          onChange={(event) => {
                                                            const rows = [...(entry.rows?.length ? entry.rows : [{}])];
                                                            rows[rowIndex] = { ...rows[rowIndex], [column.key]: event.target.value };
                                                            updateAssetRows(section.id, question.id, rows);
                                                          }}
                                                          className="w-full min-w-[105px] rounded-lg border border-slate-200 bg-white px-2 py-2 text-xs dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                                                        >
                                                          <option value="">Select</option>
                                                          {column.options.map((option) => <option key={option} value={option}>{option}</option>)}
                                                        </select>
                                                      ) : (
                                                        <input
                                                          value={row[column.key] || ""}
                                                          disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                                          onChange={(event) => {
                                                            const rows = [...(entry.rows?.length ? entry.rows : [{}])];
                                                            rows[rowIndex] = { ...rows[rowIndex], [column.key]: event.target.value };
                                                            updateAssetRows(section.id, question.id, rows);
                                                          }}
                                                          className="w-full min-w-[105px] rounded-lg border border-slate-200 bg-white px-2 py-2 text-xs dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                                                          placeholder={column.label}
                                                        />
                                                      )}
                                                    </td>
                                                  ))}
                                                  <td className="p-1.5 align-top">
                                                    <button
                                                      type="button"
                                                      disabled={entry.na || isQuestionLocked(section.id, question.id) || (entry.rows?.length || 0) <= 1}
                                                      onClick={() => updateAssetRows(section.id, question.id, (entry.rows || [{}]).filter((_, index) => index !== rowIndex))}
                                                      className="rounded-lg border border-red-200 px-2 py-2 text-[10px] font-bold text-red-600 disabled:opacity-40"
                                                    >
                                                      Remove
                                                    </button>
                                                  </td>
                                                </tr>
                                              ))}
                                            </tbody>
                                          </table>
                                          <button
                                            type="button"
                                            disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                            onClick={() => updateAssetRows(section.id, question.id, [...(entry.rows || [{}]), {}])}
                                            className="m-2 rounded-lg border border-violet-300 bg-violet-50 px-3 py-2 text-xs font-semibold text-violet-700 disabled:opacity-50 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300"
                                          >
                                            Add asset row
                                          </button>
                                          </div>
                                        </div>
                                      ) : question.type === "upload" ? (
                                        <div className="space-y-2">
                                          <div className="flex flex-wrap items-center gap-2">
                                            <label className={`inline-flex items-center justify-center gap-2 rounded-xl border border-violet-300 bg-violet-50 px-4 py-2 text-sm font-semibold text-violet-700 transition hover:bg-violet-100 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300 ${entry.na || isQuestionLocked(section.id, question.id) || attachmentState[attachmentKey(section.id, question.id)]?.uploading ? "cursor-not-allowed opacity-60" : "cursor-pointer"}`}>
                                              {attachmentState[attachmentKey(section.id, question.id)]?.uploading ? <Loader2 size={16} className="animate-spin" /> : <FileUp size={16} />}
                                              {attachmentState[attachmentKey(section.id, question.id)]?.uploading ? "Uploading…" : "Choose file"}
                                              <input
                                                type="file"
                                                accept={question.accept}
                                                className="hidden"
                                                disabled={entry.na || isQuestionLocked(section.id, question.id) || attachmentState[attachmentKey(section.id, question.id)]?.uploading}
                                                onChange={(event) => {
                                                  handleAttachmentSelected(section.id, question, event.target.files?.[0]);
                                                  event.target.value = "";
                                                }}
                                              />
                                            </label>
                                            {entry.attachment?.id && !isQuestionLocked(section.id, question.id) && (
                                              <button
                                                type="button"
                                                onClick={() => handleAttachmentRemove(section.id, question)}
                                                className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
                                              >
                                                Remove file
                                              </button>
                                            )}
                                          </div>

                                          {entry.attachment?.id ? (
                                            <p className="flex flex-wrap items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-semibold text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">
                                              <CheckCircle2 size={14} /> {entry.attachment.filename}
                                              {typeof entry.attachment.size_bytes === "number" ? ` (${Math.max(1, Math.round(entry.attachment.size_bytes / 1024))} KB)` : ""}
                                            </p>
                                          ) : (
                                            <p className="text-[11px] font-semibold uppercase tracking-[0.15em] text-slate-500 dark:text-slate-400">
                                              {question.required === false ? "Optional — upload a file" : "Required — upload a file, or mark N/A and explain by email"}
                                            </p>
                                          )}

                                          {attachmentState[attachmentKey(section.id, question.id)]?.error && (
                                            <p className="rounded-lg border border-red-200 bg-red-50 px-2.5 py-1.5 text-[11px] font-semibold text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
                                              {attachmentState[attachmentKey(section.id, question.id)].error}
                                            </p>
                                          )}
                                        </div>
                                      ) : question.type === "textarea" ? (
                                        <textarea
                                          rows={2}
                                          value={entry.na ? "N/A" : entry.answer}
                                          disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                          onChange={(e) => updateQuestionAnswer(section.id, question.id, e.target.value, false)}
                                          className={`${baseClass} min-h-[74px] resize-y`}
                                          placeholder={question.example || "Provide details"}
                                        />
                                      ) : question.type === "table" ? (
                                        <div className="space-y-3">
                                          <textarea
                                            rows={3}
                                            value={entry.na ? "N/A" : entry.answer}
                                            disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                            onChange={(e) => updateQuestionAnswer(section.id, question.id, e.target.value, false)}
                                            className={`${baseClass} min-h-[90px] resize-y`}
                                            placeholder={question.example || "Add rows as needed for each asset / platform entry."}
                                          />
                                        </div>
                                      ) : (
                                        <input
                                          type="text"
                                          value={entry.na ? "N/A" : entry.answer}
                                          disabled={entry.na || isQuestionLocked(section.id, question.id)}
                                          onChange={(e) => updateQuestionAnswer(section.id, question.id, e.target.value, false)}
                                          className={baseClass}
                                          placeholder={question.example || "Type answer"}
                                        />
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>

                    <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-4 dark:border-slate-700">
                      <button
                        type="button"
                        onClick={() => {
                          const currentIndex = QUESTION_SECTIONS.findIndex((s) => s.id === activeSection);
                          if (currentIndex > 0) {
                            setActiveSection(QUESTION_SECTIONS[currentIndex - 1].id);
                          }
                        }}
                        disabled={QUESTION_SECTIONS.findIndex((s) => s.id === activeSection) === 0}
                        className="inline-flex items-center justify-center rounded-xl border border-slate-300 bg-white px-5 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
                      >
                        ← Previous
                      </button>

                      {isLastSection ? (
                        <button
                          type="button"
                          onClick={handleSubmitOnboarding}
                          disabled={checklistSubmitting || !canSubmitChecklist}
                          title={canSubmitChecklist ? "Submit checklist for SOC review" : "Complete all required fields before submitting"}
                          className="inline-flex items-center justify-center rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 px-5 py-2.5 text-sm font-bold text-white shadow-lg shadow-purple-500/15 transition hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {checklistSubmitting ? "Submitting checklist..." : "Submit checklist"}
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => {
                            const currentIndex = QUESTION_SECTIONS.findIndex((s) => s.id === activeSection);
                            if (currentIndex < QUESTION_SECTIONS.length - 1) {
                              setActiveSection(QUESTION_SECTIONS[currentIndex + 1].id);
                            }
                          }}
                          className="inline-flex items-center justify-center rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 px-5 py-2.5 text-sm font-bold text-white shadow-lg shadow-purple-500/15 transition hover:opacity-95"
                        >
                          Next →
                        </button>
                      )}
                    </div>
                  </div>
                  );
                })}
              </div>

              {checklistMessage && (
                <div className="rounded-xl border border-violet-200 bg-violet-50 px-4 py-3 text-sm text-violet-800 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-200">
                  {checklistMessage}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!canUpload && clientAccessState === "pending_soc_review") {
    return (
      <div className="flex min-h-screen items-center justify-center p-6 text-slate-900 dark:text-slate-100">
        <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <p className="text-sm leading-6 text-slate-700 dark:text-slate-200">Your VAPT checklist has been submitted. The SOC team will review it before your reports are unlocked.</p>
          {onboarding.proposed_start_at && onboarding.proposed_end_at && (
            <div className="mt-5 rounded-xl border border-sky-200 bg-sky-50 p-4 text-left text-sm text-sky-900 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-200">
              <p className="font-bold">SOC proposed a different testing window</p>
              <p className="mt-1">{new Date(onboarding.proposed_start_at).toLocaleString()} to {new Date(onboarding.proposed_end_at).toLocaleString()} ({onboarding.proposed_timezone})</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <button type="button" onClick={async () => { await decideInitialVaptDate((vaptAccessStatus.pending_regions?.[0]?.code || ""), { decision: "accepted" }, localStorage.getItem("token")); }} className="rounded-lg bg-emerald-600 px-3 py-2 text-xs font-bold text-white">Accept date</button>
                <button type="button" onClick={async () => { await decideInitialVaptDate((vaptAccessStatus.pending_regions?.[0]?.code || ""), { decision: "rejected", note: "Please propose another first-scan window." }, localStorage.getItem("token")); }} className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-xs font-bold text-amber-700">Reject date</button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-[1400px] px-4 py-8 sm:px-6 lg:px-10">
        {/* ── Page header ── */}
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">file_upload</span>
              <span className="text-[11px] font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
                VAPT Report Import
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl">
              Import a scanner report
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500 dark:text-slate-400">
              Turn Nessus / OpenVAS / Qualys / generic export files into detailed,
              normalized, shareable security reports.
            </p>
          </div>
          <Link
            to={libraryPath}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 shadow-sm transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
          >
            <Database size={16} />
            Report Library
          </Link>
        </div>

        {!preview ? (
          <>
            {/* ── Drop zone ── */}
            <DropZone onFile={handleFile} error={fileError} isUploading={isUploading} />

            {/* ── Publish-to organization picker (SOC analysts / admins) ── */}
            <div className="mx-auto mt-5 max-w-3xl rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
              {canUpload && verificationSchedules.length > 0 && (
                <div className="mb-5 rounded-xl border border-sky-200 bg-sky-50 p-4 dark:border-sky-900 dark:bg-sky-950/30">
                  <label htmlFor="vapt-verification-schedule" className="mb-2 block text-xs font-black uppercase tracking-[0.2em] text-sky-700 dark:text-sky-300">
                    Manual verification upload
                  </label>
                  <select
                    id="vapt-verification-schedule"
                    value={selectedVerificationSchedule}
                    onChange={(e) => {
                      const scheduleId = e.target.value;
                      setSelectedVerificationSchedule(scheduleId);
                      if (!scheduleId) {
                        setVerificationDisplayName("");
                        return;
                      }
                      // A verification belongs to the organization and region of the
                      // report it retests, so surface both as soon as it is picked.
                      const schedule = verificationSchedules.find((s) => s.id === scheduleId);
                      if (!schedule) return;
                      setVerificationDisplayName(schedule.display_name || "");
                      const orgId = schedule.org_id || "";
                      setSelectedOrgId(orgId);
                      const org = orgs.find((o) => o.org_id === orgId);
                      const firstRegion = (org?.approved_regions || [])[0];
                      const fallbackRegion =
                        typeof firstRegion === "string" ? firstRegion : firstRegion?.code || "";
                      setSelectedRegion(schedule.region || fallbackRegion);
                    }}
                    className="w-full rounded-xl border border-sky-200 bg-white px-3 py-2.5 text-sm text-slate-800 outline-none transition focus:border-sky-400 focus:ring-2 focus:ring-sky-200 dark:border-sky-800 dark:bg-slate-900 dark:text-slate-100"
                  >
                    <option value="">Upload an initial report</option>
                    {verificationSchedules.map((schedule) => (
                      <option key={schedule.id} value={schedule.id}>
                        Verification · {schedule.display_name || schedule.file_name || schedule.import_id} · {new Date(schedule.scheduled_at).toLocaleString()}
                      </option>
                    ))}
                  </select>
                  <p className="mt-2 text-xs text-sky-700 dark:text-sky-300">
                    Select the approved rescan to attach the SOC retest export. This upload completes that manual verification.
                  </p>
                  {selectedVerificationSchedule && (
                    <div className="mt-4">
                      <label htmlFor="vapt-verification-name" className="mb-2 block text-xs font-black uppercase tracking-[0.2em] text-sky-700 dark:text-sky-300">
                        Report name
                      </label>
                      <input
                        id="vapt-verification-name"
                        type="text"
                        value={verificationDisplayName}
                        onChange={(e) => setVerificationDisplayName(e.target.value)}
                        maxLength={120}
                        placeholder="e.g. Q3 re-validation — Mumbai"
                        className="w-full rounded-xl border border-sky-200 bg-white px-3 py-2.5 text-sm text-slate-800 outline-none transition focus:border-sky-400 focus:ring-2 focus:ring-sky-200 dark:border-sky-800 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-sky-500 dark:focus:ring-sky-900/40"
                      />
                      <p className="mt-2 text-xs text-sky-700 dark:text-sky-300">
                        Appears as the report title and in the download filename. Leave blank for the default name.
                      </p>
                    </div>
                  )}
                </div>
              )}
              <label htmlFor="vapt-target-org" className="mb-2 block text-xs font-black uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">
                Publish to organization
              </label>
              <select
                id="vapt-target-org"
                value={selectedOrgId}
                onChange={(e) => {
                  const orgId = e.target.value;
                  setSelectedVerificationSchedule("");
                  setSelectedOrgId(orgId);
                  const org = orgs.find((o) => o.org_id === orgId);
                  const regions = org?.approved_regions || [];
                  const firstRegion = regions[0];
                  setSelectedRegion(typeof firstRegion === "string" ? firstRegion : firstRegion?.code || "");
                }}
                disabled={Boolean(selectedVerificationSchedule)}
                className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-800 outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
              >
                <option value="">Select an organization…</option>
                {orgs.map((org) => (
                  <option key={org.org_id} value={org.org_id}>
                    {org.domain || org.org_id}
                  </option>
                ))}
              </select>
              {orgsError && (
                <p className="mt-2 text-xs font-semibold text-red-600 dark:text-red-400">{orgsError}</p>
              )}
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                The finished report is published to this organization — its users see it read-only.
              </p>

              <div className="mt-4">
                <label htmlFor="vapt-target-region" className="mb-2 block text-xs font-black uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">
                  Assessment region
                </label>
                <select
                  id="vapt-target-region"
                  value={selectedRegion}
                  onChange={(e) => setSelectedRegion(e.target.value)}
                  disabled={!selectedOrgId || Boolean(selectedVerificationSchedule)}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-800 outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
                >
                  {!selectedOrgId ? (
                    <option value="">Select an organization first…</option>
                  ) : (selectedOrg?.approved_regions || []).length === 0 ? (
                    <option value="">No approved regions for this organization</option>
                  ) : (
                    (selectedOrg?.approved_regions || []).map((region) => {
                      const code = typeof region === "string" ? region : region.code;
                      const name = typeof region === "string" ? "" : region.name;
                      return (
                        <option key={code} value={code}>
                          {code}{name ? ` - ${name}` : ""}
                        </option>
                      );
                    })
                  )}
                </select>
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  The region the assessment was performed in. The organization's users see reports
                  filtered by their approved regions.
                </p>
              </div>
            </div>

            {selectedFile && !fileError && (
              <div className="mx-auto mt-5 flex max-w-3xl flex-col items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900 sm:flex-row">
                <div className="flex min-w-0 items-center gap-3">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-purple-50 text-purple-600 dark:bg-purple-950/40 dark:text-purple-400">
                    <FileUp size={18} />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-bold text-slate-800 dark:text-slate-200">{selectedFile.name}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {formatBytes(selectedFile.size)} · ready to import
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleUpload}
                  disabled={isUploading}
                  className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-purple-600 px-5 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95 disabled:opacity-50"
                >
                  {isUploading ? (
                    <>
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                      {progressMsg || "Uploading…"}
                    </>
                  ) : (
                    <>
                      <Zap size={15} />
                      {selectedVerificationSchedule ? "Upload verification" : "Import & Score"}
                    </>
                  )}
                </button>
              </div>
            )}

            {uploadError && (
              <div
                className={`mx-auto mt-5 flex max-w-3xl items-start gap-3 rounded-2xl border px-5 py-4 text-sm ${
                  uploadError.startsWith("Network error")
                    ? "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-400"
                    : "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
                }`}
              >
                {uploadError.startsWith("Network error") ? (
                  <WifiOff size={18} className="mt-0.5 shrink-0" />
                ) : (
                  <XCircle size={18} className="mt-0.5 shrink-0" />
                )}
                <div>
                  <p className="font-bold">
                    {uploadError.startsWith("Network error")
                      ? "Cannot reach the import server"
                      : "Import failed"}
                  </p>
                  <p className="mt-1 opacity-90">{uploadError}</p>
                </div>
              </div>
            )}

            {/* ── What's included ── */}
            <div className="mt-12">
              <div className="mb-5 flex items-center gap-2">
                <Activity size={16} className="text-purple-600 dark:text-purple-400" />
                <h2 className="text-sm font-black uppercase tracking-[0.22em] text-slate-600 dark:text-slate-300">
                  What's included
                </h2>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <CapabilityCard
                  icon={<ShieldAlert size={18} />}
                  title="Real issues only"
                  description="Informational entries are excluded automatically so the risk score and report focus on real vulnerabilities."
                />
                <CapabilityCard
                  icon={<Layers size={18} />}
                  title="Smart consolidation"
                  description="The same vulnerability found on many hosts is reported once, with the full list of affected addresses and a host count."
                />
                <CapabilityCard
                  icon={<FileText size={18} />}
                  title="Nessus-style PDF"
                  description="A professional PDF with a cover page, severity banners, CVSS metadata, NVD-linked CVEs and proof-of-concept sections."
                />
                <CapabilityCard
                  icon={<Server size={18} />}
                  title="Auto-categorization"
                  description="Every finding is classified into Web App, TLS/SSL, DNS, Network, Mail Security, OS/Host or Application."
                />
                <CapabilityCard
                  icon={<Globe size={18} />}
                  title="Format detection"
                  description="Flexible header matching auto-detects Nessus, OpenVAS, Qualys and generic CSV / Excel exports."
                />
                <CapabilityCard
                  icon={<Lock size={18} />}
                  title="Passive & secure"
                  description="XXE-safe parsing, 25 MB limit, extension whitelist, and org-scoped storage — no active scanning."
                />
              </div>
            </div>
          </>
        ) : (
          <>
            {/* ── Preview ── */}
            <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 size={22} className="text-emerald-500" />
                <div>
                  <h2 className="text-lg font-bold">Import complete — parse preview</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {preview.file_name} · {formatSource(preview.source_tool)} · imported {fmtDate(preview.created_at)}
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={handleDownloadPdf}
                  className="inline-flex items-center gap-2 rounded-xl border border-purple-200 bg-white px-4 py-2.5 text-sm font-bold text-purple-700 shadow-sm transition hover:bg-purple-50 active:scale-95 dark:border-purple-800 dark:bg-slate-900 dark:text-purple-400 dark:hover:bg-purple-950/30"
                >
                  <Download size={15} /> Download PDF
                </button>
                <Link
                  to={`/admin/vapt-reports/${preview.import_id}`}
                  className="inline-flex items-center gap-2 rounded-xl bg-purple-600 px-4 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95"
                >
                  <Eye size={15} /> View Full Report
                </Link>
                <button
                  type="button"
                  onClick={() => { setPreview(null); setSelectedFile(null); }}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-600 shadow-sm transition hover:border-slate-300 hover:text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"
                >
                  <ArrowLeft size={15} /> Import another
                </button>
              </div>
            </div>

            {/* Stat cards */}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              <StatCard
                label="Risk Score"
                value={preview.risk_score ?? 0}
                icon={<Activity size={20} />}
                tone={{
                  border: "border-slate-200 dark:border-slate-800",
                  iconBg: riskMeta.iconBg,
                  text: riskMeta.text,
                }}
                sub="/ 100"
              />
              <StatCard
                label="Severity"
                value={preview.severity ? severityMeta(preview.severity).label : "None"}
                icon={<ShieldAlert size={20} />}
                tone={{ text: riskMeta.text, border: "border-slate-200 dark:border-slate-800" }}
              />
              <StatCard label="Real Findings" value={totalReal} icon={<Layers size={20} />} tone={{}} />
              <StatCard label="Unique Hosts" value={preview.unique_hosts ?? 0} icon={<Globe size={20} />} tone={{}} />
              <StatCard
                label="Info Excluded"
                value={excludedInfo}
                icon={<Info size={20} />}
                tone={excludedInfo > 0 ? { text: "text-amber-600 dark:text-amber-400" } : {}}
                sub={`of ${rawParsed} raw entries`}
              />
            </div>

            {/* Transparency note */}
            <div className="mt-4 flex flex-wrap items-center gap-3 rounded-2xl border border-slate-200 bg-white px-5 py-3.5 text-sm shadow-sm dark:border-slate-800 dark:bg-slate-900">
              <Info size={16} className="shrink-0 text-sky-500" />
              <span className="text-slate-600 dark:text-slate-300">
                <b className="text-slate-900 dark:text-slate-100">{rawParsed}</b> raw entries parsed ·{" "}
                <b className="text-slate-900 dark:text-slate-100">{excludedInfo}</b> informational findings excluded ·{" "}
                <b className="text-slate-900 dark:text-slate-100">{totalReal}</b> real findings reported.
              </span>
            </div>

            {/* Severity distribution */}
            <div className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
              <h3 className="mb-4 text-sm font-bold text-slate-800 dark:text-slate-200">Severity distribution</h3>
              <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
                {SEVERITY_ORDER.map((sev) => {
                  const count = dist[sev] || 0;
                  const meta = severityMeta(sev);
                  const pct = totalReal ? Math.round((100 * count) / totalReal) : 0;
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <span className={`w-16 shrink-0 text-xs font-bold ${meta.text}`}>{meta.label}</span>
                      <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                        <div
                          className={`h-full rounded-full ${meta.bar} transition-all duration-700`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="w-14 shrink-0 text-right text-xs font-bold text-slate-700 dark:text-slate-300">
                        {count} <span className="font-medium text-slate-400">({pct}%)</span>
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Preview table */}
            <div className="mt-6 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4 dark:border-slate-800">
                <h3 className="text-sm font-bold text-slate-800 dark:text-slate-200">
                  Findings preview <span className="font-medium text-slate-400">({preview.findings?.length || 0} normalized)</span>
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 bg-slate-50/70 text-left dark:border-slate-800 dark:bg-slate-800/50">
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">#</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Severity</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Title</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Hosts</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">CVSS</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Category</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {previewRows.map((f) => (
                      <tr key={f.id} className="transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="px-6 py-3.5 font-mono text-xs text-slate-400">{f.id}</td>
                        <td className="px-6 py-3.5"><SeverityBadge severity={f.severity_label} /></td>
                        <td className="max-w-[340px] truncate px-6 py-3.5 font-semibold text-slate-800 dark:text-slate-200" title={f.title}>{f.title}</td>
                        <td className="px-6 py-3.5 text-slate-600 dark:text-slate-300">
                          {f.host_count > 1 ? (
                            <span className="inline-flex items-center gap-1 font-bold text-purple-600 dark:text-purple-400">
                              <Server size={12} /> {f.host_count} hosts
                            </span>
                          ) : (
                            f.affected_hosts?.[0] || "—"
                          )}
                        </td>
                        <td className="px-6 py-3.5 font-mono text-xs text-slate-600 dark:text-slate-300">{fmtCvss(f.cvss_score)}</td>
                        <td className="px-6 py-3.5 text-xs text-slate-500 dark:text-slate-400">{f.category}</td>
                      </tr>
                    ))}
                    {previewRows.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-6 py-12 text-center text-sm text-slate-400">
                          No findings to preview.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {(preview.findings?.length || 0) > 12 && (
                <div className="border-t border-slate-100 px-6 py-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  Showing the first 12 findings —{" "}
                  <Link to={`/admin/vapt-reports/${preview.import_id}`} className="font-bold text-purple-600 hover:underline dark:text-purple-400">
                    view all {preview.findings.length} in the full report →
                  </Link>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
