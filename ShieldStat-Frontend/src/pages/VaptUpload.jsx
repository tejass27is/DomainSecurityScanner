import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  Upload, FileUp, FileSpreadsheet, FileText, ShieldAlert, AlertTriangle,
  CheckCircle2, XCircle, Info, Globe, Download, Eye, Database, Zap,
  Layers, Server, Activity, ArrowLeft, FileDigit, Lock, WifiOff,
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

function ChoiceChipGroup({ options, value, onChange }) {
  return (
    <div className="flex flex-wrap gap-2">
      {options.map((option) => (
        <button
          key={option}
          type="button"
          onClick={() => onChange(option)}
          className={`rounded-full border px-3 py-2 text-xs font-semibold transition ${value === option ? "border-violet-600 bg-violet-600 text-white shadow-sm" : "border-slate-200 bg-slate-50 text-slate-700 hover:border-violet-200 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300"}`}
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
  const [orgsError, setOrgsError] = useState("");
  const [vaptAccessStatus, setVaptAccessStatus] = useState({
    vapt_access_enabled: false,
    requested_regions: [],
    approved_regions: [],
    available_regions: [],
  });
  const QUESTION_SECTIONS = [
    {
      id: "general_information",
      title: "General Information",
      description: "Client and scope overview for the VAPT engagement.",
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
      ],
    },
    {
      id: "network_infrastructure",
      title: "Network & Infrastructure",
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
      title: "Web Applications",
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
      title: "Cloud & Platform",
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
      title: "Email & Endpoint Security",
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
      title: "Access & Authorization",
      description: "Additional access requirements and approval details.",
      questions: [
        { id: "additional_vpn_remote_access_jump_server", label: "Will VAPT require any additional VPN, remote access, jump server or other access besides the WFH VPN described above?", type: "textarea", helper: "Any additional access required beyond WFH VPN.", example: "Example: Jump host required for prod segment access." },
        { id: "additional_credentials_required_for_vapt", label: "Will any additional credentials be required for VAPT?", type: "textarea", helper: "Any extra credentials required.", example: "Example: Root access or firewall admin credentials." },
      ],
    },
    {
      id: "testing_window_section",
      title: "Testing Window & Approval",
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
        normalized[section.id][question.id] = {
          question: question.label,
          answer: typeof item.answer === "string" ? item.answer : "",
          na: Boolean(item.na),
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
    const generalAnswers = nextOnboarding?.checklist_answers?.general_information || {};
    const primaryContactAnswer = generalAnswers.primary_contact?.answer || "";
    const derivedContact = extractPrimaryContactInfo(primaryContactAnswer);
    const testingAuthorizationAnswer = generalAnswers.testing_authorization?.answer || "";

    const scopeIpRanges = nextOnboarding?.scope_ip_ranges || nextOnboarding?.checklist_answers?.network_infrastructure?.internal_ips?.answer || "";
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

  const emptyOnboarding = {
    completed: false,
    review_status: "pending",
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
  };
  const [onboarding, setOnboarding] = useState(emptyOnboarding);
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
  const [activeSection, setActiveSection] = useState("general_information");
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
            prev.vapt_access_enabled === normalized.vapt_access_enabled &&
            (prev.requested_regions || []).join(",") === (normalized.requested_regions || []).join(",")
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Detect user changes by watching the token - reset form when user logs out/in
  useEffect(() => {
    const handleStorageChange = () => {
      // When token changes (user logout/login), reset form data
      setOnboarding(emptyOnboarding);
      setRequestRegionCode("");
      setRequestRegionName("");
      setChecklistMessage("");
      setActiveSection("general_information");
      setSocReviewNote("");
    };
    
    // Listen for logout events
    window.addEventListener("logout", handleStorageChange);
    return () => window.removeEventListener("logout", handleStorageChange);
  }, []);

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
          setActiveSection("general_information");
          setChecklistMessage("");
        }

        setOnboarding(nextOnboarding);
        setSocReviewNote((onbData || {})?.review_note || "");
        setHasScans(!!scanData?.has_completed_scans);

        // For region requests, start with a fresh empty checklist
        // and only preserve the region-agnostic metadata.
        if (regionRequestMode) {
          setOnboarding((prev) => ({
            ...prev,
            checklist_answers: buildEmptyChecklistAnswers(),
            testing_start_at: "",
            testing_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
            completed: false,
            review_status: "pending",
          }));
          setRequestRegionCode("");
          setRequestRegionName("");
          setActiveSection("general_information");
          setChecklistMessage("");
        }
      } catch {
        // If onboarding endpoint doesn't exist yet, allow through
        setHasScans(true);
      }
    })();
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
        ? await uploadVaptVerificationReport(selectedFile, selectedVerificationSchedule, token)
        : await uploadVaptReport(selectedFile, token, selectedOrgId, selectedRegion);
      setPreview(result);
      setProgressMsg("");
    } catch (err) {
      setUploadError(err?.message || "Upload failed. Please try again.");
      setProgressMsg("");
    } finally {
      setIsUploading(false);
    }
  }, [selectedFile, isUploading, selectedOrgId, selectedRegion, selectedVerificationSchedule]);

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

  if (!canUpload && clientAccessState === "access_not_approved") {
    return (
      <div className="mx-auto max-w-2xl rounded-[2rem] border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 flex items-center gap-3">
          <span className="material-symbols-outlined text-purple-600">fact_check</span>
          <span className="text-xs font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">VAPT access</span>
        </div>
        <h2 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">Request VAPT access</h2>
        <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">
          Your account has not been approved for VAPT yet. Choose the region you need and send the request to the admin for approval.
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
  const totalChecklistItems = QUESTION_SECTIONS.reduce((sum, section) => sum + section.questions.length, 0);
  const answeredChecklistCount = QUESTION_SECTIONS.reduce((sum, section) => {
    const sectionAnswers = normalizeChecklistAnswers(onboarding.checklist_answers || {})[section.id] || {};
    return sum + Object.values(sectionAnswers).filter((entry) => {
      const value = entry?.answer ?? "";
      return Boolean(String(value).trim()) || Boolean(entry?.na);
    }).length;
  }, 0);
  const allChecklistComplete = answeredChecklistCount >= totalChecklistItems;

  const requiredFieldsComplete = [
    onboarding.testing_start_at,
    onboarding.testing_timezone,
  ].every((value) => value !== "" && value != null);
  const canSubmitChecklist = allChecklistComplete && requiredFieldsComplete;

  // ── Onboarding checklist for first-time org users ──
  const updateQuestionAnswer = useCallback((sectionId, questionId, value, na = false) => {
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
  }, [syncDerivedOnboardingFields]);

  const toggleNa = useCallback((sectionId, questionId) => {
    const current = onboarding.checklist_answers?.[sectionId]?.[questionId];
    const isNa = !current?.na;
    updateQuestionAnswer(sectionId, questionId, isNa ? "N/A" : "", isNa);
  }, [onboarding.checklist_answers, updateQuestionAnswer]);

  const getSectionProgress = useCallback((section) => {
    const questions = Object.entries(normalizeChecklistAnswers(onboarding.checklist_answers || {})[section.id] || {});
    const total = section.questions.length;
    if (total === 0) return { answered: 0, total: 0, percent: 0 };
    let answered = 0;
    questions.forEach(([, entry]) => {
      const value = entry?.answer ?? "";
      const isAnswered = Boolean((value || "").toString().trim()) || Boolean(entry?.na);
      if (isAnswered) answered += 1;
    });
    return {
      answered,
      total,
      percent: Math.round((answered / total) * 100),
    };
  }, [onboarding.checklist_answers]);

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

  const handleSubmitOnboarding = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token) return;

    const regionCode = (requestRegionCode || "").trim().toUpperCase();
    const regionName = (requestRegionName || "").trim();
    if (!regionCode || !regionName) {
      setChecklistMessage("Please add the region code and region name before submitting the VAPT request.");
      return;
    }

    const derivedScopeIpRanges = onboarding.scope_ip_ranges || onboarding.checklist_answers?.network_infrastructure?.internal_ips?.answer || "";
    const derivedPrimaryContact = extractPrimaryContactInfo(onboarding.checklist_answers?.general_information?.primary_contact?.answer || "");
    const derivedAuthorizationConfirmed = Boolean(onboarding.authorization_confirmed) || (onboarding.checklist_answers?.general_information?.testing_authorization?.answer || "").toLowerCase() === "yes";
    const requiredFields = {
      testing_start_at: onboarding.testing_start_at,
      testing_timezone: onboarding.testing_timezone,
    };

    if (regionRequestMode) {
      if (!requiredFields.testing_start_at || !requiredFields.testing_timezone) {
        setChecklistMessage("Please provide the testing start date and timezone before submitting.");
        return;
      }
      setChecklistSubmitting(true);
      setChecklistMessage("");
      try {
        await requestVaptRegion({
          region_code: regionCode,
          region_name: regionName,
          testing_start_at: new Date(onboarding.testing_start_at).toISOString(),
          testing_timezone: onboarding.testing_timezone,
        }, token);
        setVaptAccessStatus(await getVaptAccessStatus(token));
        setChecklistMessage("The new region request has been submitted. Your existing VAPT access and reports remain available while SOC reviews this region.");
      } catch (err) {
        setChecklistMessage(err?.message || "Unable to submit the region request. Please try again.");
      } finally {
        setChecklistSubmitting(false);
      }
      return;
    }

    const missing = Object.entries(requiredFields).filter(([, value]) => value === "" || value === false || value == null);
    const normalizedAnswers = normalizeChecklistAnswers(onboarding.checklist_answers || {});
    const unansweredQuestion = QUESTION_SECTIONS.flatMap((section) =>
      section.questions.map((question) => ({ ...question, sectionId: section.id })),
    ).find((question) => {
      const entry = normalizedAnswers?.[question.sectionId]?.[question.id];
      const answer = entry?.answer ?? "";
      return !entry?.na && !String(answer).trim();
    });

    if (missing.length > 0) {
      setChecklistMessage(`Please complete the required fields: ${missing.map(([field]) => field.replaceAll("_", " ")).join(", ")}.`);
      return;
    }

    if (unansweredQuestion) {
      setChecklistMessage("Please answer every mandatory question before submitting the form.");
      return;
    }

    setChecklistSubmitting(true);
    setChecklistMessage("");
    try {
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
      const response = regionRequestMode
        ? await requestVaptRegion({
            region_code: regionCode,
            region_name: regionName,
            testing_start_at: payload.testing_start_at,
            testing_timezone: payload.testing_timezone,
          }, token)
        : await requestVaptAccess([{ code: regionCode, name: regionName }], token, payload);
      const nextStatus = regionRequestMode
        ? await getVaptAccessStatus(token)
        : (response || { vapt_access_enabled: false, requested_regions: [], approved_regions: [], available_regions: [] });
      setVaptAccessStatus(nextStatus);
      if (regionRequestMode) {
        setChecklistMessage("The new region request has been submitted. Your existing VAPT access and reports remain available while SOC reviews this region.");
      } else {
        setOnboarding((prev) => ({ ...prev, ...payload, completed: true, review_status: "pending" }));
        setChecklistMessage("Your VAPT request has been submitted. The admin and SOC team will review the region, checklist, and preferred testing window together.");
      }
    } catch (err) {
      setChecklistMessage(err?.message || "Unable to submit the checklist. Please try again.");
    } finally {
      setChecklistSubmitting(false);
    }
  }, [onboarding, requestRegionCode, requestRegionName]);

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
          {regionRequestMode ? "Complete the VAPT form again for this region. SOC will review the region, checklist, and testing start together." : "Complete this one-time checklist so your security team knows how to scope and schedule your first scan."}
        </p>

        <div className="mt-8 space-y-6">
          <div className="rounded-2xl border border-violet-200 bg-violet-50 px-4 py-3 text-sm text-violet-800 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-200">
            This intake is structured by section so it stays manageable. Progress saves automatically as you go, and you can return later without losing work.
          </div>

          {onboarding.review_status === "rejected" && socReviewNote && (
            <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
              <p className="font-bold">SOC review feedback</p>
              <p className="mt-1 whitespace-pre-wrap">{socReviewNote}</p>
            </div>
          )}

          <div className="mx-auto w-full max-w-6xl rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="mb-5 grid gap-4 rounded-2xl border border-violet-200 bg-violet-50 p-4 dark:border-violet-900 dark:bg-violet-950/30 md:grid-cols-2">
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
                        const twoColumnQuestions = section.questions.filter((question) => question.short || question.type === "choice");
                        const fullWidthQuestions = section.questions.filter((question) => !question.short && question.type !== "choice");

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
                                    <div key={question.id} className={wrapClass}>
                                      <div className="mb-2 flex items-center justify-between gap-3">
                                        <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">
                                          <span className="inline-flex items-center gap-1.5">
                                            <span className="text-violet-700 dark:text-violet-300">{getQuestionNumber(section.id, question.id)}.</span>
                                            <span>{question.label}</span>
                                            <span className="text-red-500">*</span>
                                          </span>
                                        </label>
                                        <button
                                          type="button"
                                          onClick={() => toggleNa(section.id, question.id)}
                                          className={`rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.15em] ${entry.na ? "border-slate-700 bg-slate-800 text-white dark:border-slate-200 dark:bg-slate-100 dark:text-slate-900" : "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300"}`}
                                        >
                                          N/A
                                        </button>
                                      </div>

                                      {question.helper && (
                                        <p className="mb-2 text-[11px] leading-5 text-slate-500 dark:text-slate-400">{question.helper}</p>
                                      )}

                                      {question.type === "choice" ? (
                                        <ChoiceChipGroup
                                          options={question.options}
                                          value={entry.answer}
                                          onChange={(option) => updateQuestionAnswer(section.id, question.id, option, false)}
                                        />
                                      ) : (
                                        <input
                                          type="text"
                                          value={entry.na ? "N/A" : entry.answer}
                                          disabled={entry.na}
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
                                    <div key={question.id} className={wrapClass}>
                                      <div className="mb-2 flex items-center justify-between gap-3">
                                        <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">
                                          <span className="inline-flex items-center gap-1.5">
                                            <span className="text-violet-700 dark:text-violet-300">{getQuestionNumber(section.id, question.id)}.</span>
                                            <span>{question.label}</span>
                                            <span className="text-red-500">*</span>
                                          </span>
                                        </label>
                                        <button
                                          type="button"
                                          onClick={() => toggleNa(section.id, question.id)}
                                          className={`rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.15em] ${entry.na ? "border-slate-700 bg-slate-800 text-white dark:border-slate-200 dark:bg-slate-100 dark:text-slate-900" : "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300"}`}
                                        >
                                          N/A
                                        </button>
                                      </div>

                                      {question.helper && (
                                        <p className="mb-2 text-[11px] leading-5 text-slate-500 dark:text-slate-400">{question.helper}</p>
                                      )}

                                      {question.type === "textarea" ? (
                                        <textarea
                                          rows={2}
                                          value={entry.na ? "N/A" : entry.answer}
                                          disabled={entry.na}
                                          onChange={(e) => updateQuestionAnswer(section.id, question.id, e.target.value, false)}
                                          className={`${baseClass} min-h-[74px] resize-y`}
                                          placeholder={question.example || "Provide details"}
                                        />
                                      ) : question.type === "table" ? (
                                        <div className="space-y-3">
                                          <textarea
                                            rows={3}
                                            value={entry.na ? "N/A" : entry.answer}
                                            disabled={entry.na}
                                            onChange={(e) => updateQuestionAnswer(section.id, question.id, e.target.value, false)}
                                            className={`${baseClass} min-h-[90px] resize-y`}
                                            placeholder={question.example || "Add rows as needed for each asset / platform entry."}
                                          />
                                        </div>
                                      ) : (
                                        <input
                                          type="text"
                                          value={entry.na ? "N/A" : entry.answer}
                                          disabled={entry.na}
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
          <p className="text-sm leading-6 text-slate-700 dark:text-slate-200">Your VAPT request has been submitted. The admin and SOC team will review the region, checklist, and preferred testing window together.</p>
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

  if (!canUpload && clientAccessState === "access_not_approved") {
    return (
      <div className="flex min-h-screen items-center justify-center p-6 text-slate-900 dark:text-slate-100">
        <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-purple-50 text-purple-600 dark:bg-purple-950/40 dark:text-purple-400">
            <FileUp size={26} />
          </div>
          <h2 className="text-lg font-bold">Upload access is restricted</h2>
          <p className="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">
            VAPT reports are uploaded and published by your security team (SOC analysts). Your
            account can view and download the reports published to your organization, and mark
            findings as solved.
          </p>
          <Link
            to="/vapt/reports"
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-purple-600 px-5 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95"
          >
            <Eye size={16} /> View published reports
          </Link>
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
                    onChange={(e) => setSelectedVerificationSchedule(e.target.value)}
                    className="w-full rounded-xl border border-sky-200 bg-white px-3 py-2.5 text-sm text-slate-800 outline-none transition focus:border-sky-400 focus:ring-2 focus:ring-sky-200 dark:border-sky-800 dark:bg-slate-900 dark:text-slate-100"
                  >
                    <option value="">Upload an initial report</option>
                    {verificationSchedules.map((schedule) => (
                      <option key={schedule.id} value={schedule.id}>
                        Verification · {schedule.file_name || schedule.import_id} · {new Date(schedule.scheduled_at).toLocaleString()}
                      </option>
                    ))}
                  </select>
                  <p className="mt-2 text-xs text-sky-700 dark:text-sky-300">
                    Select the approved rescan to attach the SOC retest export. This upload completes that manual verification.
                  </p>
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
