#nullable enable
using System;
using System.Collections.Generic;
using DS = System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Microsoft.Win32;
using System.Xml;
using System.Management;
using System.Reflection;
using System.Threading;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.DirectoryServices;

namespace ADSecurityAuditor
{
    public enum AuditSeverity
    {
        Informational = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public enum AuditMode
    {
        GRC,
        RedTeam
    }

    public class AuditConfig
    {
        public bool EnableParallelExecution { get; set; } = true;
        public List<string> DisabledChecks { get; set; } = new List<string>();
        public Dictionary<string, int> CustomThresholds { get; set; } = new Dictionary<string, int>();
        public string OutputDirectory { get; set; } = Directory.GetCurrentDirectory();
        public AuditSeverity MinReportSeverity { get; set; } = AuditSeverity.Low;
        public bool EnableSiemIntegration { get; set; }
        public string SiemEndpoint { get; set; } = string.Empty;
        public string SiemToken { get; set; } = string.Empty;
        public List<string> PrivilegedGroups { get; set; } = new()
    {
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators"
    };

    }

    public class DomainPasswordPolicy
    {
        public int MinPasswordLength { get; set; }
        public int PasswordHistoryLength { get; set; }
        public TimeSpan MaxPasswordAge { get; set; }
        public int LockoutThreshold { get; set; }
        public TimeSpan LockoutDuration { get; set; }
    }

    public class ADAuditFinding
    {
        public string ID { get; set; }
        public string Title { get; set; }
        public AuditSeverity Severity { get; set; }
        public string Description { get; set; }
        public string AffectedObject { get; set; }
        public string Remediation { get; set; }
        public string Evidence { get; set; }
        public List<string> References { get; set; }
        public DateTime Timestamp { get; set; }
        public string RemediationScript { get; set; }
        public List<string> ComplianceMappings { get; set; }

        public ADAuditFinding()
        {
            Timestamp = DateTime.Now;
            References = new List<string>();
            ComplianceMappings = new List<string>();
            RemediationScript = string.Empty;
        }
    }

    public static class Logger
    {
        private static readonly string LogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ADAudit.log");

        public static void Info(string message) => Log("INFO", message);
        public static void Warn(string message) => Log("WARN", message);
        public static void Error(string message) => Log("ERROR", message);

        private static void Log(string level, string message)
        {
            try
            {
                var log = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}";
                Console.WriteLine(log);
                File.AppendAllText(LogPath, log + Environment.NewLine);
            }
            catch { /* Ignore logging errors */ }
        }
    }

    public class ADAuditor
    {
        private readonly AuditMode _mode;
        private readonly string? _domain;
        private readonly string? _username;
        private readonly SecureString? _passwordSecure;
        private readonly List<ADAuditFinding> _findings = new List<ADAuditFinding>();
        private DS.DirectoryEntry _domainRoot;
        private DS.DirectoryEntry _domainEntry;
        private readonly Domain _currentDomain = Domain.GetCurrentDomain();
        private string _namingContext = string.Empty;
        private readonly Forest _currentForest = Forest.GetCurrentForest();
        private readonly AuditConfig _config;
        private readonly Dictionary<string, int> _complianceCounts = new Dictionary<string, int>();

        public ADAuditor(AuditMode mode, AuditConfig config, string? domain = null, string? username = null, string? password = null)
        {
            _mode = mode;
            _config = config;
            _domain = domain;
            _username = username;

            if (!string.IsNullOrEmpty(password))
            {
                _passwordSecure = new SecureString();
                foreach (char c in password) _passwordSecure.AppendChar(c);
                _passwordSecure.MakeReadOnly();
            }

            LoadComplianceMappings();
        }

        public ADAuditor(AuditMode mode, AuditConfig config, string? domain = null, string? username = null, SecureString? password = null)
        {
            _mode = mode;
            _config = config;
            _domain = domain;
            _username = username;
            _passwordSecure = password;

            LoadComplianceMappings();
        }

        private void LoadComplianceMappings()
        {
            // Predefined compliance mappings
            var mappings = new Dictionary<string, List<string>>
            {
                ["PWD-001"] = new List<string> { "NIST.800-53.IA-5(1)", "CIS.9.1.1" },
                ["PWD-002"] = new List<string> { "CIS.9.1.2" },
                ["PWD-003"] = new List<string> { "CIS.9.1.3" },
                ["ALP-001"] = new List<string> { "NIST.800-53.AC-7", "CIS.9.2.1" },
                ["ALP-002"] = new List<string> { "CIS.9.2.2" },
                ["KRB-001"] = new List<string> { "CIS.18.9.1" },
                ["KRB-002"] = new List<string> { "CIS.18.9.2" },
                ["DEL-001"] = new List<string> { "MITRE.T1558.003", "CIS.1.1.5" },
                ["PRIV-001"] = new List<string> { "CIS.18.9.13" },
                ["SVC-001"] = new List<string> { "CIS.2.3.11", "NIST.IA-5" },
                ["SDH-001"] = new List<string> { "MITRE.T1484.001" },
                ["LAPS-001"] = new List<string> { "CIS.4.1" },
                ["LDAP-001"] = new List<string> { "CIS.1.7" },
                ["NTLM-001"] = new List<string> { "CIS.1.8" },
                ["SMB-001"] = new List<string> { "CIS.2.3.2" },
                ["PROT-001"] = new List<string> { "CIS.1.9" },
                ["STALE-001"] = new List<string> { "CIS.1.1.4" },
                ["ACL-001"] = new List<string> { "MITRE.T1484.002", "CIS.1.3" },
                ["GPP-001"] = new List<string> { "CIS.18.9.60" },
                ["DCSYNC-001"] = new List<string> { "MITRE.T1003.006" },
                ["TRUST-001"] = new List<string> { "CIS.1.5" }
            };

            // Store in findings when created
        }

        private static string SecureStringToString(SecureString ss)
        {
            IntPtr ptr = Marshal.SecureStringToGlobalAllocUnicode(ss);
            try
            {
                return Marshal.PtrToStringUni(ptr)!;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        private DS.DirectoryEntry GetAuthenticatedEntry(string path = null)
        {
            path ??= $"LDAP://{_domain}";
            var auth = AuthenticationTypes.Secure
                | AuthenticationTypes.Signing
                | AuthenticationTypes.Sealing;

            if (!string.IsNullOrEmpty(_username) && _passwordSecure != null)
            {
                var pwd = SecureStringToString(_passwordSecure);
                return new DS.DirectoryEntry(path, _username, pwd, auth);
            }
            else
            {
                return new DS.DirectoryEntry(path, null, null, auth);
            }
        }

        private void InitializeDomainConnection()
        {
            Logger.Info("Initializing domain connection...");

            using (var rootDse = GetAuthenticatedEntry("LDAP://RootDSE"))
            {
                _namingContext = rootDse.Properties["defaultNamingContext"][0].ToString();
            }

            string ldapPath = $"LDAP://{_namingContext}";
            Logger.Info($"Binding to domain at: {ldapPath}");
            _domainRoot = GetAuthenticatedEntry(ldapPath);

            _domainEntry = GetAuthenticatedEntry(ldapPath);
            Logger.Info($"DomainEntry.Path = {_domainEntry.Path}");

            var task = Task.Run(() => _domainRoot.NativeObject);
            if (!task.Wait(TimeSpan.FromSeconds(15)))
                throw new ApplicationException("Domain connection timed out");
            Logger.Info($"Connected to domain: {_domainRoot.Path}");
        }

        private DS.DirectoryEntry GetDomainEntry()
        {
            return _domainEntry;
        }


        private void ExecuteSafely(Action action, string checkName)
        {
            try
            {
                Logger.Info($"Starting check: {checkName}");
                action();
                Logger.Info($"Completed check: {checkName}");
            }
            catch (Exception ex)
            {
                var err = new ADAuditFinding
                {
                    ID = "ERR-000",
                    Title = $"Audit check failed: {checkName}",
                    Severity = AuditSeverity.High,
                    Description = ex.Message,
                    AffectedObject = "Audit System",
                    Remediation = "Check permissions and connectivity"
                };

                Logger.Error(
                    $"[{err.ID}] {err.Title} | " +
                    $"Severity={err.Severity} | " +
                    $"Desc=\"{err.Description}\" | " +
                    $"Affected=\"{err.AffectedObject}\" | " +
                    $"Remediation=\"{err.Remediation}\""
                );
            }
        }

        public List<ADAuditFinding> RunAudit()
        {
            InitializeDomainConnection();

            var checks = new List<Action>
            {
                () => ExecuteSafely(CheckPasswordPolicy, nameof(CheckPasswordPolicy)),
                () => ExecuteSafely(CheckAccountLockoutPolicy, nameof(CheckAccountLockoutPolicy)),
                () => ExecuteSafely(CheckKerberosSettings, nameof(CheckKerberosSettings)),
                () => ExecuteSafely(CheckDelegationRisks, nameof(CheckDelegationRisks)),
                () => ExecuteSafely(CheckPrivilegedGroups, nameof(CheckPrivilegedGroups)),
                () => ExecuteSafely(CheckServiceAccounts, nameof(CheckServiceAccounts)),
                () => ExecuteSafely(CheckAdminSDHolder, nameof(CheckAdminSDHolder)),
                () => ExecuteSafely(CheckLAPS, nameof(CheckLAPS)),
                () => ExecuteSafely(CheckLDAPSecurity, nameof(CheckLDAPSecurity)),
                () => ExecuteSafely(CheckNTLMSettings, nameof(CheckNTLMSettings)),
                () => ExecuteSafely(CheckSMBv1, nameof(CheckSMBv1)),
                () => ExecuteSafely(CheckProtectedUsers, nameof(CheckProtectedUsers)),
                () => ExecuteSafely(CheckStaleObjects, nameof(CheckStaleObjects)),
                () => ExecuteSafely(CheckRecycleBin, nameof(CheckRecycleBin)),
                () => ExecuteSafely(CheckPrintSpooler, nameof(CheckPrintSpooler)),
                () => ExecuteSafely(CheckShadowCopies, nameof(CheckShadowCopies)),
                () => ExecuteSafely(CheckConstainedDelegation, nameof(CheckConstainedDelegation)),
                () => ExecuteSafely(CheckForestTrusts, nameof(CheckForestTrusts))
            };

            if (_mode == AuditMode.RedTeam)
            {
                checks.Add(() => ExecuteSafely(CheckACLBackdoors, nameof(CheckACLBackdoors)));
                checks.Add(() => ExecuteSafely(CheckGPPCredentials, nameof(CheckGPPCredentials)));
                checks.Add(() => ExecuteSafely(CheckTrustedForDelegation, nameof(CheckTrustedForDelegation)));
                checks.Add(() => ExecuteSafely(CheckDCSyncRights, nameof(CheckDCSyncRights)));
                checks.Add(() => ExecuteSafely(CheckSPNTargets, nameof(CheckSPNTargets)));
            }

            // Filter out disabled checks
            var enabledChecks = checks.Where(c =>
                !_config.DisabledChecks.Contains(GetCheckNameFromAction(c))).ToList();

            Logger.Info($"Running {enabledChecks.Count} checks (Mode: {_mode})");

            if (_config.EnableParallelExecution)
            {
                Logger.Info("Running checks in parallel...");
                Parallel.ForEach(enabledChecks, check => check());
            }
            else
            {
                Logger.Info("Running checks sequentially...");
                foreach (var check in enabledChecks)
                {
                    check();
                }
            }

            //GenerateRemediationScripts();
            if (_config.EnableSiemIntegration) SubmitToSIEM().Wait();

            return _findings.OrderByDescending(f => (int)f.Severity).ToList();
        }

        private string GetCheckNameFromAction(Action action)
        {
            // Extract check name from action
            return action.Method.Name.Replace("__", "").Split('>')[0];
        }

        private void AddFinding(ADAuditFinding finding)
        {
            // Add compliance mappings if available
            if (!finding.ComplianceMappings.Any())
            {
                var mappings = new Dictionary<string, List<string>>
                {
                    ["PWD-001"] = new List<string> { "NIST.800-53.IA-5(1)", "CIS.9.1.1" },
                    ["PWD-002"] = new List<string> { "CIS.9.1.2" },
                    ["PWD-003"] = new List<string> { "CIS.9.1.3" },
                    ["ALP-001"] = new List<string> { "NIST.800-53.AC-7", "CIS.9.2.1" },
                    ["ALP-002"] = new List<string> { "CIS.9.2.2" },
                    ["KRB-001"] = new List<string> { "CIS.18.9.1" },
                    ["KRB-002"] = new List<string> { "CIS.18.9.2" },
                    ["DEL-001"] = new List<string> { "MITRE.T1558.003", "CIS.1.1.5" },
                    ["PRIV-001"] = new List<string> { "CIS.18.9.13" },
                    ["SVC-001"] = new List<string> { "CIS.2.3.11", "NIST.IA-5" },
                    ["SDH-001"] = new List<string> { "MITRE.T1484.001" },
                    ["LAPS-001"] = new List<string> { "CIS.4.1" },
                    ["LDAP-001"] = new List<string> { "CIS.1.7" },
                    ["NTLM-001"] = new List<string> { "CIS.1.8" },
                    ["SMB-001"] = new List<string> { "CIS.2.3.2" },
                    ["PROT-001"] = new List<string> { "CIS.1.9" },
                    ["STALE-001"] = new List<string> { "CIS.1.1.4" },
                    ["ACL-001"] = new List<string> { "MITRE.T1484.002", "CIS.1.3" },
                    ["GPP-001"] = new List<string> { "CIS.18.9.60" },
                    ["DCSYNC-001"] = new List<string> { "MITRE.T1003.006" },
                    ["TRUST-001"] = new List<string> { "CIS.1.5" }
                };

                if (mappings.TryGetValue(finding.ID, out var compliance))
                {
                    finding.ComplianceMappings.AddRange(compliance);
                }
            }


            // Add context evidence
            finding.Evidence += $"\n[Context] {DateTime.UtcNow:u} | {Environment.UserName}@{Environment.MachineName}";

            lock (_findings)
            {
                _findings.Add(finding);
            }

            // Update compliance counts
            foreach (var mapping in finding.ComplianceMappings)
            {
                if (_complianceCounts.ContainsKey(mapping))
                {
                    _complianceCounts[mapping]++;
                }
                else
                {
                    _complianceCounts[mapping] = 1;
                }
            }
        }

        #region Security Checks
        private DomainPasswordPolicy GetPasswordPolicy()
        {
            // 1) Bind to RootDSE to get the naming context
            using var rootDse = GetAuthenticatedEntry("LDAP://RootDSE");
            string nc = rootDse.Properties["defaultNamingContext"][0]?.ToString()
                        ?? throw new InvalidOperationException("Cannot read defaultNamingContext.");

            // 2) Bind to the domain object
            using var domainEntry = GetAuthenticatedEntry($"LDAP://{nc}");

            // 3) Read the properties
            int minLen = (int)(domainEntry.Properties["minPwdLength"].Value ?? 0);
            int histLen = (int)(domainEntry.Properties["pwdHistoryLength"].Value ?? 0);

            dynamic rawMaxPwd = domainEntry.Properties["maxPwdAge"].Value;
            dynamic rawLockDur = domainEntry.Properties["lockoutDuration"].Value;
            int lockoutThresh = (int)(domainEntry.Properties["lockoutThreshold"].Value ?? 0);

            // 4) Convert large-integer to TimeSpan
            long maxTicks = ((long)rawMaxPwd.HighPart << 32) | (uint)rawMaxPwd.LowPart;
            long lockTicks = ((long)rawLockDur.HighPart << 32) | (uint)rawLockDur.LowPart;

            var policy = new DomainPasswordPolicy
            {
                MinPasswordLength = minLen,
                PasswordHistoryLength = histLen,
                MaxPasswordAge = TimeSpan.FromTicks(Math.Abs(maxTicks)),
                LockoutThreshold = lockoutThresh,
                LockoutDuration = TimeSpan.FromTicks(Math.Abs(lockTicks))
            };

            // 5) Apply any custom thresholds
            if (_config.CustomThresholds.TryGetValue("MinPasswordLength", out var cMin)) policy.MinPasswordLength = cMin;
            if (_config.CustomThresholds.TryGetValue("PasswordHistoryLength", out var cHist)) policy.PasswordHistoryLength = cHist;
            if (_config.CustomThresholds.TryGetValue("LockoutThreshold", out var cThresh)) policy.LockoutThreshold = cThresh;
            if (_config.CustomThresholds.TryGetValue("LockoutDuration", out var cDur)) policy.LockoutDuration = TimeSpan.FromMinutes(cDur);

            return policy;
        }



        private static TimeSpan ConvertLargeIntegerToTimeSpan(object liValue)
        {
            dynamic li = liValue;
            long high = (long)li.HighPart;
            long low = (uint)li.LowPart;
            long ticks = (high << 32) | low;
            return TimeSpan.FromTicks(Math.Abs(ticks));
        }

        private void CheckPasswordPolicy()
        {
            try
            {
                // 1) Read RootDSE → defaultNamingContext
                using var rootDse = GetAuthenticatedEntry("LDAP://RootDSE");
                string baseDn = rootDse.Properties["defaultNamingContext"][0]!.ToString()!;

                // 2) Bind to the domain naming context
                using var domainEntry = GetAuthenticatedEntry($"LDAP://{baseDn}");

                // 3) Pull the msDS-style properties
                int minLen = (int)(domainEntry.Properties["minPwdLength"].Value ?? 0);
                int histLen = (int)(domainEntry.Properties["pwdHistoryLength"].Value ?? 0);

                dynamic rawMaxAge = domainEntry.Properties["maxPwdAge"].Value!;
                dynamic rawLockDur = domainEntry.Properties["lockoutDuration"].Value!;

                long maxAgeTicks = ((long)rawMaxAge.HighPart << 32) | (uint)rawMaxAge.LowPart;
                long lockDurTicks = ((long)rawLockDur.HighPart << 32) | (uint)rawLockDur.LowPart;

                // 4) Construct the policy object
                var policy = new DomainPasswordPolicy
                {
                    MinPasswordLength = minLen,
                    PasswordHistoryLength = histLen,
                    MaxPasswordAge = TimeSpan.FromTicks(Math.Abs(maxAgeTicks)),
                    LockoutThreshold = (int)(domainEntry.Properties["lockoutThreshold"].Value ?? 0),
                    LockoutDuration = TimeSpan.FromTicks(Math.Abs(lockDurTicks))
                };

                // 5) Compare against your thresholds
                int reqMin = _config.CustomThresholds.GetValueOrDefault("MinPasswordLength", 14);
                if (policy.MinPasswordLength < reqMin)
                    AddFinding(new ADAuditFinding
                    {
                        ID = "PWD-001",
                        Title = $"Min password length < {reqMin}",
                        Severity = AuditSeverity.High,
                        Description = $"MinPwdLength = {policy.MinPasswordLength}",
                        AffectedObject = baseDn,
                        Remediation = $"Set minPwdLength ≥ {reqMin}",
                        References = new List<string> { "NIST SP 800-63B 5.1.1", "CIS L1 1.1.x" }
                    });

                int reqHist = _config.CustomThresholds.GetValueOrDefault("PasswordHistoryLength", 24);
                if (policy.PasswordHistoryLength < reqHist)
                    AddFinding(new ADAuditFinding
                    {
                        ID = "PWD-002",
                        Title = $"Insufficient password history (< {reqHist})",
                        Severity = AuditSeverity.Medium,
                        Description = $"pwdHistoryLength = {policy.PasswordHistoryLength}",
                        AffectedObject = baseDn,
                        Remediation = $"Set pwdHistoryLength ≥ {reqHist}"
                    });

                int reqAge = _config.CustomThresholds.GetValueOrDefault("MaxPasswordAge", 90);
                if (policy.MaxPasswordAge.TotalDays > reqAge)
                    AddFinding(new ADAuditFinding
                    {
                        ID = "PWD-003",
                        Title = $"MaxPwdAge > {reqAge} days",
                        Severity = AuditSeverity.Medium,
                        Description = $"maxPwdAge = {policy.MaxPasswordAge.TotalDays:F0} days",
                        AffectedObject = baseDn,
                        Remediation = $"Set maxPwdAge ≤ {reqAge} days"
                    });
            }
            catch (Exception ex)
            {
                Logger.Error($"Password policy check failed: {ex.Message}");
                AddFinding(new ADAuditFinding
                {
                    ID = "ERR-001",
                    Title = "Password policy check failed",
                    Severity = AuditSeverity.High,
                    Description = ex.Message,
                    AffectedObject = _namingContext,
                    Remediation = "Verify LDAP connectivity/credentials"
                });
            }
        }

        private void CheckAccountLockoutPolicy()
        {
            try
            {
                // 1) Read RootDSE → defaultNamingContext
                using var rootDse = GetAuthenticatedEntry("LDAP://RootDSE");
                string baseDn = rootDse.Properties["defaultNamingContext"][0]!.ToString()!;

                // 2) Bind to the domain naming context
                using var domainEntry = GetAuthenticatedEntry($"LDAP://{baseDn}");

                // 3) Pull lockout props
                int thresh = (int)(domainEntry.Properties["lockoutThreshold"].Value ?? 0);

                dynamic rawLockDur = domainEntry.Properties["lockoutDuration"].Value!;
                long ticks = ((long)rawLockDur.HighPart << 32) | (uint)rawLockDur.LowPart;
                var dur = TimeSpan.FromTicks(Math.Abs(ticks));

                // 4a) Unlimited attempts?
                int reqThresh = _config.CustomThresholds.GetValueOrDefault("LockoutThreshold", 5);
                if (thresh == 0)
                    AddFinding(new ADAuditFinding
                    {
                        ID = "ALP-001",
                        Title = "No account lockout",
                        Severity = AuditSeverity.Critical,
                        Description = "lockoutThreshold = 0",
                        AffectedObject = baseDn,
                        Remediation = $"Set lockoutThreshold ≤ {reqThresh}"
                    });

                // 4b) Too short duration?
                int reqDurMin = _config.CustomThresholds.GetValueOrDefault("LockoutDuration", 15);
                if (dur.TotalMinutes < reqDurMin)
                    AddFinding(new ADAuditFinding
                    {
                        ID = "ALP-002",
                        Title = "Short lockout duration",
                        Severity = AuditSeverity.Low,
                        Description = $"lockoutDuration = {dur.TotalMinutes:F0} min",
                        AffectedObject = baseDn,
                        Remediation = $"Set lockoutDuration ≥ {reqDurMin} min"
                    });
            }
            catch (Exception ex)
            {
                Logger.Error($"Lockout policy check failed: {ex.Message}");
                AddFinding(new ADAuditFinding
                {
                    ID = "ERR-002",
                    Title = "Lockout policy check failed",
                    Severity = AuditSeverity.High,
                    Description = ex.Message,
                    AffectedObject = _namingContext,
                    Remediation = "Verify LDAP connectivity/credentials"
                });
            }
        }


        private void CheckKerberosSettings()
        {
            try
            {
                // bind directly to the domainRoot via LDAP
                using var entry = GetAuthenticatedEntry($"LDAP://RootDSE");
                string defaultNC = entry.Properties["defaultNamingContext"][0].ToString()!;
                using var domainEntry = GetAuthenticatedEntry($"LDAP://{defaultNC}");

                dynamic rawTicket = domainEntry.Properties["maxTicketAge"].Value;
                dynamic rawRenew = domainEntry.Properties["maxRenewAge"].Value;

                long ticketTicks = ((long)rawTicket.HighPart << 32) | (uint)rawTicket.LowPart;
                long renewTicks = ((long)rawRenew.HighPart << 32) | (uint)rawRenew.LowPart;

                int maxTicketHrs = _config.CustomThresholds.GetValueOrDefault("MaxTicketAge", 10);
                if (TimeSpan.FromTicks(Math.Abs(ticketTicks)).TotalHours > maxTicketHrs)
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "KRB-001",
                        Title = $"Long Kerberos ticket lifetime (> {maxTicketHrs}h)",
                        Severity = AuditSeverity.Medium,
                        Description = $"maxTicketAge = {TimeSpan.FromTicks(Math.Abs(ticketTicks)).TotalHours:F1} hours",
                        AffectedObject = _domain ?? defaultNC,
                        Remediation = $"Set maxTicketAge ≤ {maxTicketHrs} hours",
                        References = new List<string> { "Microsoft Kerberos Policy" },
                        ComplianceMappings = new List<string> { "CIS.18.9.1" }
                    });
                }

                int maxRenewHrs = _config.CustomThresholds.GetValueOrDefault("MaxRenewAge", 168);
                if (TimeSpan.FromTicks(Math.Abs(renewTicks)).TotalHours > maxRenewHrs)
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "KRB-002",
                        Title = $"Long Kerberos renewal lifetime (> {maxRenewHrs}h)",
                        Severity = AuditSeverity.Medium,
                        Description = $"maxRenewAge = {TimeSpan.FromTicks(Math.Abs(renewTicks)).TotalHours:F1} hours",
                        AffectedObject = _domain ?? defaultNC,
                        Remediation = $"Set maxRenewAge ≤ {maxRenewHrs} hours",
                        ComplianceMappings = new List<string> { "CIS.18.9.2" }
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Kerberos settings check failed: {ex.Message}");
                AddFinding(new ADAuditFinding
                {
                    ID = "ERR-003",
                    Title = "Kerberos settings check failed",
                    Severity = AuditSeverity.High,
                    Description = ex.Message,
                    AffectedObject = _domain ?? "(unknown)",
                    Remediation = "Check domain connectivity and credentials"
                });
            }
        }



        private void CheckDelegationRisks()
        {
            try
            {
                var searcher = CreateSearcher(
                    "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                    "name", "userAccountControl"
                );

                foreach (SearchResult result in searcher.FindAll())
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "DEL-001",
                        Title = "Unconstrained delegation",
                        Severity = AuditSeverity.High,
                        Description = "Computer allows plain TGT forwarding",
                        AffectedObject = result.Properties["name"][0].ToString(),
                        Remediation = "Convert to constrained delegation or remove",
                        Evidence = $"userAccountControl: {result.Properties["userAccountControl"][0]}",
                        References = new List<string> { "MITRE ATT&CK T1558.003", "CIS AD L2 1.1.5" },
                        ComplianceMappings = new List<string> { "MITRE.T1558.003", "CIS.1.1.5" }
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Delegation check failed: {ex.Message}");
                throw;
            }
        }

        private void CheckPrivilegedGroups()
        {
            var groupsToCheck = _config.PrivilegedGroups;

            Parallel.ForEach(groupsToCheck, groupName =>
            {
                try
                {
                    string dn = GetGroupDN(groupName);

                    using var groupEntry = GetAuthenticatedEntry($"LDAP://{dn}");
                    var members = groupEntry.Properties["member"];

                    if (members == null || members.Count == 0)
                        return;

                    foreach (string memberDn in members.Cast<string>())
                    {
                        try
                        {
                            using var userEntry = GetAuthenticatedEntry($"LDAP://{memberDn}");
                            int uac = userEntry.Properties["userAccountControl"]?.Value is int val ? val : 0;
                            string sam = userEntry.Properties["sAMAccountName"]?.Value?.ToString()
                                         ?? memberDn;

                            if ((uac & 0x10000) != 0)
                                AddFinding(new ADAuditFinding
                                {
                                    ID = "PRIV-001",
                                    Title = "Privileged account with DES encryption",
                                    Severity = AuditSeverity.High,
                                    AffectedObject = sam,
                                    Remediation = "Disable 'Use DES encryption types for this account'",
                                    References = new List<string> {
                                "Microsoft KB977321",
                                "CIS WS 2022 18.9.13"
                            },
                                    ComplianceMappings = new List<string> {
                                "CIS.18.9.13"
                            }
                                });

                            if ((uac & 0x0002) != 0)
                                AddFinding(new ADAuditFinding
                                {
                                    ID = "PRIV-002",
                                    Title = "Disabled privileged account still in group",
                                    Severity = AuditSeverity.Low,
                                    AffectedObject = sam,
                                    Remediation = "Remove from privileged groups or delete account"
                                });
                        }
                        catch (Exception ex)
                        {
                            Logger.Error($"[PRIV] Error processing member {memberDn}: {ex.Message}");
                            AddFinding(new ADAuditFinding
                            {
                                ID = "ERR-005",
                                Title = "Privileged account check failed",
                                Severity = AuditSeverity.Medium,
                                Description = $"Error processing {memberDn}: {ex.Message}",
                                AffectedObject = groupName,
                                Remediation = "Check permissions"
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error($"[PRIV] Couldn’t bind group {groupName}: {ex.Message}");
                    AddFinding(new ADAuditFinding
                    {
                        ID = "ERR-006",
                        Title = "Privileged group bind failed",
                        Severity = AuditSeverity.Medium,
                        Description = $"Couldn’t bind {groupName}: {ex.Message}",
                        AffectedObject = groupName,
                        Remediation = "Check group existence and permissions"
                    });
                }
            });
        }

        private void CheckServiceAccounts()
        {
            try
            {

                using var searcher = CreateSearcher(
                    "(&(objectCategory=user)(servicePrincipalName=*))",
                    "name", "userAccountControl", "memberOf"
                );

                foreach (SearchResult result in searcher.FindAll())
                {
                    string svcName = result.Properties["name"][0]?.ToString() ?? "<unknown>";

                    int uac = (int)result.Properties["userAccountControl"][0];
                    
                    if ((uac & 0x10000) == 0x10000)
                    {
                        AddFinding(new ADAuditFinding
                        {
                            ID = "SVC-001",
                            Title = "Service account no password expiry",
                            Severity = AuditSeverity.High,
                            Description = $"{svcName} has PasswordNeverExpires",
                            AffectedObject = svcName,
                            Remediation = "Convert to gMSA or rotate password periodically",
                            References = new List<string> { "CIS WS 2022 2.3.11", "NIST IA-5" },
                            ComplianceMappings = new List<string> { "CIS.2.3.11", "NIST.IA-5" }
                        });
                    }

                    var memberOf = result.Properties["memberOf"];
                    foreach (object dnObj in memberOf)
                    {
                        string dn = dnObj.ToString()!;
                        if (dn.Contains("CN=Domain Admins", StringComparison.OrdinalIgnoreCase) ||
                            dn.Contains("CN=Enterprise Admins", StringComparison.OrdinalIgnoreCase))
                        {
                            AddFinding(new ADAuditFinding
                            {
                                ID = "SVC-002",
                                Title = "Service account with admin privileges",
                                Severity = AuditSeverity.Critical,
                                Description = $"{svcName} is a member of {dn}",
                                AffectedObject = svcName,
                                Remediation = "Remove administrative group membership or convert to gMSA"
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Service account check failed: {ex.Message}");
                throw;
            }
        }

        private void CheckAdminSDHolder()
        {
            try
            {
                using var adminSDHolder = GetAuthenticatedEntry(
                    $"LDAP://CN=AdminSDHolder,CN=System,{_namingContext}"
                );
                var acl = adminSDHolder.ObjectSecurity;

                // any identity that ends with one of these group names is safe to ignore
                var ignoredGroups = new[]
                {
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "NT AUTHORITY\\SYSTEM",
            "BUILTIN\\Administrators"
        };

                foreach (ActiveDirectoryAccessRule ace in acl.GetAccessRules(true, true, typeof(NTAccount)))
                {
                    string idRef = ace.IdentityReference.Value;

                    // if the identity ends with any of the ignored names, skip it:
                    if (ignoredGroups.Any(g => idRef.EndsWith("\\" + g, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    // only flag truly dangerous rights
                    if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll) ||
                        ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl) ||
                        ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                    {
                        AddFinding(new ADAuditFinding
                        {
                            ID = "SDH-001",
                            Title = "Dangerous ACE on AdminSDHolder",
                            Severity = AuditSeverity.Critical,
                            Description = $"ACE: {idRef} – {ace.ActiveDirectoryRights}",
                            AffectedObject = "AdminSDHolder",
                            Remediation = "Remove unnecessary ACEs from AdminSDHolder",
                            References = new List<string> { "MITRE ATT&CK T1484.001", "Microsoft KB817433" },
                            ComplianceMappings = new List<string> { "MITRE.T1484.001" }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"AdminSDHolder check failed: {ex.Message}");
                throw;
            }
        }
        private void CheckLAPS()
        {
            try
            {

                var ctx = new DirectoryContext(
                    DirectoryContextType.Domain,
                    _currentDomain.Name,
                    _username,
                    _passwordSecure != null ? SecureStringToString(_passwordSecure) : null
                );

                var domain = Domain.GetDomain(ctx);
                using var domainEntry = domain.GetDirectoryEntry();
                var searcher = new DirectorySearcher(domainEntry)
                {
                    Filter = "(objectClass=computer)",
                    PageSize = 1000
                };
                searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd");
                searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwdExpirationTime");

                int totalComputers = 0;
                int lapsEnabledCount = 0;

                foreach (SearchResult result in searcher.FindAll())
                {
                    totalComputers++;
                    if (result.Properties.Contains("ms-Mcs-AdmPwd") &&
                        result.Properties["ms-Mcs-AdmPwd"].Count > 0 &&
                        !string.IsNullOrEmpty(result.Properties["ms-Mcs-AdmPwd"][0].ToString()))
                    {
                        lapsEnabledCount++;
                    }
                }

                if (lapsEnabledCount == 0)
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "LAPS-001",
                        Title = "LAPS not implemented",
                        Severity = AuditSeverity.High,
                        Description = "No computers found with LAPS enabled",
                        AffectedObject = domain.Name,
                        Remediation = "Deploy Microsoft LAPS solution",
                        References = new List<string> { "Microsoft KB 3062591", "CIS AD L1 4.1" },
                        ComplianceMappings = new List<string> { "CIS.4.1" }
                    });
                }
                else if (lapsEnabledCount < totalComputers)
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "LAPS-002",
                        Title = "LAPS partially implemented",
                        Severity = AuditSeverity.Medium,
                        Description = $"LAPS enabled on {lapsEnabledCount}/{totalComputers} computers",
                        AffectedObject = domain.Name,
                        Remediation = "Ensure LAPS GPO is applied to all computer OUs"
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"LAPS check failed: {ex.Message}");
                throw;
            }
        }


        private void CheckLDAPSecurity()
        {
            try
            {

                string domainName = !string.IsNullOrEmpty(_domain)
                    ? _domain
                    : _currentDomain.Name;

                DirectoryContext ctx = (!string.IsNullOrEmpty(_username) && _passwordSecure != null)
                    ? new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName,
                          _username,
                          SecureStringToString(_passwordSecure)
                      )
                    : new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName
                      );

                Domain domainObj = Domain.GetDomain(ctx);

                foreach (DomainController dc in domainObj.DomainControllers)
                {
                    try
                    {
                        using var rk = RegistryKey.OpenRemoteBaseKey(
                            RegistryHive.LocalMachine,
                            dc.Name
                        );
                        var ldapSigning = rk
                            .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
                            ?.GetValue("LdapServerIntegrity")
                            ?.ToString();

                        if (ldapSigning != "2")
                        {
                            AddFinding(new ADAuditFinding
                            {
                                ID = "LDAP-001",
                                Title = "LDAP signing not enforced",
                                Severity = AuditSeverity.Critical,
                                Description = $"LDAP signing not enforced on {dc.Name}",
                                AffectedObject = dc.Name,
                                Remediation = "Set 'LdapServerIntegrity' registry value to 2",
                                References = new List<string> { "CVE-2017-8563", "CIS AD L2 1.7" },
                                ComplianceMappings = new List<string> { "CIS.1.7" }
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn($"Registry access failed on {dc.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"LDAP security check failed: {ex.Message}");
                throw;
            }
        }


        private void CheckNTLMSettings()
        {
            try
            {
                // bind domain
                string domainName = !string.IsNullOrEmpty(_domain) ? _domain : _currentDomain.Name;
                DirectoryContext ctx = (!string.IsNullOrEmpty(_username) && _passwordSecure != null)
                    ? new DirectoryContext(DirectoryContextType.Domain, domainName, _username, SecureStringToString(_passwordSecure))
                    : new DirectoryContext(DirectoryContextType.Domain, domainName);
                Domain domainObj = Domain.GetDomain(ctx);

                // get our authenticated LDAP entry for the domain naming context
                var entry = GetAuthenticatedEntry($"LDAP://{_namingContext}");
                var value = entry.Properties["ntlmAuditingEnabled"].Value?.ToString();

                if (value != "1")
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "NTLM-001",
                        Title = "NTLM auditing disabled",
                        Severity = AuditSeverity.Medium,
                        Description = "ntlmAuditingEnabled != 1",
                        AffectedObject = domainObj.Name,
                        Remediation = "Enable NTLM auditing in domain security policy",
                        References = new List<string> { "CIS AD L2 1.8" },
                        ComplianceMappings = new List<string> { "CIS.1.8" }
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"NTLM settings check failed: {ex.Message}");
                throw;
            }
        }


        private void CheckSMBv1()
        {
            try
            {
                string domainName = !string.IsNullOrEmpty(_domain)
                    ? _domain
                    : _currentDomain.Name;

                DirectoryContext ctx = (!string.IsNullOrEmpty(_username) && _passwordSecure != null)
                    ? new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName,
                          _username,
                          SecureStringToString(_passwordSecure)
                      )
                    : new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName
                      );

                Domain domainObj = Domain.GetDomain(ctx);

                foreach (DomainController dc in domainObj.DomainControllers)
                {
                    try
                    {
                        using var rk = RegistryKey.OpenRemoteBaseKey(
                            RegistryHive.LocalMachine,
                            dc.Name
                        );
                        var v = rk
                            .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
                            ?.GetValue("SMB1")
                            ?.ToString();

                        if (v == "1")
                        {
                            AddFinding(new ADAuditFinding
                            {
                                ID = "SMB-001",
                                Title = "SMBv1 enabled",
                                Severity = AuditSeverity.Critical,
                                Description = $"SMB1 = 1 on {dc.Name}",
                                AffectedObject = dc.Name,
                                Remediation = "Disable SMBv1 on all domain controllers",
                                References = new List<string> { "CVE-2017-0143", "CIS AD L1 2.3.2" },
                                ComplianceMappings = new List<string> { "CIS.2.3.2" }
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn($"Registry access failed on {dc.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"SMBv1 check failed: {ex.Message}");
                throw;
            }
        }


        private void CheckProtectedUsers()
        {
            try
            {

                string protectedUsersDn = GetGroupDN("Protected Users");

                using var protectedUsers = GetAuthenticatedEntry($"LDAP://{protectedUsersDn}");

                var members = protectedUsers.Properties["member"]
                              as System.DirectoryServices.PropertyValueCollection;

                if (members == null || members.Count == 0)
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "PROT-001",
                        Title = "Protected Users group is empty",
                        Severity = AuditSeverity.Medium,
                        Description = "No members in Protected Users group",
                        AffectedObject = "Protected Users",
                        Remediation = "Add highly privileged accounts to Protected Users group",
                        References = new List<string>
                {
                    "Microsoft Docs: Protected Users",
                    "CIS AD L2 1.9"
                },
                        ComplianceMappings = new List<string> { "CIS.1.9" }
                    });
                }
            }
            catch (InvalidOperationException)
            {
                AddFinding(new ADAuditFinding
                {
                    ID = "PROT-002",
                    Title = "Protected Users group missing",
                    Severity = AuditSeverity.Low,
                    Description = "Protected Users group not found (requires domain functional level 2012 R2+)",
                    AffectedObject = "Domain",
                    Remediation = "Upgrade domain functional level to 2012 R2 or later"
                });
            }
            catch (Exception ex)
            {
                Logger.Error($"Protected Users check failed: {ex.Message}");
                throw;
            }
        }

        private void CheckStaleObjects()
        {
            try
            {
                int staleDays = _config.CustomThresholds.GetValueOrDefault("StaleObjectThreshold", 90);
                var staleThreshold = DateTime.Now.AddDays(-staleDays);

                var searcher = CreateSearcher(
                    "(&(objectCategory=user)(lastLogonTimestamp<=" + staleThreshold.ToFileTime() + "))",
                    "name"
                );

                int staleCount = 0;
                foreach (SearchResult result in searcher.FindAll()) staleCount++;

                if (staleCount > 0)
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "STALE-001",
                        Title = $"Stale user accounts (> {staleDays} days)",
                        Severity = AuditSeverity.Medium,
                        Description = $"{staleCount} user accounts inactive for {staleDays}+ days",
                        AffectedObject = "Domain",
                        Remediation = "Review and disable/remove stale accounts",
                        References = new List<string> { "CIS AD L1 1.1.4" },
                        ComplianceMappings = new List<string> { "CIS.1.1.4" }
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Stale objects check failed: {ex.Message}");
                throw;
            }
        }

        private void CheckRecycleBin()
        {
            try
            {
                using var rootDSE = GetAuthenticatedEntry("LDAP://RootDSE");
                var features = rootDSE.Properties["EnabledOptionalFeatures"];

                bool recycleBinEnabled = false;
                foreach (string feature in features)
                {
                    if (feature.Contains("Recycle Bin Feature"))
                    {
                        recycleBinEnabled = true;
                        break;
                    }
                }

                if (!recycleBinEnabled)
                {
                    AddFinding(new ADAuditFinding
                    {
                        ID = "BIN-001",
                        Title = "AD Recycle Bin disabled",
                        Severity = AuditSeverity.High,
                        Description = "Accidental deletion protection not enabled",
                        AffectedObject = "Forest",
                        Remediation = "Enable AD Recycle Bin feature",
                        References = new List<string> { "Microsoft Docs: AD Recycle Bin" }
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Recycle Bin check failed: {ex.Message}");
                throw;
            }
        }

        private void CheckPrintSpooler()
        {
            try
            {
                var domain = _currentDomain;
                foreach (DomainController dc in domain.DomainControllers)
                {
                    try
                    {
                        using var svc = new System.ServiceProcess.ServiceController("Spooler", dc.Name);

                        svc.Refresh();

                        if (svc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                        {
                            AddFinding(new ADAuditFinding
                            {
                                ID = "PRINT-001",
                                Title = "Print Spooler running on DC",
                                Severity = AuditSeverity.Critical,
                                Description = $"Print Spooler service is running on {dc.Name}",
                                AffectedObject = dc.Name,
                                Remediation = "Disable the Print Spooler service on all domain controllers",
                                References = new List<string> { "CVE-2021-1675", "CVE-2021-34527" }
                            });
                        }
                    }
                    catch (InvalidOperationException ioe)
                    {
                        Logger.Warn($"Print Spooler not present on {dc.Name}: {ioe.Message}");
                    }
                    catch (System.ComponentModel.Win32Exception w32e)
                    {
                        Logger.Warn($"Cannot query Spooler on {dc.Name}: {w32e.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Print Spooler check failed: {ex.Message}");
                throw;
            }
        }


        private IEnumerable<string> GetShares(string serverName)
        {
            var list = new List<string>();
            var scope = new ManagementScope($@"\\{serverName}\root\cimv2");
            scope.Connect();

            var query = new ObjectQuery("SELECT Name FROM Win32_Share");
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (ManagementObject mo in searcher.Get())
            {
                list.Add(mo["Name"].ToString());
            }

            return list;
        }

        private void CheckShadowCopies()
        {
            try
            {
                var ctx = new DirectoryContext(
                    DirectoryContextType.Domain,
                    _currentDomain.Name,
                    _username,
                    _passwordSecure != null ? SecureStringToString(_passwordSecure) : null
                );

                var domain = Domain.GetDomain(ctx);

                foreach (DomainController dc in domain.DomainControllers)
                {
                    try
                    {
                        var shares = GetShares(dc.Name);
                        if (shares.Any(s => s.IndexOf("SYSVOL", StringComparison.OrdinalIgnoreCase) >= 0
                                         || s.IndexOf("NETLOGON", StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            AddFinding(new ADAuditFinding
                            {
                                ID = "SHADOW-001",
                                Title = "SYSVOL/NETLOGON shadow copies enabled",
                                Severity = AuditSeverity.High,
                                Description = $"Shadow copies enabled on {dc.Name}",
                                AffectedObject = dc.Name,
                                Remediation = "Disable shadow copies for SYSVOL and NETLOGON shares",
                                References = new List<string> { "MITRE ATT&CK T1552.002" },
                                ComplianceMappings = new List<string> { "MITRE.T1552.002" }
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn($"Shadow copy check failed on {dc.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Shadow copies check failed: {ex.Message}");
                throw;
            }
        }

        private string GetGroupDN(string cn)
        {
            using var root = GetAuthenticatedEntry("LDAP://RootDSE");
            string baseDn = root.Properties["defaultNamingContext"][0].ToString();

            using var searcher = new DirectorySearcher(
                GetAuthenticatedEntry($"LDAP://{baseDn}")
            )
            {
                Filter = $"(&(objectCategory=group)(cn={cn}))",
                PageSize = 1
            };
            searcher.PropertiesToLoad.Add("distinguishedName");

            var result = searcher.FindOne();
            if (result == null)
                throw new InvalidOperationException($"Group '{cn}' not found in AD.");

            return result.Properties["distinguishedName"][0].ToString();
        }


        private void CheckACLBackdoors()
        {
            var criticalGroups = _config.PrivilegedGroups;

            Parallel.ForEach(criticalGroups, groupName =>
            {
                try
                {
                    string dn = GetGroupDN(groupName);

                    using var groupEntry = GetAuthenticatedEntry($"LDAP://{dn}");
                    var acl = groupEntry.ObjectSecurity;

                    foreach (ActiveDirectoryAccessRule ace in acl.GetAccessRules(true, true, typeof(NTAccount)))
                    {
                        string idRef = ace.IdentityReference.Value;

                        if (idRef.StartsWith("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
                            idRef.StartsWith("BUILTIN\\Administrators", StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (idRef.EndsWith("\\" + groupName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll) ||
                            ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl) ||
                            ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                        {
                            AddFinding(new ADAuditFinding
                            {
                                ID = "ACL-001",
                                Title = "Dangerous ACE on privileged group",
                                Severity = AuditSeverity.Critical,
                                Description = $"{idRef} has {ace.ActiveDirectoryRights}",
                                AffectedObject = groupName,
                                Remediation = "Remove or restrict ACE",
                                References = new List<string> { "MITRE.T1484.002", "CIS.1.3" },
                                ComplianceMappings = new List<string> { "MITRE.T1484.002", "CIS.1.3" }
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error($"ACL check failed for {groupName}: {ex.Message}");
                    AddFinding(new ADAuditFinding
                    {
                        ID = "ERR-018",
                        Title = "ACL check failed for group",
                        Severity = AuditSeverity.Medium,
                        Description = ex.Message,
                        AffectedObject = groupName,
                        Remediation = "Check permissions"
                    });
                }
            });
        }


        private void CheckGPPCredentials()
        {
            try
            {

                string domainName = !string.IsNullOrEmpty(_domain)
                    ? _domain
                    : _currentDomain.Name;

                DirectoryContext ctx = (!string.IsNullOrEmpty(_username) && _passwordSecure != null)
                    ? new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName,
                          _username,
                          SecureStringToString(_passwordSecure)
                      )
                    : new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName
                      );

                Domain domainObj = Domain.GetDomain(ctx);
                foreach (DomainController dc in domainObj.DomainControllers)
                {
                    string sysvolPath = $@"\\{dc.Name}\SYSVOL\{domainObj.Name}\Policies";
                    if (!Directory.Exists(sysvolPath))
                    {
                        Logger.Warn($"SYSVOL path not found on {dc.Name}: {sysvolPath}");
                        continue;
                    }

                    foreach (string xmlFile in Directory.EnumerateFiles(
                        sysvolPath,
                        "*.xml",
                        System.IO.SearchOption.AllDirectories
                    ))
                    {
                        try
                        {
                            string content = File.ReadAllText(xmlFile);
                            if (content.IndexOf("cpassword", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                AddFinding(new ADAuditFinding
                                {
                                    ID = "GPP-001",
                                    Title = "GPP stored credentials",
                                    Severity = AuditSeverity.Critical,
                                    Description = $"cpassword found in {xmlFile}",
                                    AffectedObject = xmlFile,
                                    Remediation = "Delete preference item; deploy via LAPS or DSC instead",
                                    References = new List<string> { "CVE-2014-1812", "CIS WS 2022 18.9.60" },
                                    ComplianceMappings = new List<string> { "CIS.18.9.60" }
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Warn($"Error reading {xmlFile}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"GPP credentials check failed: {ex.Message}");
                throw;
            }
        }




        private void CheckTrustedForDelegation()
        {
            try
            {
                var searcher = CreateSearcher(
                    "(msDS-AllowedToDelegateTo=*)",
                    "name", "msDS-AllowedToDelegateTo"
                );

                foreach (SearchResult result in searcher.FindAll())
                {
                    var delegationTargets = result.Properties["msDS-AllowedToDelegateTo"];
                    foreach (string target in delegationTargets)
                    {
                        AddFinding(new ADAuditFinding
                        {
                            ID = "DEL-002",
                            Title = "Constrained delegation",
                            Severity = AuditSeverity.High,
                            Description = $"Account can delegate to {target}",
                            AffectedObject = result.Properties["name"][0].ToString(),
                            Remediation = "Review delegation permissions",
                            Evidence = $"Delegation target: {target}",
                            References = new List<string> { "MITRE ATT&CK T1558.003" },
                            ComplianceMappings = new List<string> { "MITRE.T1558.003" }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Trusted for delegation check failed: {ex.Message}");
                throw;
            }
        }

        private static readonly Guid ReplicateChangesGuid = new Guid("1131f6ad-9c07-11d1-f79f-0000f80367c1");
        private static readonly Guid ReplicateChangesAllGuid = new Guid("1131f6ae-9c07-11d1-f79f-0000f80367c1");

        private void CheckDCSyncRights()
        {
            try
            {

                string domainName = !string.IsNullOrEmpty(_domain)
                    ? _domain
                    : _currentDomain.Name;

                DirectoryContext ctx = (!string.IsNullOrEmpty(_username) && _passwordSecure != null)
                    ? new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName,
                          _username,
                          SecureStringToString(_passwordSecure)
                      )
                    : new DirectoryContext(
                          DirectoryContextType.Domain,
                          domainName
                      );

                Domain domainObj = Domain.GetDomain(ctx);

                var domainEntry = domainObj.GetDirectoryEntry();
                string domainDN = domainEntry.Properties["distinguishedName"][0].ToString();

                using var ldapEntry = GetAuthenticatedEntry($"LDAP://{domainDN}");
                var acl = ldapEntry.ObjectSecurity;

                foreach (ActiveDirectoryAccessRule ace in acl.GetAccessRules(true, true, typeof(NTAccount)))
                {

                    if ((ace.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) != ActiveDirectoryRights.ExtendedRight)
                        continue;

                    if (ace.ObjectType == ReplicateChangesGuid || ace.ObjectType == ReplicateChangesAllGuid)
                    {
                        AddFinding(new ADAuditFinding
                        {
                            ID = "DCSYNC-001",
                            Title = "DCSync rights granted",
                            Severity = AuditSeverity.Critical,
                            Description = $"{ace.IdentityReference.Value} can replicate directory changes",
                            AffectedObject = domainDN,
                            Remediation = "Remove the 'Replicate Directory Changes' permission",
                            References = new List<string> { "MITRE ATT&CK T1003.006" },
                            ComplianceMappings = new List<string> { "MITRE.T1003.006" }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"DCSync rights check failed: {ex.Message}");
                throw;
            }
        }


        private void CheckSPNTargets()
        {
            try
            {
                var searcher = CreateSearcher(
                    "(servicePrincipalName=*)",
                    "servicePrincipalName", "name"
                );

                foreach (SearchResult result in searcher.FindAll())
                {
                    var spns = result.Properties["servicePrincipalName"];
                    foreach (string spn in spns)
                    {
                        if (spn.StartsWith("restrictedkrb/") || spn.StartsWith("HOST/"))
                        {
                            AddFinding(new ADAuditFinding
                            {
                                ID = "SPN-001",
                                Title = "Potentially dangerous SPN",
                                Severity = AuditSeverity.Medium,
                                Description = $"SPN: {spn}",
                                AffectedObject = result.Properties["name"][0].ToString(),
                                Remediation = "Review SPN configuration",
                                References = new List<string> { "MITRE ATT&CK T1558.003" },
                                ComplianceMappings = new List<string> { "MITRE.T1558.003" }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"SPN targets check failed: {ex.Message}");
                throw;
            }
        }

        private void CheckForestTrusts()
        {
            try
            {
                string dnsName = !string.IsNullOrEmpty(_domain)
                    ? _domain
                    : _currentDomain.Name;

                DirectoryContext ctx = (!string.IsNullOrEmpty(_username) && _passwordSecure != null)
                    ? new DirectoryContext(
                          DirectoryContextType.Forest,
                          dnsName,
                          _username,
                          SecureStringToString(_passwordSecure)
                      )
                    : new DirectoryContext(
                          DirectoryContextType.Forest,
                          dnsName
                      );

                Forest forestObj = Forest.GetForest(ctx);

                foreach (ForestTrustRelationshipInformation trustInfo in forestObj.GetAllTrustRelationships())
                {

                    if (trustInfo.TrustType == TrustType.Forest)
                    {
                        AddFinding(new ADAuditFinding
                        {
                            ID = "TRUST-001",
                            Title = "Forest trust detected",
                            Severity = AuditSeverity.Medium,
                            Description = $"Forest trust to {trustInfo.TargetName}",
                            AffectedObject = forestObj.Name,
                            Remediation = "Review trust security settings",
                            References = new List<string> { "CIS AD L2 1.5" },
                            ComplianceMappings = new List<string> { "CIS.1.5" }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Forest trusts check failed: {ex.Message}");
                throw;
            }
        }


        private void CheckConstainedDelegation()
        {
            try
            {
                var searcher = CreateSearcher(
                    "(msDS-AllowedToDelegateTo=*)",
                    "name", "msDS-AllowedToDelegateTo"
                );

                foreach (SearchResult result in searcher.FindAll())
                {
                    var targets = result.Properties["msDS-AllowedToDelegateTo"];
                    foreach (string target in targets)
                    {
                        AddFinding(new ADAuditFinding
                        {
                            ID = "DEL-003",
                            Title = "Constrained delegation configured",
                            Severity = AuditSeverity.High,
                            Description = $"{result.Properties["name"][0]} can delegate to {target}",
                            AffectedObject = result.Properties["name"][0].ToString(),
                            Remediation = "Review constrained delegation settings",
                            References = new List<string> { "MITRE ATT&CK T1558.003" },
                            ComplianceMappings = new List<string> { "MITRE.T1558.003" }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Constrained delegation check failed: {ex.Message}");
                throw;
            }
        }
        #endregion

        #region Helper Methods
        private DirectorySearcher CreateSearcher(string filter, params string[] properties)
        {
            var searcher = new DirectorySearcher(GetDomainEntry())
            {
                Filter = filter,
                PageSize = 1000
            };

            foreach (var prop in properties)
                searcher.PropertiesToLoad.Add(prop);

            return searcher;
        }

        #endregion

        #region Remediation and Reporting
        public void GenerateRemediationScripts()
        {
            try
            {
                string scriptPath = Path.Combine(_config.OutputDirectory, "ADRemediation.ps1");
                var sb = new StringBuilder();
                sb.AppendLine("# Active Directory Remediation Script");
                sb.AppendLine("# Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
                sb.AppendLine("# " + _findings.Count + " findings addressed");
                sb.AppendLine();

                foreach (var finding in _findings.Where(f => !string.IsNullOrEmpty(f.RemediationScript)))
                {
                    sb.AppendLine($"# {finding.Title} ({finding.ID})");
                    sb.AppendLine($"# Severity: {finding.Severity}");
                    sb.AppendLine($"# Affected: {finding.AffectedObject}");
                    sb.AppendLine(finding.RemediationScript);
                    sb.AppendLine();
                }

                File.WriteAllText(scriptPath, sb.ToString());
                Logger.Info($"Remediation script generated: {scriptPath}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to generate remediation script: {ex.Message}");
            }
        }

        public void ExportToCsv(string filePath = null)
        {
            try
            {
                filePath ??= Path.Combine(_config.OutputDirectory, $"ADAudit_{DateTime.Now:yyyyMMddHHmmss}.csv");
                using var writer = new StreamWriter(filePath);

                writer.WriteLine("ID,Title,Severity,Description,AffectedObject,Remediation,Evidence,References,Compliance");

                foreach (var f in _findings)
                {
                    var evidence = f.Evidence?
                        .Replace("\r\n", "; ")
                        .Replace("\n", "; ")
                        .Trim() ?? string.Empty;

                    var references = string.Join(";", f.References);
                    var compliance = string.Join(";", f.ComplianceMappings);

                    writer.WriteLine(
                        $"\"{EscapeCsv(f.ID)}\"," +
                        $"\"{EscapeCsv(f.Title)}\"," +
                        $"\"{f.Severity}\"," +
                        $"\"{EscapeCsv(f.Description)}\"," +
                        $"\"{EscapeCsv(f.AffectedObject)}\"," +
                        $"\"{EscapeCsv(f.Remediation)}\"," +
                        $"\"{EscapeCsv(evidence)}\"," +
                        $"\"{EscapeCsv(references)}\"," +
                        $"\"{EscapeCsv(compliance)}\""
                    );
                }

                Logger.Info($"CSV report generated: {filePath}");
            }
            catch (Exception ex)
            {
                Logger.Error($"CSV export failed: {ex.Message}");
            }
        }


        public void ExportToHtml(string filePath = null, AuditSeverity minSeverity = AuditSeverity.Low)
        {
            try
            {
                minSeverity = _config.MinReportSeverity;
                var filteredFindings = _findings.Where(f => f.Severity >= minSeverity).ToList();
                filePath ??= Path.Combine(_config.OutputDirectory, $"ADAudit_{DateTime.Now:yyyyMMddHHmmss}.html");

                string html = GenerateHtmlReport(filteredFindings);
                File.WriteAllText(filePath, html);
                Logger.Info($"HTML report generated: {filePath}");
            }
            catch (Exception ex)
            {
                Logger.Error($"HTML export failed: {ex.Message}");
            }
        }

        private string GenerateHtmlReport(List<ADAuditFinding> findings)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html>");
            sb.AppendLine("<head>");
            sb.AppendLine("  <meta charset='utf-8' />");
            sb.AppendLine("  <title>AD Security Audit Report</title>");
            sb.AppendLine("  <style>");
            sb.AppendLine("    body { font-family: Arial; font-size: .9em; margin: 20px; }");
            sb.AppendLine("    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }");
            sb.AppendLine("    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }");
            sb.AppendLine("    th { background-color: #eee; position: sticky; top: 0; }");
            sb.AppendLine("    .Critical { background-color: #ff4d4d; color: #fff; }");
            sb.AppendLine("    .High { background-color: #ff944d; }");
            sb.AppendLine("    .Medium { background-color: #ffd966; }");
            sb.AppendLine("    .Low { background-color: #d9ead3; }");
            sb.AppendLine("    .Informational { background-color: #f2f2f2; }");
            sb.AppendLine("    .summary-card { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; background-color: #f9f9f9; }");
            sb.AppendLine("    .severity-chart { display: flex; height: 30px; margin: 10px 0; border: 1px solid #ddd; }");
            sb.AppendLine("    .chart-segment { display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }");
            sb.AppendLine("  </style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine($"  <h1>AD Security Audit Report</h1>");
            sb.AppendLine($"  <p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"  <p>Domain: {_domainRoot.Name}</p>");
            sb.AppendLine($"  <p>Audit Mode: {_mode}</p>");
            sb.AppendLine($"  <p>Min Severity: {_config.MinReportSeverity}</p>");

            // Executive Summary
            sb.AppendLine("  <div class='summary-card'>");
            sb.AppendLine("    <h2>Executive Summary</h2>");
            sb.AppendLine($"    <p>Total Findings: {findings.Count}</p>");
            sb.AppendLine($"    <div class='severity-chart'>{GenerateSeverityChart(findings)}</div>");
            sb.AppendLine($"    <ul>{GenerateSeveritySummary(findings)}</ul>");

            // Compliance Summary
            sb.AppendLine("    <h3>Compliance Summary</h3>");
            sb.AppendLine("    <ul>");
            foreach (var kvp in _complianceCounts.OrderByDescending(k => k.Value))
            {
                sb.AppendLine($"      <li><b>{kvp.Key}:</b> {kvp.Value} findings</li>");
            }
            sb.AppendLine("    </ul>");
            sb.AppendLine("  </div>");

            // Detailed Findings
            sb.AppendLine("  <h2>Detailed Findings</h2>");
            sb.AppendLine("  <table>");
            sb.AppendLine("    <thead>");
            sb.AppendLine("      <tr>");
            sb.AppendLine("        <th>ID</th>");
            sb.AppendLine("        <th>Title</th>");
            sb.AppendLine("        <th>Severity</th>");
            sb.AppendLine("        <th>Description</th>");
            sb.AppendLine("        <th>Affected Object</th>");
            sb.AppendLine("        <th>Remediation</th>");
            sb.AppendLine("        <th>Evidence</th>");
            sb.AppendLine("        <th>References</th>");
            sb.AppendLine("        <th>Compliance</th>");
            sb.AppendLine("      </tr>");
            sb.AppendLine("    </thead>");
            sb.AppendLine("    <tbody>");
            foreach (var f in findings.OrderByDescending(f => (int)f.Severity))
            {
                var evidenceHtml = (f.Evidence ?? "")
                    .Replace("\r\n", "<br/>")
                    .Replace("\n", "<br/>");

                var referencesHtml = string.Join("<br/>", f.References);
                var complianceHtml = string.Join(", ", f.ComplianceMappings);

                sb.AppendLine("      <tr>");
                sb.AppendLine($"        <td>{f.ID}</td>");
                sb.AppendLine($"        <td>{f.Title}</td>");
                sb.AppendLine($"        <td class='{f.Severity}'>{f.Severity}</td>");
                sb.AppendLine($"        <td>{f.Description}</td>");
                sb.AppendLine($"        <td>{f.AffectedObject}</td>");
                sb.AppendLine($"        <td>{f.Remediation}</td>");
                sb.AppendLine($"        <td>{evidenceHtml}</td>");
                sb.AppendLine($"        <td>{referencesHtml}</td>");
                sb.AppendLine($"        <td>{complianceHtml}</td>");
                sb.AppendLine("      </tr>");
            }
            sb.AppendLine("    </tbody>");
            sb.AppendLine("  </table>");

            sb.AppendLine("</body>");
            sb.AppendLine("</html>");
            return sb.ToString();
        }


        private string GenerateSeverityChart(List<ADAuditFinding> findings)
        {
            var counts = new Dictionary<AuditSeverity, int>
            {
                [AuditSeverity.Critical] = findings.Count(f => f.Severity == AuditSeverity.Critical),
                [AuditSeverity.High] = findings.Count(f => f.Severity == AuditSeverity.High),
                [AuditSeverity.Medium] = findings.Count(f => f.Severity == AuditSeverity.Medium),
                [AuditSeverity.Low] = findings.Count(f => f.Severity == AuditSeverity.Low),
                [AuditSeverity.Informational] = findings.Count(f => f.Severity == AuditSeverity.Informational)
            };

            int total = counts.Values.Sum();
            if (total == 0) total = 1; // Prevent division by zero

            var colors = new Dictionary<AuditSeverity, string>
            {
                [AuditSeverity.Critical] = "#ff4d4d",
                [AuditSeverity.High] = "#ff944d",
                [AuditSeverity.Medium] = "#ffd966",
                [AuditSeverity.Low] = "#d9ead3",
                [AuditSeverity.Informational] = "#f2f2f2"
            };

            var html = new StringBuilder();
            foreach (var severity in Enum.GetValues(typeof(AuditSeverity)).Cast<AuditSeverity>().OrderByDescending(s => (int)s))
            {
                int width = (int)Math.Round((counts[severity] / (double)total) * 100);
                if (width > 0)
                {
                    html.Append($"<div class='chart-segment' style='width:{width}%; background-color:{colors[severity]};'>");
                    html.Append($"{counts[severity]} {severity}");
                    html.Append("</div>");
                }
            }

            return html.ToString();
        }

        private string GenerateSeveritySummary(List<ADAuditFinding> findings)
        {
            var html = new StringBuilder();
            foreach (var severity in Enum.GetValues(typeof(AuditSeverity)).Cast<AuditSeverity>().OrderByDescending(s => (int)s))
            {
                int count = findings.Count(f => f.Severity == severity);
                if (count > 0)
                {
                    html.Append($"<li><b>{severity}:</b> {count} findings</li>");
                }
            }
            return html.ToString();
        }

        public void ExportToJson(string filePath = null)
        {
            try
            {
                filePath ??= Path.Combine(_config.OutputDirectory, $"ADAudit_{DateTime.Now:yyyyMMddHHmmss}.json");
                var report = new
                {
                    Domain = _domainRoot.Name,
                    Timestamp = DateTime.Now,
                    Findings = _findings,
                    ComplianceSummary = _complianceCounts
                };

                File.WriteAllText(filePath, JsonConvert.SerializeObject(report, Newtonsoft.Json.Formatting.Indented));
                Logger.Info($"JSON report generated: {filePath}");
            }
            catch (Exception ex)
            {
                Logger.Error($"JSON export failed: {ex.Message}");
            }
        }

        private async Task SubmitToSIEM()
        {
            if (string.IsNullOrEmpty(_config.SiemEndpoint))
                return;
            try
            {
                using var client = new HttpClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.SiemToken}");

                var siemData = new
                {
                    timestamp = DateTime.UtcNow,
                    domain = _domainRoot.Name,
                    findings = _findings.Select(f => new
                    {
                        f.ID,
                        f.Title,
                        severity = f.Severity.ToString(),
                        f.Description,
                        f.AffectedObject
                    }),
                    compliance = _complianceCounts
                };

                var content = new StringContent(
                    JsonConvert.SerializeObject(siemData),
                    Encoding.UTF8,
                    "application/json"
                );

                var response = await client.PostAsync(_config.SiemEndpoint, content);
                if (!response.IsSuccessStatusCode)
                {
                    Logger.Error($"SIEM integration failed: {response.StatusCode}");
                }
                else
                {
                    Logger.Info("Findings submitted to SIEM successfully");
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"SIEM integration error: {ex.Message}");
            }
        }

        public List<ADAuditFinding> CompareWithBaseline(string baselinePath)
        {
            try
            {
                var baseline = JsonConvert.DeserializeObject<List<ADAuditFinding>>(File.ReadAllText(baselinePath));
                return _findings
                    .Where(current => !baseline.Any(b =>
                        b.ID == current.ID &&
                        b.AffectedObject == current.AffectedObject))
                    .ToList();
            }
            catch (Exception ex)
            {
                Logger.Error($"Baseline comparison failed: {ex.Message}");
                return new List<ADAuditFinding>();
            }
        }

        private string EscapeCsv(string input)
        {
            return input?.Replace("\"", "\"\"") ?? string.Empty;
        }
        #endregion

        #region Continuous Monitoring
        public void RunContinuousMonitoring(TimeSpan interval, int maxRuns = 0)
        {
            int runCount = 0;
            while (maxRuns == 0 || runCount < maxRuns)
            {
                runCount++;
                Logger.Info($"Starting monitoring run #{runCount}");
                try
                {
                    RunAudit();
                    ExportToHtml();
                    Thread.Sleep(interval);
                }
                catch (Exception ex)
                {
                    Logger.Error($"Monitoring run failed: {ex.Message}");
                    Thread.Sleep(TimeSpan.FromMinutes(5)); // Wait before retrying
                }
            }
        }
        #endregion
    }

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("-----------------------");
                Console.WriteLine("AD Security Auditor 1.0");
                Console.WriteLine("By: Mohamed Alzhrani");
                Console.WriteLine("0xMaz");
                Console.WriteLine("-----------------------");

                if (args.Contains("--help") || args.Contains("-h"))
                {
                    ShowHelp();
                    return;
                }

                // Parse command line arguments
                var config = new AuditConfig();
                var mode = ParseMode(args);
                string domain = GetArgValue(args, "--domain");
                string user = GetArgValue(args, "--user");
                string pass = GetArgValue(args, "--pass");
                string configFile = GetArgValue(args, "--config");
                bool continuous = args.Contains("--continuous");
                int maxRuns = GetArgIntValue(args, "--maxruns", 0);
                int interval = GetArgIntValue(args, "--interval", 24);

                // Load configuration from file if specified
                if (!string.IsNullOrEmpty(configFile))
                {
                    try
                    {
                        config = JsonConvert.DeserializeObject<AuditConfig>(File.ReadAllText(configFile));
                        Console.WriteLine($"Loaded configuration from: {configFile}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] Error loading config: {ex.Message}");
                        return;
                    }
                }

                // Validate domain format
                if (!string.IsNullOrEmpty(domain) && !Regex.IsMatch(domain, @"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
                {
                    Console.WriteLine("[!] Invalid domain format");
                    return;
                }

                // Create auditor
                var auditor = new ADAuditor(mode, config, domain, user, pass);

                Console.WriteLine($"Mode: {mode}");
                Console.WriteLine($"Domain: {domain ?? "[Current Domain]"}");
                Console.WriteLine("Running security audit...");

                if (continuous)
                {
                    Console.WriteLine($"Continuous monitoring enabled (Interval: {interval} hours)");
                    auditor.RunContinuousMonitoring(TimeSpan.FromHours(interval), maxRuns);
                }
                else
                {
                    var findings = auditor.RunAudit();

                    // Generate reports
                    auditor.ExportToCsv();
                    auditor.ExportToHtml();
                    auditor.ExportToJson();

                    Console.WriteLine($"\nAudit complete. Found {findings.Count} issues.");

                    // Summary counts
                    foreach (var severity in Enum.GetValues(typeof(AuditSeverity)).Cast<AuditSeverity>().OrderByDescending(s => (int)s))
                    {
                        int count = findings.Count(f => f.Severity == severity);
                        if (count > 0)
                        {
                            Console.WriteLine($"  {severity}: {count}");
                        }
                    }

                    // Show critical findings immediately
                    var critical = findings.Where(f => f.Severity >= AuditSeverity.Critical).ToList();
                    if (critical.Any())
                    {
                        Console.WriteLine("\n[!] CRITICAL FINDINGS:");
                        foreach (var finding in critical)
                        {
                            Console.WriteLine($"  {finding.ID}: {finding.Title} ({finding.AffectedObject})");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[!] Error: {ex.Message}");
                Console.WriteLine("Ensure you have proper permissions and domain connectivity");
                Console.WriteLine("type --help for more info");
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine(@"
Usage:
  ADAuditor [--mode=grc|redteam] [--domain=DOMAIN] 
             [--user=USER] [--pass=PASSWORD] [--config=FILE.json]
             [--continuous] [--interval=HOURS] [--maxruns=COUNT]
             
Options:
  --mode       Audit mode (grc or redteam, default: grc)
  --domain     Target domain (FQDN)
  --user       Authentication username
  --pass       Authentication password
  --config     Configuration file path
  --continuous Enable continuous monitoring
  --interval   Hours between scans (default: 24)
  --maxruns    Maximum number of runs (0=unlimited, default: 0)
  --help       Show this help message

Examples:
  Standard audit: 
    ADAuditor --domain=corp.local --user=audituser --pass=Pass123!
  
  Red team audit with config:
    ADAuditor --mode=redteam --config=audit_config.json
  
  Continuous monitoring:
    ADAuditor --continuous --interval=12 --maxruns=10");
        }

        static AuditMode ParseMode(string[] args)
        {
            if (GetArgValue(args, "--mode")?.Equals("redteam", StringComparison.OrdinalIgnoreCase) == true)
                return AuditMode.RedTeam;
            return AuditMode.GRC;
        }

        static string GetArgValue(string[] args, string prefix)
        {
            var arg = args.FirstOrDefault(a => a.StartsWith(prefix + "="));
            return arg?.Substring(prefix.Length + 1);
        }

        static int GetArgIntValue(string[] args, string prefix, int defaultValue)
        {
            var value = GetArgValue(args, prefix);
            if (int.TryParse(value, out int result)) return result;
            return defaultValue;
        }
    }
}
