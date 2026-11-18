import { LightningElement, track } from 'lwc';
import getSummary             from '@salesforce/apex/SocDashboardController.getSummary';
import getDormantUsers        from '@salesforce/apex/SocDashboardController.getDormantUsers';
import getDormantCount        from '@salesforce/apex/SocDashboardController.getDormantCount';
import getPrivilegedUsers     from '@salesforce/apex/SocDashboardController.getPrivilegedUsers';
import getRecentFailedLogins  from '@salesforce/apex/SocDashboardController.getRecentFailedLogins';
import getAuditEvents         from '@salesforce/apex/SocDashboardController.getAuditEvents';
import getExportEnabledUsers  from '@salesforce/apex/SocDashboardController.getExportEnabledUsers';
import getPasswordNeverExpiresUsers from '@salesforce/apex/SocDashboardController.getPasswordNeverExpiresUsers';
import freezeUsers            from '@salesforce/apex/SocFreezeController.freezeUsers';
import unfreezeUsers          from '@salesforce/apex/SocFreezeController.unfreezeUsers';
import getFrozenUsers         from '@salesforce/apex/SocFreezeController.getFrozenUsers';
// CSV EXPORT AUTHORIZATION:
// Returns true only when the CURRENTLY LOGGED-IN user's profile is in
// SocFreezeController.CSV_ALLOWED_PROFILES (System Administrator / Custom Admin).
// Every "Download CSV" button in the template is rendered behind this check, and
// every download handler re-checks it before assembling a file.
import canDownloadCsv         from '@salesforce/apex/SocFreezeController.canDownloadCsv';

const TABS = [
    { id: 'overview',   label: 'Overview',        icon: '⬡' },
    { id: 'dormant',    label: 'Dormant Accounts', icon: '💤' },
    { id: 'privileged', label: 'Privileged Access',icon: '🔑' },
    { id: 'export',     label: 'Export / Download',icon: '📤' },
    { id: 'password',   label: 'Password Policy',  icon: '🔒' },
    { id: 'logins',     label: 'Failed Logins',    icon: '⚠' },
    { id: 'audit',      label: 'Audit Trail',      icon: '📋' },
];

// Message shown (as a tooltip on the locked pill, and as an error if a download
// is somehow invoked without authorization).
const CSV_DENIED_MSG =
    'CSV export is limited to System Administrator and Custom Admin profiles. '
  + 'Ask your Salesforce admin if you need export access.';

// Colors permission-flag pills by severity instead of by a hardcoded
// per-permission name map, so any permission the Apex layer starts
// tracking (existing or new) is automatically styled correctly.
const FP_SEV_CLASS = {
    Critical: 'fp fp-critical',
    High:     'fp fp-high',
    Medium:   'fp fp-medium',
    Low:      'fp fp-low',
};

function buildFlagPills(flagDetails) {
    return (flagDetails || []).map(f => ({
        label: f.label,
        cls:   FP_SEV_CLASS[f.severity] || 'fp fp-low',
    }));
}

const SEV_CLASS = {
    'Critical': 'badge badge-critical',
    'High':     'badge badge-high',
    'Medium':   'badge badge-medium',
    'Low':      'badge badge-low',
};

const ROW_CLASS = {
    'Critical': 'row-critical',
    'High':     'row-high',
    'Medium':   '',
};

const AUDIT_QUICK_RANGES = [
    { hours: 0.0833, label: 'Last 5 minutes' },
    { hours: 0.25,   label: 'Last 15 minutes' },
    { hours: 0.5,    label: 'Last 30 minutes' },
    { hours: 1,      label: 'Last 1 hour' },
    { hours: 3,      label: 'Last 3 hours' },
    { hours: 6,      label: 'Last 6 hours' },
    { hours: 12,     label: 'Last 12 hours' },
    { hours: 24,     label: 'Last 24 hours' },
    { hours: 48,     label: 'Last 2 days' },
    { hours: 168,    label: 'Last 7 days' },
    { hours: 720,    label: 'Last 30 days' },
    { hours: 2160,   label: 'Last 90 days' },
    { hours: 4380,   label: 'Last 6 months' },
    { hours: 0,      label: 'All time' },
];

const AUDIT_DEFAULT_LIMIT = 5000;

// ── RULE DEFINITIONS ──────────────────────────────────────────────────────────
// Each key matches the data-rules attribute on the rule-tag spans in the HTML.
// NOTE: these "severity" values describe each *rule's* documented risk level for
// the hover tooltip only. They are unrelated to (and were not removed with) the
// per-event Severity column/filter that was removed from the Audit Trail table.
const RULE_DEFINITIONS = {
    dormant: {
        title: 'Section H — Dormant Account Detection',
        rules: [
            {
                id: 'H1',
                name: 'Dormant Accounts (90+ Days)',
                logic: 'DATEDIFF(NOW(), lastLoginDate) ≥ 90',
                severity: 'High',
            },
            {
                id: 'H2',
                name: 'Dormant Privileged Users',
                logic: 'Dormant ≥ 90 days AND ModifyAllData = true',
                severity: 'Critical',
            },
            {
                id: 'H3',
                name: 'Dormant Users With Export Access',
                logic: 'Dormant ≥ 90 days AND DataExport = true',
                severity: 'Critical',
            },
        ],
    },
    privileged: {
        title: 'Sections B & C — Privileged Access',
        rules: [
            {
                id: 'B1',
                name: 'Modify All Data Permission',
                logic: 'PermissionsModifyAllData = true',
                severity: 'Critical',
            },
            {
                id: 'B2',
                name: 'Modify All Data + Inactive User',
                logic: 'ModifyAllData = true AND lastLoginDate > 90 days',
                severity: 'Critical',
            },
            {
                id: 'B3',
                name: 'Duplicate Privileged Assignments',
                logic: 'Same user: multiple admin permission sets',
                severity: 'Medium',
            },
            {
                id: 'C1',
                name: 'View All Data Permission',
                logic: 'PermissionsViewAllData = true',
                severity: 'High',
            },
            {
                id: 'C2',
                name: 'View All + Modify All Combination',
                logic: 'ModifyAllData = true AND ViewAllData = true',
                severity: 'Critical',
            },
        ],
    },
    export: {
        title: 'Section E — Download & Export Monitoring',
        rules: [
            {
                id: 'E1',
                name: 'Data Export Permission',
                logic: 'PermissionsDataExport = true',
                severity: 'High',
            },
            {
                id: 'E2',
                name: 'Export Report Permission',
                logic: 'PermissionsExportReport = true',
                severity: 'High',
            },
            {
                id: 'E3',
                name: 'Query All Files Permission',
                logic: 'PermissionsQueryAllFiles = true',
                severity: 'Critical',
            },
            {
                id: 'E4',
                name: 'Bulk API Hard Delete Permission',
                logic: 'PermissionsBulkApiHardDelete = true',
                severity: 'Critical',
            },
            {
                id: 'E5',
                name: 'API Enabled Access',
                logic: 'PermissionsApiEnabled = true',
                severity: 'Medium',
            },
        ],
    },
    password: {
        title: 'Section G — Password Policy',
        rules: [
            {
                id: 'G1',
                name: 'Password Never Expires',
                logic: 'PermissionsPasswordNeverExpires = true',
                severity: 'High',
            },
        ],
    },
    logins: {
        title: 'Section F — Login & Authentication Monitoring',
        rules: [
            {
                id: 'F1',
                name: 'Failed Login Spike',
                logic: 'status = Failed AND count > 5 in 30 mins',
                severity: 'High',
            },
            {
                id: 'F2',
                name: 'Credential Stuffing Detection',
                logic: 'Same IP: failed logins across multiple users',
                severity: 'Critical',
            },
            {
                id: 'F3',
                name: 'Login From Inactive/Frozen User',
                logic: 'User.isActive = false AND login exists',
                severity: 'Critical',
            },
            {
                id: 'F4',
                name: 'Password Lockout Monitoring',
                logic: 'Repeated failures leading to lockout',
                severity: 'High',
            },
            {
                id: 'F5',
                name: 'MFA Disabled Users',
                logic: 'PermissionsForceTwoFactor = false',
                severity: 'Critical',
            },
            {
                id: 'F6',
                name: 'MFA Bypass Permission',
                logic: 'PermissionsBypassMFAForUiLogins = true',
                severity: 'Critical',
            },
            {
                id: 'F7',
                name: 'Suspicious Country Login',
                logic: 'Login country differs from baseline',
                severity: 'High',
            },
            {
                id: 'F8',
                name: 'Weak TLS Usage',
                logic: 'tlsProtocol IN (TLS 1.0, TLS 1.1)',
                severity: 'Medium',
            },
        ],
    },
    audit: {
        title: 'Section A — Managed Package Governance',
        rules: [
            {
                id: 'A1',
                name: 'Install Managed Package Permission',
                logic: 'permissionSetName LIKE %Package% OR ModifyAllData = true',
                severity: 'Critical',
            },
            {
                id: 'A2',
                name: 'Customize Application Access',
                logic: 'ModifyAllData = true OR ManageUsers = true',
                severity: 'Critical',
            },
            {
                id: 'A3',
                name: 'Managed Package Installation Event',
                logic: 'SetupAuditTrail: action LIKE %package%',
                severity: 'Critical',
            },
            {
                id: 'A4',
                name: 'Bulk Permission Changes',
                logic: 'Multiple permission/profile changes in short duration',
                severity: 'Critical',
            },
        ],
    },
};

const SEV_PILL_CLS = {
    Critical: 'rule-sev rule-sev-critical',
    High:     'rule-sev rule-sev-high',
    Medium:   'rule-sev rule-sev-medium',
    Low:      'rule-sev rule-sev-low',
};
// ─────────────────────────────────────────────────────────────────────────────

function sfRecordUrl(recordId, objectApiName) {
    return `/lightning/r/${objectApiName}/${recordId}/view`;
}

function escapeCsvCell(val) {
    if (val === null || val === undefined) return '';
    const str = String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
}

function buildCsv(headers, rows) {
    const lines = [headers.map(escapeCsvCell).join(',')];
    rows.forEach(r => lines.push(r.map(escapeCsvCell).join(',')));
    return lines.join('\n');
}

function dateToLocalInput(d) {
    if (!d || isNaN(d.getTime())) return '';
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function localInputToDate(s) {
    if (!s) return null;
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
}

// permissionSetName on a row is a comma-joined list of ALL non-profile
// permission sets that user holds (see resolvePermissionSetNames in Apex).
// This splits it back into individual names so dropdown options and
// filtering operate per-permission-set, not per-unique-combination — fixes
// both the "Permission Set" dropdown running off-screen (options were
// previously entire multi-set combinations, sometimes 100+ chars long) and
// the filter only matching users whose *entire* combination equalled the
// selected string.
function splitPermSetNames(str) {
    if (!str) return [];
    return str.split(',').map(s => s.trim()).filter(Boolean);
}

export default class SocDashboard extends LightningElement {

    @track activeTab    = 'overview';
    @track loading      = false;
    @track errorMessage = null;
    @track currentTime  = '';
    // Light mode is now the default theme (per requirement). Users can still
    // toggle to Dark via the theme button; nothing else needed to change,
    // since shellCls already applies .soc-shell--light whenever this is false.
    @track isDarkTheme  = false;

    // ── CSV EXPORT AUTHORIZATION ──────────────────
    // Starts false so the button never flashes into view before Apex answers.
    @track csvAllowed = false;

    // raw data
    @track summary          = {};
    @track _dormantUsers    = [];
    @track _privilegedUsers = [];
    @track failedLogins     = [];
    @track auditEvents      = [];
    @track exportUsers      = [];
    @track passwordUsers    = [];

    @track dormantSearch         = '';
    @track dormantSortCol        = 'dormantDays';
    @track dormantSortDir        = 'desc';
    @track dormantProfileFilter  = '';
    @track dormantPermSetFilter  = '';
    @track dormantSeverityFilter = '';
    @track dormantLimit          = 10000;
    @track dormantCustomLimit    = 10000;
    @track dormantTotalCount     = null;

    // dormant sub-tab + freeze/selection state
    @track dormantSubTab         = 'active';
    @track dormantSelectedIds    = [];
    @track frozenUsers           = [];
    @track frozenSearch          = '';
    @track frozenSelectedIds     = [];
    @track freezeInProgress      = false;
    @track freezeResultMsg       = '';
    @track freezeResultSuccess   = true;
    @track unfreezeResultMsg     = '';
    @track unfreezeResultSuccess = true;

    // privileged search / sort / filter / flag state
    @track privSearch           = '';
    @track privSortCol          = 'severity';
    @track privSortDir          = 'desc';
    @track privProfileFilter    = '';
    @track privPermSetFilter    = '';
    @track privSeverityFilter   = '';
    @track privActiveFlags      = [];

    // export search / sort / filter / flag state
    @track exportSearch         = '';
    @track exportSortCol        = 'severity';
    @track exportSortDir        = 'desc';
    @track exportProfileFilter  = '';
    @track exportPermSetFilter  = '';
    @track exportSeverityFilter = '';
    @track exportActiveFlags    = [];

    // audit trail state
    // NOTE: `auditSeverityFilter` was removed as part of the "Remove Severity
    // from Audit Trail" requirement. `auditPermSetFilter` was added in its
    // place to support the new "Search by Permission Set" filter, implemented
    // the same way as the existing Profile filters elsewhere in this app.
    @track auditSearch          = '';
    @track auditSortCol         = 'createdDate';
    @track auditSortDir         = 'desc';
    @track auditSectionFilter   = '';
    @track auditActionFilter    = '';
    @track auditPermSetFilter   = '';
    @track auditWindowHours     = 0;
    @track auditFromDate        = null;
    @track auditToDate          = null;
    @track auditFromInput       = '';
    @track auditToInput         = '';
    @track auditTimePickerOpen  = false;
    @track auditRecordLimit     = AUDIT_DEFAULT_LIMIT;

    // password search / sort / filter / flag state
    @track pwdSearch            = '';
    @track pwdSortCol           = 'severity';
    @track pwdSortDir           = 'desc';
    @track pwdProfileFilter     = '';
    @track pwdPermSetFilter     = '';
    @track pwdSeverityFilter    = '';
    @track pwdActiveFlags       = [];

    // failed logins state
    @track loginWindowHours  = 48;
    @track loginCustomValue  = 48;
    @track loginCustomUnit   = 'hours';
    @track loginSearch       = '';
    @track loginStatusFilter = '';
    @track loginCountryFilter= '';
    @track loginTlsFilter    = '';
    @track loginSortCol      = 'loginTime';
    @track loginSortDir      = 'desc';
    @track loginGroupByField  = '';
    @track _loginExpandedGrps = {};

    // ── RULE POPOVER STATE ────────────────────────
    @track rulePopoverVisible = false;
    @track rulePopoverStyle   = '';
    @track rulePopoverTitle   = '';
    @track rulePopoverItems   = [];

    _popoverHovered   = false;
    _ruleTagHovered   = false;
    _popoverHideTimer = null;
    // ─────────────────────────────────────────────

    _timer;

    connectedCallback() {
        this._updateTime();
        this._timer = setInterval(() => this._updateTime(), 60000);
        this._loadCsvAccess();
        this._loadAll();
    }

    disconnectedCallback() {
        clearInterval(this._timer);
    }

    _updateTime() {
        this.currentTime = new Date().toLocaleString('en-IN', {
            timeZone: 'Asia/Kolkata',
            day: '2-digit', month: 'short', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    }

    // ── CSV EXPORT AUTHORIZATION ──────────────────

    /**
     * Asks Apex whether the CURRENT user may export SOC data.
     * Any failure is treated as "not allowed" — the button stays hidden.
     */
    async _loadCsvAccess() {
        try {
            this.csvAllowed = await canDownloadCsv() === true;
        } catch (err) {
            this.csvAllowed = false;
        }
    }

    /** Drives every `if:true={canExportCsv}` block in the template. */
    get canExportCsv()  { return this.csvAllowed === true; }

    /** Tooltip on the locked pill non-admins see instead of the button. */
    get csvLockedTitle() { return CSV_DENIED_MSG; }

    /**
     * Second gate: even if a download handler is reached some other way
     * (stale render, console call), nothing is assembled without authorization.
     */
    _guardCsv() {
        if (this.csvAllowed !== true) {
            this.errorMessage = CSV_DENIED_MSG;
            return false;
        }
        return true;
    }

    async _loadAll() {
        this.loading      = true;
        this.errorMessage = null;
        try {
            const [
                summaryData, dormant, dormantCount, privileged,
                logins, audit, exportData, pwdData, frozen
            ] = await Promise.all([
                getSummary(),
                getDormantUsers({ recordLimit: this.dormantLimit }),
                getDormantCount(),
                getPrivilegedUsers(),
                getRecentFailedLogins({ hoursBack: this.loginWindowHours }),
                getAuditEvents({
                    fromDate:    this._computeAuditFromIso(),
                    toDate:      this._computeAuditToIso(),
                    recordLimit: this.auditRecordLimit
                }),
                getExportEnabledUsers(),
                getPasswordNeverExpiresUsers(),
                getFrozenUsers(),
            ]);

            this.summary           = summaryData || {};
            this._dormantUsers     = this._enrichDormantRows(dormant    || []);
            this.dormantTotalCount = dormantCount || 0;
            this._privilegedUsers  = this._enrichPrivilegedRows(privileged || []);
            this.exportUsers       = this._enrichExportRows(exportData || []);
            this.passwordUsers     = this._enrichPasswordRows(pwdData    || []);
            this.failedLogins      = this._enrichLoginRows(logins    || []);
            this.auditEvents       = this._enrichAuditRows(audit     || []);
            this.frozenUsers       = this._enrichFrozenRows(frozen    || []);

        } catch (err) {
            this.errorMessage = 'Error loading SOC data: ' + (err.body?.message || err.message || JSON.stringify(err));
        } finally {
            this.loading = false;
        }
    }

    async _loadFrozen() {
        try {
            const frozen = await getFrozenUsers();
            this.frozenUsers       = this._enrichFrozenRows(frozen || []);
            this.frozenSelectedIds = [];
        } catch (err) {
            this.errorMessage = 'Error loading frozen users: ' + (err.body?.message || err.message);
        }
    }

    async _loadLogins() {
        this.loading = true;
        try {
            const logins = await getRecentFailedLogins({ hoursBack: this.loginWindowHours });
            this.failedLogins = this._enrichLoginRows(logins || []);
        } catch (err) {
            this.errorMessage = 'Error loading login data: ' + (err.body?.message || err.message || JSON.stringify(err));
        } finally {
            this.loading = false;
        }
    }

    async _loadDormant() {
        this.loading = true;
        try {
            const [dormant, count] = await Promise.all([
                getDormantUsers({ recordLimit: this.dormantLimit }),
                getDormantCount(),
            ]);
            this._dormantUsers      = this._enrichDormantRows(dormant || []);
            this.dormantTotalCount  = count || 0;
            this.dormantSelectedIds = [];
        } catch (err) {
            this.errorMessage = 'Error loading dormant data: ' + (err.body?.message || err.message || JSON.stringify(err));
        } finally {
            this.loading = false;
        }
    }

    async _loadAudit() {
        this.loading = true;
        try {
            const audit = await getAuditEvents({
                fromDate:    this._computeAuditFromIso(),
                toDate:      this._computeAuditToIso(),
                recordLimit: this.auditRecordLimit
            });
            this.auditEvents = this._enrichAuditRows(audit || []);
        } catch (err) {
            this.errorMessage = 'Error loading audit data: ' + (err.body?.message || err.message || JSON.stringify(err));
        } finally {
            this.loading = false;
        }
    }

    _computeAuditFromIso() {
        if (this.auditFromDate) return this.auditFromDate;
        if (!this.auditWindowHours || this.auditWindowHours <= 0) return null;
        const cutoff = new Date(Date.now() - (this.auditWindowHours * 3600 * 1000));
        return cutoff.toISOString();
    }

    _computeAuditToIso() {
        return this.auditToDate || null;
    }

    // ── ROW ENRICHMENT ────────────────────────────

    _enrichDormantRows(rows) {
        return rows.map(r => {
            const days = r.dormantDays;
            return {
                ...r,
                selected:         this.dormantSelectedIds.includes(r.userId),
                userUrl:          sfRecordUrl(r.userId, 'User'),
                profileUrl:       r.profileId ? sfRecordUrl(r.profileId, 'Profile') : null,
                dormantDaysLabel: days === -1 ? 'Never logged in' : `${days} days`,
                riskFlags: r.riskReason
                    ? r.riskReason.replace(/^(Never logged in|Dormant \d+ days)\s*·?\s*/, '').trim() || '—'
                    : '—',
                statusLabel: r.isActive ? 'Active' : 'Inactive',
                statusCls:   r.isActive ? 'badge badge-low' : 'badge badge-medium',
                severityCls: SEV_CLASS[r.severity] || 'badge badge-low',
                rowCls:      ROW_CLASS[r.severity]  || '',
            };
        });
    }

    _enrichFrozenRows(rows) {
        return rows.map(r => ({
            ...r,
            selected: this.frozenSelectedIds.includes(r.userId),
        }));
    }

    _enrichPrivilegedRows(rows) {
        return rows.map(r => {
            const flagList = (r.flagDetails || []).map(f => f.permName);
            return {
                ...r,
                userUrl:    sfRecordUrl(r.userId, 'User'),
                profileUrl: r.profileId ? sfRecordUrl(r.profileId, 'Profile') : null,
                flagList,
                flagPills:   buildFlagPills(r.flagDetails),
                severityCls: SEV_CLASS[r.severity] || 'badge badge-low',
                rowCls:      ROW_CLASS[r.severity]  || '',
            };
        });
    }

    _enrichLoginRows(rows) {
        return rows.map((r, idx) => ({
            ...r,
            _key:           `${r.loginTime || ''}_${idx}`,
            userUrl:        r.userId ? sfRecordUrl(r.userId, 'User') : null,
            rowCls:         'row-high',
            tlsCls:         (r.tlsProtocol === 'TLS 1.0' || r.tlsProtocol === 'TLS 1.1') ? 'cell-tls-weak' : '',
            loginType:      r.loginType      || '',
            loginSubType:   r.loginSubType   || '',
            application:    r.application    || '',
            loginUrl:       r.loginUrl       || '',
            experience:     r.experience     || '',
            forwardedForIp: r.forwardedForIp || '',
        }));
    }

    _enrichExportRows(rows) {
        return rows.map(r => {
            const flagList = (r.flagDetails || []).map(f => f.permName);
            return {
                ...r,
                userUrl:    sfRecordUrl(r.userId, 'User'),
                profileUrl: r.profileId ? sfRecordUrl(r.profileId, 'Profile') : null,
                flagList,
                flagPills:   buildFlagPills(r.flagDetails),
                severityCls: SEV_CLASS[r.severity] || 'badge badge-low',
                rowCls:      ROW_CLASS[r.severity]  || '',
            };
        });
    }


    // Severity-derived styling (severityCls / rowCls) has been removed here as
    // part of the "Remove Severity from Audit Trail" requirement — the Audit
    // Trail table no longer surfaces a Severity value or coloring at all.
    _enrichAuditRows(rows) {
        return rows.map(r => ({
            ...r,
            userUrl: r.createdById ? sfRecordUrl(r.createdById, 'User') : null,
            rowCls:  '',
        }));
    }

    _enrichPasswordRows(rows) {
        const fmtDt = d => {
            if (!d || isNaN(d.getTime())) return '—';
            return d.toLocaleString('en-IN', {
                day: '2-digit', month: '2-digit', year: 'numeric',
                hour: '2-digit', minute: '2-digit', hour12: true
            });
        };

        return rows.map(r => {
            const flagList = (r.flagDetails || []).map(f => f.permName);

            let lastPwdDate = null;
            if (r.lastPasswordChangeDate) {
                lastPwdDate = new Date(r.lastPasswordChangeDate);
                if (isNaN(lastPwdDate.getTime())) lastPwdDate = null;
            }

            let nextPwdDisplay = 'Never (policy exempt)';
            let nextPwdChangeCls = 'cell-date cell-pwd-never';
            if (r.passwordExpiryDays && r.passwordExpiryDays > 0 && lastPwdDate) {
                const next = new Date(lastPwdDate.getTime() + r.passwordExpiryDays * 86400000);
                nextPwdDisplay = fmtDt(next);
                const now = Date.now();
                nextPwdChangeCls = next.getTime() < now
                    ? 'cell-date cell-pwd-overdue'
                    : 'cell-date cell-pwd-upcoming';
            }

            return {
                ...r,
                userUrl:    sfRecordUrl(r.userId, 'User'),
                profileUrl: r.profileId ? sfRecordUrl(r.profileId, 'Profile') : null,
                flagList,
                flagPills:   buildFlagPills(r.flagDetails),
                severityCls:      SEV_CLASS[r.severity] || 'badge badge-low',
                rowCls:           ROW_CLASS[r.severity]  || '',
                lastPasswordChange:  lastPwdDate ? fmtDt(lastPwdDate) : '—',
                nextPasswordChange:  nextPwdDisplay,
                nextPwdChangeCls:    nextPwdChangeCls,
                _lastPwdTs: lastPwdDate ? lastPwdDate.getTime() : 0,
            };
        });
    }

    // ── CSV DOWNLOAD ──────────────────────────────
    // Every handler below starts with _guardCsv(). The buttons themselves are
    // only rendered for authorized users (see canExportCsv in the template);
    // this is the belt-and-braces second check.

    _triggerCsvDownload(csvString, filename) {
        if (!this._guardCsv()) return;

        const bom     = '\uFEFF';
        const encoded = encodeURIComponent(bom + csvString);
        const dataUri = 'data:text/csv;charset=utf-8,' + encoded;
        const a      = document.createElement('a');
        a.href       = dataUri;
        a.download   = filename;
        a.style.cssText = 'display:none;position:fixed;top:-9999px;left:-9999px;';
        document.body.appendChild(a);
        a.click();
        window.setTimeout(() => { if (a.parentNode) { a.parentNode.removeChild(a); } }, 200);
    }

    // Added 'Permission Set' column, matching how Profile already appears.
    downloadDormantCsv() {
        if (!this._guardCsv()) return;
        const headers = ['Name', 'Username', 'Profile', 'Permission Set', 'Last Login', 'Days Dormant', 'Status', 'Risk Flags', 'Severity'];
        const rows = this.dormantUsersFiltered.map(u => [
            u.name, u.userName, u.profileName, u.permissionSetName || '', u.lastLoginDate,
            u.dormantDaysLabel, u.statusLabel, u.riskFlags, u.severity
        ]);
        this._triggerCsvDownload(buildCsv(headers, rows), 'soc_dormant_users.csv');
    }

    downloadFrozenCsv() {
        if (!this._guardCsv()) return;
        const headers = ['Name', 'Username', 'Profile', 'Last Login', 'Frozen On'];
        const rows = this.frozenUsersFiltered.map(u => [
            u.name, u.userName, u.profileName, u.lastLoginDate, u.frozenDate
        ]);
        this._triggerCsvDownload(buildCsv(headers, rows), 'soc_frozen_accounts.csv');
    }

    downloadPrivCsv() {
        if (!this._guardCsv()) return;
        const headers = ['Name', 'Username', 'Profile', 'Permission Set', 'Last Login', 'Risk Flags (with source)', 'Severity'];
        const rows = this.privUsersFiltered.map(u => [
            u.name, u.userName, u.profileName, u.permissionSetName || '', u.lastLoginDate,
            (u.flagDetails || []).map(f => f.label).join('; '), u.severity
        ]);
        this._triggerCsvDownload(buildCsv(headers, rows), 'soc_privileged_users.csv');
    }

    downloadExportCsv() {
        if (!this._guardCsv()) return;
        const headers = ['Name', 'Username', 'Profile', 'Permission Set', 'Last Login', 'Export Flags (with source)', 'Severity'];
        const rows = this.exportUsersFiltered.map(u => [
            u.name, u.userName, u.profileName, u.permissionSetName || '', u.lastLoginDate,
            (u.flagDetails || []).map(f => f.label).join('; '), u.severity
        ]);
        this._triggerCsvDownload(buildCsv(headers, rows), 'soc_export_users.csv');
    }

    downloadPwdCsv() {
        if (!this._guardCsv()) return;
        const headers = ['Name', 'Username', 'Profile', 'Permission Set', 'Last Login', 'Last Pwd Change', 'Next Pwd Change', 'Risk (with source)', 'Severity'];
        const rows = this.pwdUsersFiltered.map(u => [
            u.name, u.userName, u.profileName, u.permissionSetName || '', u.lastLoginDate,
            u.lastPasswordChange, u.nextPasswordChange,
            (u.flagDetails || []).map(f => f.label).join('; '), u.severity
        ]);
        this._triggerCsvDownload(buildCsv(headers, rows), 'soc_password_policy.csv');
    }

    downloadLoginCsv() {
        if (!this._guardCsv()) return;
        const headers = ['Time', 'Name', 'Username', 'User ID', 'Source IP', 'Login Type', 'Subtype', 'Status', 'Application', 'Login URL', 'Experience', 'Fwd For IP', 'Browser', 'Country', 'TLS'];
        const rows = this.loginRowsFiltered.map(l => [
            l.loginTime, l.userFullName, l.userName, l.userId,
            l.sourceIp, l.loginType, l.loginSubType, l.status,
            l.application, l.loginUrl, l.experience, l.forwardedForIp,
            l.browser, l.country, l.tlsProtocol
        ]);
        this._triggerCsvDownload(buildCsv(headers, rows), 'soc_failed_logins.csv');
    }

    // Severity column removed from export; Permission Set (new) added instead.
    downloadAuditCsv() {
        if (!this._guardCsv()) return;
        const headers = ['Date', 'By', 'Section', 'Action', 'Permission Set', 'Detail'];
        const rows = this.auditEventsFiltered.map(a => [
            a.createdDate, a.createdByName, a.section, a.action, a.permissionSetName || '', a.display
        ]);
        this._triggerCsvDownload(buildCsv(headers, rows), 'soc_audit_trail.csv');
    }

    // ── DORMANT ───────────────────────────────────

    get dormantUsersFiltered() {
        let list = [...this._dormantUsers];

        const q = this.dormantSearch.toLowerCase().trim();
        if (q) {
            list = list.filter(u =>
                (u.name     || '').toLowerCase().includes(q) ||
                (u.userName || '').toLowerCase().includes(q)
            );
        }
        if (this.dormantProfileFilter)  list = list.filter(u => u.profileName === this.dormantProfileFilter);
        if (this.dormantPermSetFilter)  list = list.filter(u => splitPermSetNames(u.permissionSetName).includes(this.dormantPermSetFilter));
        if (this.dormantSeverityFilter) list = list.filter(u => u.severity    === this.dormantSeverityFilter);

        const col = this.dormantSortCol;
        const dir = this.dormantSortDir === 'asc' ? 1 : -1;
        list.sort((a, b) => {
            if (col === 'dormantDays') {
                const va = a.dormantDays === -1 ? 999999 : a.dormantDays;
                const vb = b.dormantDays === -1 ? 999999 : b.dormantDays;
                return dir * (va - vb);
            }
            if (col === 'severity') {
                const rank = { Critical: 2, High: 1, Medium: 0, Low: -1 };
                return dir * ((rank[a.severity] || 0) - (rank[b.severity] || 0));
            }
            if (col === 'isActive') {
                const va = a.isActive ? 1 : 0;
                const vb = b.isActive ? 1 : 0;
                return dir * (va - vb);
            }
            const va = (a[col] || '').toLowerCase();
            const vb = (b[col] || '').toLowerCase();
            return dir * va.localeCompare(vb);
        });

        const selectedSet = new Set(this.dormantSelectedIds);
        return list.map(u => ({
            ...u,
            selected: selectedSet.has(u.userId),
            rowCls: selectedSet.has(u.userId)
                ? 'row-selected'
                : (u.severity === 'Critical' ? 'row-critical' : u.severity === 'High' ? 'row-high' : ''),
        }));
    }

    get dormantFilteredCount()  { return this.dormantUsersFiltered.length; }
    get dormantNoResults()      { return this._dormantUsers.length > 0 && this.dormantUsersFiltered.length === 0; }

    get dormantProfileOptions() {
        const seen = new Set();
        this._dormantUsers.forEach(u => { if (u.profileName) seen.add(u.profileName); });
        return [...seen].sort();
    }

    // Flattens each user's comma-joined permissionSetName into individual
    // set names before deduping, so the dropdown lists real permission set
    // names (short) instead of whole per-user combinations (which could run
    // to dozens of names and hundreds of characters on one option).
    get dormantPermSetOptions() {
        const seen = new Set();
        this._dormantUsers.forEach(u => splitPermSetNames(u.permissionSetName).forEach(n => seen.add(n)));
        return [...seen].sort();
    }

    get dormantSortIcon() {
        const active = this.dormantSortCol;
        const dir    = this.dormantSortDir;
        const icon   = col => active === col ? (dir === 'asc' ? ' ▲' : ' ▼') : ' ⇅';
        return {
            name:          icon('name'),
            userName:      icon('userName'),
            profileName:   icon('profileName'),
            lastLoginDate: icon('lastLoginDate'),
            dormantDays:   icon('dormantDays'),
            isActive:      icon('isActive'),
            severity:      icon('severity'),
        };
    }

    handleDormantSearch(evt)    { this.dormantSearch = evt.target.value; }
    clearDormantSearch()        { this.dormantSearch = ''; }
    handleProfileFilter(evt)    { this.dormantProfileFilter = evt.target.value; }
    handleDormantPermSetFilter(evt) { this.dormantPermSetFilter = evt.target.value; }
    handleSeverityFilter(evt)   { this.dormantSeverityFilter = evt.target.value; }
    resetDormantFilters() {
        this.dormantSearch         = '';
        this.dormantProfileFilter  = '';
        this.dormantPermSetFilter  = '';
        this.dormantSeverityFilter = '';
        this.dormantSortCol        = 'dormantDays';
        this.dormantSortDir        = 'desc';
    }
    handleDormantSort(evt) {
        const col = evt.currentTarget.dataset.col;
        if (this.dormantSortCol === col) {
            this.dormantSortDir = this.dormantSortDir === 'asc' ? 'desc' : 'asc';
        } else {
            this.dormantSortCol = col;
            this.dormantSortDir = 'asc';
        }
    }

    get dormantLimitInfo() {
        const loaded = this._dormantUsers.length;
        const total  = this.dormantTotalCount;
        if (total === null) return `Showing ${loaded} users`;
        if (loaded >= total) return `Showing all ${total} dormant users`;
        return `Showing ${loaded} of ${total} dormant users`;
    }

    get dormantHasMore() {
        return this.dormantTotalCount !== null && this._dormantUsers.length < this.dormantTotalCount;
    }

    get dormantLimitPresets() {
        const presets = [100, 250, 500, 1000, 2500, 5000];
        return presets.map(n => ({
            value: n,
            label: String(n),
            cls: 'lp-btn' + (this.dormantLimit === n ? ' lp-btn-active' : ''),
        }));
    }

    handleDormantLimitPreset(evt) {
        const val = parseInt(evt.currentTarget.dataset.value, 10);
        this.dormantLimit       = val;
        this.dormantCustomLimit = val;
        this._loadDormant();
    }

    handleDormantCustomLimitInput(evt) { this.dormantCustomLimit = evt.target.value; }

    applyDormantCustomLimit() {
        const val = parseInt(this.dormantCustomLimit, 10);
        if (!val || val < 1) return;
        this.dormantLimit = Math.min(val, 10000);
        this._loadDormant();
    }

    loadAllDormant() {
        const total = this.dormantTotalCount;
        if (total && total > 0) {
            this.dormantLimit       = Math.min(total, 10000);
            this.dormantCustomLimit = this.dormantLimit;
            this._loadDormant();
        }
    }

    get dormantSubTabCls() {
        return {
            active: 'sub-tab-btn' + (this.dormantSubTab === 'active' ? ' sub-tab-active' : ''),
            frozen: 'sub-tab-btn' + (this.dormantSubTab === 'frozen' ? ' sub-tab-active' : ''),
        };
    }
    get isDormantSubActive() { return this.dormantSubTab === 'active'; }
    get isDormantSubFrozen() { return this.dormantSubTab === 'frozen'; }

    handleDormantSubTab(evt) {
        this.dormantSubTab = evt.currentTarget.dataset.sub;
        if (this.dormantSubTab === 'frozen') this._loadFrozen();
    }

    get dormantSelectedCount()       { return this.dormantSelectedIds.length; }
    get dormantSelectedCountPlural() { return this.dormantSelectedIds.length === 1 ? '' : 's'; }
    get hasDormantSelection()        { return this.dormantSelectedIds.length > 0; }

    get allDormantSelected() {
        const filtered = this.dormantUsersFiltered;
        return filtered.length > 0 && filtered.every(u => this.dormantSelectedIds.includes(u.userId));
    }

    handleSelectAllDormant(evt) {
        if (evt.target.checked) {
            const ids = this.dormantUsersFiltered.map(u => u.userId);
            this.dormantSelectedIds = [...new Set([...this.dormantSelectedIds, ...ids])];
        } else {
            const filteredIds = new Set(this.dormantUsersFiltered.map(u => u.userId));
            this.dormantSelectedIds = this.dormantSelectedIds.filter(id => !filteredIds.has(id));
        }
    }

    handleDormantRowSelect(evt) {
        const uid = evt.currentTarget.dataset.userid;
        if (evt.target.checked) {
            if (!this.dormantSelectedIds.includes(uid)) {
                this.dormantSelectedIds = [...this.dormantSelectedIds, uid];
            }
        } else {
            this.dormantSelectedIds = this.dormantSelectedIds.filter(id => id !== uid);
        }
    }

    clearDormantSelection() { this.dormantSelectedIds = []; }

    async handleFreezeSelected() {
        if (this.dormantSelectedIds.length === 0) return;
        this.freezeInProgress = true;
        this.freezeResultMsg  = '';
        try {
            const result = await freezeUsers({ userIds: this.dormantSelectedIds });
            this.freezeResultSuccess = result.success;
            this.freezeResultMsg = result.message
                + (result.skippedNames && result.skippedNames.length
                    ? ' Skipped: ' + result.skippedNames.join(', ')
                    : '');
            if (result.success) {
                this.dormantSelectedIds = [];
                const [dormant, frozen] = await Promise.all([
                    getDormantUsers({ recordLimit: this.dormantLimit }),
                    getFrozenUsers()
                ]);
                this._dormantUsers = this._enrichDormantRows(dormant || []);
                this.frozenUsers   = this._enrichFrozenRows(frozen   || []);
            }
        } catch (err) {
            this.freezeResultSuccess = false;
            this.freezeResultMsg = 'Error: ' + (err.body?.message || err.message);
        } finally {
            this.freezeInProgress = false;
        }
    }

    get freezeResultCls() {
        return 'action-toast ' + (this.freezeResultSuccess ? 'toast-success' : 'toast-error');
    }
    clearFreezeResult() { this.freezeResultMsg = ''; }

    get frozenUsersFiltered() {
        const q = (this.frozenSearch || '').toLowerCase().trim();
        const selectedSet = new Set(this.frozenSelectedIds);
        return this.frozenUsers
            .filter(u => !q ||
                (u.name     || '').toLowerCase().includes(q) ||
                (u.userName || '').toLowerCase().includes(q)
            )
            .map(u => ({
                ...u,
                selected: selectedSet.has(u.userId),
                rowCls: selectedSet.has(u.userId) ? 'row-selected row-frozen' : 'row-frozen',
            }));
    }

    get hasFrozenUsers()           { return this.frozenUsers.length > 0; }
    get frozenNoResults()          { return this.frozenUsers.length > 0 && this.frozenUsersFiltered.length === 0; }
    get frozenSelectedCount()      { return this.frozenSelectedIds.length; }
    get frozenSelectedCountPlural(){ return this.frozenSelectedIds.length === 1 ? '' : 's'; }
    get hasFrozenSelection()       { return this.frozenSelectedIds.length > 0; }

    get allFrozenSelected() {
        const f = this.frozenUsersFiltered;
        return f.length > 0 && f.every(u => this.frozenSelectedIds.includes(u.userId));
    }

    handleFrozenSearch(evt) { this.frozenSearch = evt.target.value; }
    clearFrozenSearch()     { this.frozenSearch = ''; }

    handleSelectAllFrozen(evt) {
        if (evt.target.checked) {
            this.frozenSelectedIds = this.frozenUsersFiltered.map(u => u.userId);
        } else {
            this.frozenSelectedIds = [];
        }
    }

    handleFrozenRowSelect(evt) {
        const uid = evt.currentTarget.dataset.userid;
        if (evt.target.checked) {
            if (!this.frozenSelectedIds.includes(uid)) {
                this.frozenSelectedIds = [...this.frozenSelectedIds, uid];
            }
        } else {
            this.frozenSelectedIds = this.frozenSelectedIds.filter(id => id !== uid);
        }
    }

    clearFrozenSelection() { this.frozenSelectedIds = []; }

    async handleUnfreezeSelected() {
        if (this.frozenSelectedIds.length === 0) return;
        this.freezeInProgress  = true;
        this.unfreezeResultMsg = '';
        try {
            const result = await unfreezeUsers({ userIds: this.frozenSelectedIds });
            this.unfreezeResultSuccess = result.success;
            this.unfreezeResultMsg     = result.message;
            if (result.success) {
                this.frozenSelectedIds = [];
                const [dormant, frozen] = await Promise.all([
                    getDormantUsers({ recordLimit: this.dormantLimit }),
                    getFrozenUsers()
                ]);
                this._dormantUsers = this._enrichDormantRows(dormant || []);
                this.frozenUsers   = this._enrichFrozenRows(frozen   || []);
            }
        } catch (err) {
            this.unfreezeResultSuccess = false;
            this.unfreezeResultMsg = 'Error: ' + (err.body?.message || err.message);
        } finally {
            this.freezeInProgress = false;
        }
    }

    get unfreezeResultCls() {
        return 'action-toast ' + (this.unfreezeResultSuccess ? 'toast-success' : 'toast-error');
    }
    clearUnfreezeResult() { this.unfreezeResultMsg = ''; }

    // ── PRIVILEGED ────────────────────────────────

    get privUsersFiltered() {
        let list = [...this._privilegedUsers];
        const q = (this.privSearch || '').toLowerCase().trim();
        if (q) {
            list = list.filter(u =>
                (u.name || '').toLowerCase().includes(q) ||
                (u.userName || '').toLowerCase().includes(q)
            );
        }
        if (this.privProfileFilter)  list = list.filter(u => u.profileName === this.privProfileFilter);
        if (this.privPermSetFilter)  list = list.filter(u => splitPermSetNames(u.permissionSetName).includes(this.privPermSetFilter));
        if (this.privSeverityFilter) list = list.filter(u => u.severity    === this.privSeverityFilter);
        if (this.privActiveFlags.length > 0) {
            list = list.filter(u => this.privActiveFlags.every(f => (u.flagList || []).includes(f)));
        }
        const col = this.privSortCol;
        const dir = this.privSortDir === 'asc' ? 1 : -1;
        list.sort((a, b) => {
            if (col === 'severity') {
                const rank = { Critical: 2, High: 1, Medium: 0, Low: -1 };
                return dir * ((rank[a.severity] || 0) - (rank[b.severity] || 0));
            }
            return dir * (a[col] || '').toLowerCase().localeCompare((b[col] || '').toLowerCase());
        });
        return list;
    }

    get privFilteredCount()  { return this.privUsersFiltered.length; }
    get privNoResults()      { return this._privilegedUsers.length > 0 && this.privUsersFiltered.length === 0; }
    get hasPrivFlagFilter()  { return this.privActiveFlags.length > 0; }

    get privProfileOptions() {
        const seen = new Set();
        this._privilegedUsers.forEach(u => { if (u.profileName) seen.add(u.profileName); });
        return [...seen].sort();
    }

    // Flattened, same rationale as dormantPermSetOptions above.
    get privPermSetOptions() {
        const seen = new Set();
        this._privilegedUsers.forEach(u => splitPermSetNames(u.permissionSetName).forEach(n => seen.add(n)));
        return [...seen].sort();
    }

    get privFlagOptions() {
        const seen = new Set();
        this._privilegedUsers.forEach(u => (u.flagList || []).forEach(f => seen.add(f)));
        return [...seen].sort().map(f => ({
            value: f, label: f,
            cls: 'flag-pill' + (this.privActiveFlags.includes(f) ? ' flag-pill-active' : ''),
        }));
    }

    get privSortIcon() {
        const active = this.privSortCol; const dir = this.privSortDir;
        const icon = col => active === col ? (dir === 'asc' ? ' ▲' : ' ▼') : ' ⇅';
        return { name: icon('name'), userName: icon('userName'), profileName: icon('profileName'), lastLoginDate: icon('lastLoginDate'), severity: icon('severity') };
    }

    handlePrivSearch(evt)         { this.privSearch = evt.target.value; }
    clearPrivSearch()             { this.privSearch = ''; }
    handlePrivProfileFilter(evt)  { this.privProfileFilter = evt.target.value; }
    handlePrivPermSetFilter(evt)  { this.privPermSetFilter = evt.target.value; }
    handlePrivSeverityFilter(evt) { this.privSeverityFilter = evt.target.value; }
    handlePrivFlagToggle(evt) {
        const flag = evt.currentTarget.dataset.flag;
        this.privActiveFlags = this.privActiveFlags.includes(flag)
            ? this.privActiveFlags.filter(f => f !== flag)
            : [...this.privActiveFlags, flag];
    }
    clearPrivFlags() { this.privActiveFlags = []; }
    resetPrivFilters() {
        this.privSearch = ''; this.privProfileFilter = ''; this.privPermSetFilter = ''; this.privSeverityFilter = '';
        this.privActiveFlags = []; this.privSortCol = 'severity'; this.privSortDir = 'desc';
    }
    handlePrivSort(evt) {
        const col = evt.currentTarget.dataset.col;
        if (this.privSortCol === col) { this.privSortDir = this.privSortDir === 'asc' ? 'desc' : 'asc'; }
        else { this.privSortCol = col; this.privSortDir = 'asc'; }
    }

    // ── EXPORT ────────────────────────────────────

    get exportUsersFiltered() {
        let list = [...this.exportUsers];
        const q = (this.exportSearch || '').toLowerCase().trim();
        if (q) {
            list = list.filter(u =>
                (u.name || '').toLowerCase().includes(q) ||
                (u.userName || '').toLowerCase().includes(q)
            );
        }
        if (this.exportProfileFilter)  list = list.filter(u => u.profileName === this.exportProfileFilter);
        if (this.exportPermSetFilter)  list = list.filter(u => splitPermSetNames(u.permissionSetName).includes(this.exportPermSetFilter));
        if (this.exportSeverityFilter) list = list.filter(u => u.severity    === this.exportSeverityFilter);
        if (this.exportActiveFlags.length > 0) {
            list = list.filter(u => this.exportActiveFlags.every(f => (u.flagList || []).includes(f)));
        }
        const col = this.exportSortCol; const dir = this.exportSortDir === 'asc' ? 1 : -1;
        list.sort((a, b) => {
            if (col === 'severity') {
                const rank = { Critical: 2, High: 1, Medium: 0, Low: -1 };
                return dir * ((rank[a.severity] || 0) - (rank[b.severity] || 0));
            }
            return dir * (a[col] || '').toLowerCase().localeCompare((b[col] || '').toLowerCase());
        });
        return list;
    }

    get exportFilteredCount()  { return this.exportUsersFiltered.length; }
    get exportNoResults()      { return this.exportUsers.length > 0 && this.exportUsersFiltered.length === 0; }
    get hasExportFlagFilter()  { return this.exportActiveFlags.length > 0; }

    get exportProfileOptions() {
        const seen = new Set();
        this.exportUsers.forEach(u => { if (u.profileName) seen.add(u.profileName); });
        return [...seen].sort();
    }

    // Flattened, same rationale as dormantPermSetOptions above.
    get exportPermSetOptions() {
        const seen = new Set();
        this.exportUsers.forEach(u => splitPermSetNames(u.permissionSetName).forEach(n => seen.add(n)));
        return [...seen].sort();
    }

    get exportFlagOptions() {
        const seen = new Set();
        this.exportUsers.forEach(u => (u.flagList || []).forEach(f => seen.add(f)));
        return [...seen].sort().map(f => ({
            value: f, label: f,
            cls: 'flag-pill' + (this.exportActiveFlags.includes(f) ? ' flag-pill-active' : ''),
        }));
    }

    get exportSortIcon() {
        const active = this.exportSortCol; const dir = this.exportSortDir;
        const icon = col => active === col ? (dir === 'asc' ? ' ▲' : ' ▼') : ' ⇅';
        return { name: icon('name'), userName: icon('userName'), profileName: icon('profileName'), lastLoginDate: icon('lastLoginDate'), severity: icon('severity') };
    }

    handleExportSearch(evt)         { this.exportSearch = evt.target.value; }
    clearExportSearch()             { this.exportSearch = ''; }
    handleExportProfileFilter(evt)  { this.exportProfileFilter = evt.target.value; }
    handleExportPermSetFilter(evt)  { this.exportPermSetFilter = evt.target.value; }
    handleExportSeverityFilter(evt) { this.exportSeverityFilter = evt.target.value; }
    handleExportFlagToggle(evt) {
        const flag = evt.currentTarget.dataset.flag;
        this.exportActiveFlags = this.exportActiveFlags.includes(flag)
            ? this.exportActiveFlags.filter(f => f !== flag)
            : [...this.exportActiveFlags, flag];
    }
    clearExportFlags() { this.exportActiveFlags = []; }
    resetExportFilters() {
        this.exportSearch = ''; this.exportProfileFilter = ''; this.exportPermSetFilter = ''; this.exportSeverityFilter = '';
        this.exportActiveFlags = []; this.exportSortCol = 'severity'; this.exportSortDir = 'desc';
    }
    handleExportSort(evt) {
        const col = evt.currentTarget.dataset.col;
        if (this.exportSortCol === col) { this.exportSortDir = this.exportSortDir === 'asc' ? 'desc' : 'asc'; }
        else { this.exportSortCol = col; this.exportSortDir = 'asc'; }
    }

    // ── AUDIT ─────────────────────────────────────
    // Severity filtering/sorting removed. Permission Set filtering added,
    // following the exact same shape as the Profile filters used on the
    // other tabs (single-select, "includes" match against the flattened
    // per-actor permission set list, combines with other filters).

    get auditEventsFiltered() {
        let list = [...this.auditEvents];
        const q = (this.auditSearch || '').toLowerCase().trim();
        if (q) list = list.filter(a => (a.createdByName || '').toLowerCase().includes(q));
        if (this.auditSectionFilter)  list = list.filter(a => a.section === this.auditSectionFilter);
        if (this.auditActionFilter)   list = list.filter(a => (a.action || '').toLowerCase().includes(this.auditActionFilter.toLowerCase()));
        if (this.auditPermSetFilter)  list = list.filter(a => splitPermSetNames(a.permissionSetName).includes(this.auditPermSetFilter));
        const col = this.auditSortCol; const dir = this.auditSortDir === 'asc' ? 1 : -1;
        list.sort((a, b) => dir * (a[col] || '').toLowerCase().localeCompare((b[col] || '').toLowerCase()));
        return list;
    }

    get auditFilteredCount() { return this.auditEventsFiltered.length; }
    get auditLoadedCount()   { return this.auditEvents.length; }
    get auditNoResults()     { return this.auditEvents.length > 0 && this.auditEventsFiltered.length === 0; }

    get auditSectionOptions() {
        const seen = new Set();
        this.auditEvents.forEach(a => { if (a.section) seen.add(a.section); });
        return [...seen].sort();
    }

    get auditActionOptions() {
        return ['Package', 'Permission', 'Profile', 'Changedprofile', 'PermissionSet'];
    }

    // Flattened, same rationale as dormantPermSetOptions above — mirrors the
    // Profile-options getters used elsewhere in this file.
    get auditPermSetOptions() {
        const seen = new Set();
        this.auditEvents.forEach(a => splitPermSetNames(a.permissionSetName).forEach(n => seen.add(n)));
        return [...seen].sort();
    }

    get auditSortIcon() {
        const active = this.auditSortCol; const dir = this.auditSortDir;
        const icon = col => active === col ? (dir === 'asc' ? ' ▲' : ' ▼') : ' ⇅';
        return { createdDate: icon('createdDate'), createdByName: icon('createdByName'), section: icon('section'), action: icon('action') };
    }

    handleAuditSearch(evt)         { this.auditSearch = evt.target.value; }
    clearAuditSearch()             { this.auditSearch = ''; }
    handleAuditSectionFilter(evt)  { this.auditSectionFilter = evt.target.value; }
    handleAuditActionFilter(evt)   { this.auditActionFilter = evt.target.value; }
    handleAuditPermSetFilter(evt)  { this.auditPermSetFilter = evt.target.value; }
    resetAuditFilters() {
        this.auditSearch = ''; this.auditSectionFilter = ''; this.auditActionFilter = '';
        this.auditPermSetFilter = ''; this.auditSortCol = 'createdDate'; this.auditSortDir = 'desc';
    }
    handleAuditSort(evt) {
        const col = evt.currentTarget.dataset.col;
        if (this.auditSortCol === col) { this.auditSortDir = this.auditSortDir === 'asc' ? 'desc' : 'asc'; }
        else { this.auditSortCol = col; this.auditSortDir = 'asc'; }
    }

    get auditWindowLabel() {
        if (this.auditFromDate || this.auditToDate) {
            const f = this.auditFromDate ? new Date(this.auditFromDate) : null;
            const t = this.auditToDate   ? new Date(this.auditToDate)   : null;
            const fmt = d => d.toLocaleString(undefined, { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' });
            if (f && t) return `${fmt(f)} — ${fmt(t)}`;
            if (f)      return `From ${fmt(f)}`;
            if (t)      return `Until ${fmt(t)}`;
        }
        const h = this.auditWindowHours;
        if (!h || h <= 0) return 'All time';
        const match = AUDIT_QUICK_RANGES.find(q => Math.abs(q.hours - h) < 0.001);
        if (match) return match.label;
        if (h < 1)   return `Last ${Math.round(h * 60)} minutes`;
        if (h < 24)  return `Last ${h} hours`;
        if (h < 168) return `Last ${Math.round(h/24)} days`;
        if (h < 720) return `Last ${Math.round(h/168)} weeks`;
        return `Last ${Math.round(h/720)} months`;
    }

    get auditWindowDesc() {
        if (this.auditFromDate || this.auditToDate) return `SetupAuditTrail events in the selected range (${this.auditWindowLabel}).`;
        if (!this.auditWindowHours || this.auditWindowHours <= 0) return 'All SetupAuditTrail events for managed packages, permission changes, and profile modifications.';
        return `SetupAuditTrail events from the ${this.auditWindowLabel.toLowerCase()}.`;
    }

    get hasAuditTimeFilter() {
        return !!(this.auditFromDate || this.auditToDate) || (this.auditWindowHours && this.auditWindowHours > 0);
    }

    get auditQuickRanges() {
        const usingAbs = !!(this.auditFromDate || this.auditToDate);
        return AUDIT_QUICK_RANGES.map(q => ({
            ...q,
            cls: 'audit-quick-btn' + ((!usingAbs && Math.abs((this.auditWindowHours || 0) - q.hours) < 0.001) ? ' audit-quick-active' : ''),
        }));
    }

    toggleAuditTimePicker() {
        this.auditTimePickerOpen = !this.auditTimePickerOpen;
        if (this.auditTimePickerOpen && !this.auditFromInput && !this.auditToInput) {
            const now = new Date();
            const weekAgo = new Date(Date.now() - 7*24*3600*1000);
            this.auditFromInput = dateToLocalInput(weekAgo);
            this.auditToInput   = dateToLocalInput(now);
        }
    }

    closeAuditTimePicker() { this.auditTimePickerOpen = false; }
    handleAuditFromChange(evt) { this.auditFromInput = evt.target.value; }
    handleAuditToChange(evt)   { this.auditToInput   = evt.target.value; }

    applyAuditAbsoluteRange() {
        const fromDate = localInputToDate(this.auditFromInput);
        const toDate   = localInputToDate(this.auditToInput);
        if (!fromDate && !toDate) { this.errorMessage = 'Please pick at least a From or To time.'; return; }
        if (fromDate && toDate && fromDate.getTime() > toDate.getTime()) { this.errorMessage = 'From time must be before To time.'; return; }
        this.errorMessage = null;
        this.auditFromDate = fromDate ? fromDate.toISOString() : null;
        this.auditToDate   = toDate   ? toDate.toISOString()   : null;
        this.auditWindowHours = null;
        this.auditTimePickerOpen = false;
        this._loadAudit();
    }

    handleAuditQuickRange(evt) {
        const hours = parseFloat(evt.currentTarget.dataset.hours);
        this.auditWindowHours = isNaN(hours) ? 0 : hours;
        this.auditFromDate    = null;
        this.auditToDate      = null;
        this.auditTimePickerOpen = false;
        this._loadAudit();
    }

    clearAuditTimeFilter() {
        this.auditWindowHours = 0; this.auditFromDate = null; this.auditToDate = null;
        this.auditFromInput = ''; this.auditToInput = ''; this.auditTimePickerOpen = false;
        this._loadAudit();
    }

    // ── PASSWORD ──────────────────────────────────

    get pwdUsersFiltered() {
        let list = [...this.passwordUsers];
        const q = (this.pwdSearch || '').toLowerCase().trim();
        if (q) {
            list = list.filter(u =>
                (u.name || '').toLowerCase().includes(q) ||
                (u.userName || '').toLowerCase().includes(q)
            );
        }
        if (this.pwdProfileFilter)  list = list.filter(u => u.profileName === this.pwdProfileFilter);
        if (this.pwdPermSetFilter)  list = list.filter(u => splitPermSetNames(u.permissionSetName).includes(this.pwdPermSetFilter));
        if (this.pwdSeverityFilter) list = list.filter(u => u.severity    === this.pwdSeverityFilter);
        if (this.pwdActiveFlags.length > 0) {
            list = list.filter(u => this.pwdActiveFlags.every(f => (u.flagList || []).includes(f)));
        }
        const col = this.pwdSortCol; const dir = this.pwdSortDir === 'asc' ? 1 : -1;
        list.sort((a, b) => {
            if (col === 'severity') {
                const rank = { Critical: 2, High: 1, Medium: 0, Low: -1 };
                return dir * ((rank[a.severity] || 0) - (rank[b.severity] || 0));
            }
            if (col === 'lastPasswordChange' || col === 'nextPasswordChange') {
                return dir * ((a._lastPwdTs || 0) - (b._lastPwdTs || 0));
            }
            return dir * (a[col] || '').toLowerCase().localeCompare((b[col] || '').toLowerCase());
        });
        return list;
    }

    get pwdFilteredCount() { return this.pwdUsersFiltered.length; }
    get pwdNoResults()     { return this.passwordUsers.length > 0 && this.pwdUsersFiltered.length === 0; }
    get hasPwdFlagFilter() { return this.pwdActiveFlags.length > 0; }

    get pwdProfileOptions() {
        const seen = new Set();
        this.passwordUsers.forEach(u => { if (u.profileName) seen.add(u.profileName); });
        return [...seen].sort();
    }

    // Flattened, same rationale as dormantPermSetOptions above.
    get pwdPermSetOptions() {
        const seen = new Set();
        this.passwordUsers.forEach(u => splitPermSetNames(u.permissionSetName).forEach(n => seen.add(n)));
        return [...seen].sort();
    }

    get pwdFlagOptions() {
        const seen = new Set();
        this.passwordUsers.forEach(u => (u.flagList || []).forEach(f => seen.add(f)));
        return [...seen].sort().map(f => ({
            value: f, label: f,
            cls: 'flag-pill' + (this.pwdActiveFlags.includes(f) ? ' flag-pill-active' : ''),
        }));
    }

    get pwdSortIcon() {
        const active = this.pwdSortCol; const dir = this.pwdSortDir;
        const icon = col => active === col ? (dir === 'asc' ? ' ▲' : ' ▼') : ' ⇅';
        return {
            name:               icon('name'),
            userName:           icon('userName'),
            profileName:        icon('profileName'),
            lastLoginDate:      icon('lastLoginDate'),
            lastPasswordChange: icon('lastPasswordChange'),
            nextPasswordChange: icon('nextPasswordChange'),
            severity:           icon('severity'),
        };
    }

    handlePwdSearch(evt)         { this.pwdSearch = evt.target.value; }
    clearPwdSearch()             { this.pwdSearch = ''; }
    handlePwdProfileFilter(evt)  { this.pwdProfileFilter = evt.target.value; }
    handlePwdPermSetFilter(evt)  { this.pwdPermSetFilter = evt.target.value; }
    handlePwdSeverityFilter(evt) { this.pwdSeverityFilter = evt.target.value; }
    handlePwdFlagToggle(evt) {
        const flag = evt.currentTarget.dataset.flag;
        this.pwdActiveFlags = this.pwdActiveFlags.includes(flag)
            ? this.pwdActiveFlags.filter(f => f !== flag)
            : [...this.pwdActiveFlags, flag];
    }
    clearPwdFlags() { this.pwdActiveFlags = []; }
    resetPwdFilters() {
        this.pwdSearch = ''; this.pwdProfileFilter = ''; this.pwdPermSetFilter = ''; this.pwdSeverityFilter = '';
        this.pwdActiveFlags = [];
        this.pwdSortCol = 'severity'; this.pwdSortDir = 'desc';
    }
    handlePwdSort(evt) {
        const col = evt.currentTarget.dataset.col;
        if (this.pwdSortCol === col) { this.pwdSortDir = this.pwdSortDir === 'asc' ? 'desc' : 'asc'; }
        else { this.pwdSortCol = col; this.pwdSortDir = 'asc'; }
    }

    // ── LOGIN ─────────────────────────────────────

    _toHours(value, unit) {
        const v = parseFloat(value) || 1;
        const map = { minutes: v / 60, hours: v, days: v * 24, weeks: v * 168, months: v * 720 };
        return Math.max(1, Math.ceil(map[unit] || v));
    }

    get loginWindowLabel() {
        const h = this.loginWindowHours;
        if (h < 1)   return 'less than an hour';
        if (h < 24)  return `the last ${h} hour${h === 1 ? '' : 's'}`;
        if (h < 168) return `the last ${Math.round(h/24)} day${Math.round(h/24) === 1 ? '' : 's'}`;
        if (h < 720) return `the last ${Math.round(h/168)} week${Math.round(h/168) === 1 ? '' : 's'}`;
        return `the last ${Math.round(h/720)} month${Math.round(h/720) === 1 ? '' : 's'}`;
    }

    get loginWindowDesc() { return `Failed logins in ${this.loginWindowLabel}.`; }

    get loginPresets() {
        const presets = [
            { hours: 0.166, label: '10 min' }, { hours: 1, label: '1h' }, { hours: 6, label: '6h' },
            { hours: 12, label: '12h' }, { hours: 24, label: '24h' }, { hours: 48, label: '48h' },
            { hours: 168, label: '7d' }, { hours: 720, label: '30d' }, { hours: 2160, label: '3mo' },
        ];
        return presets.map(p => ({
            ...p,
            cls: 'tw-preset' + (this.loginWindowHours === Math.ceil(p.hours) ? ' tw-preset-active' : ''),
        }));
    }

    handlePresetClick(evt) {
        const h = Math.max(1, Math.ceil(parseFloat(evt.currentTarget.dataset.hours)));
        this.loginWindowHours = h;
        this._loadLogins();
    }

    handleCustomValueInput(evt)  { this.loginCustomValue = evt.target.value; }
    handleCustomUnitChange(evt)  { this.loginCustomUnit  = evt.target.value; }

    applyCustomWindow() {
        const h = this._toHours(this.loginCustomValue, this.loginCustomUnit);
        this.loginWindowHours = h;
        this._loadLogins();
    }

    get loginRowsFiltered() {
        let list = [...this.failedLogins];
        const q = (this.loginSearch || '').toLowerCase().trim();
        if (q) {
            list = list.filter(l =>
                (l.userFullName || '').toLowerCase().includes(q) ||
                (l.userName     || '').toLowerCase().includes(q) ||
                (l.userId       || '').toLowerCase().includes(q)
            );
        }
        if (this.loginStatusFilter)  list = list.filter(l => l.status  === this.loginStatusFilter);
        if (this.loginCountryFilter) list = list.filter(l => l.country === this.loginCountryFilter);
        if (this.loginTlsFilter === 'weak') {
            list = list.filter(l => l.tlsProtocol === 'TLS 1.0' || l.tlsProtocol === 'TLS 1.1');
        } else if (this.loginTlsFilter) {
            list = list.filter(l => l.tlsProtocol === this.loginTlsFilter);
        }
        const col = this.loginSortCol; const dir = this.loginSortDir === 'asc' ? 1 : -1;
        list.sort((a, b) => dir * (a[col] || '').toLowerCase().localeCompare((b[col] || '').toLowerCase()));
        return list;
    }

    get loginFilteredCount() { return this.loginRowsFiltered.length; }
    get hasLoginRows()       { return this.loginRowsFiltered.length > 0; }
    get loginNoResults()     { return this.failedLogins.length > 0 && this.loginRowsFiltered.length === 0; }

    get loginStatusOptions() {
        const seen = new Set(); this.failedLogins.forEach(l => { if (l.status) seen.add(l.status); }); return [...seen].sort();
    }
    get loginCountryOptions() {
        const seen = new Set(); this.failedLogins.forEach(l => { if (l.country) seen.add(l.country); }); return [...seen].sort();
    }
    get loginTlsOptions() {
        const seen = new Set(); this.failedLogins.forEach(l => { if (l.tlsProtocol) seen.add(l.tlsProtocol); }); return [...seen].sort();
    }

    get loginSortIcon() {
        const active = this.loginSortCol; const dir = this.loginSortDir;
        const icon = col => active === col ? (dir === 'asc' ? ' ▲' : ' ▼') : ' ⇅';
        return {
            loginTime:      icon('loginTime'),
            userFullName:   icon('userFullName'),
            sourceIp:       icon('sourceIp'),
            loginType:      icon('loginType'),
            loginSubType:   icon('loginSubType'),
            status:         icon('status'),
            application:    icon('application'),
            loginUrl:       icon('loginUrl'),
            experience:     icon('experience'),
            forwardedForIp: icon('forwardedForIp'),
            browser:        icon('browser'),
            country:        icon('country'),
            tlsProtocol:    icon('tlsProtocol'),
        };
    }

    // ── GROUP BY ──────────────────────────────────

    get loginGroupByOptions() {
        const opts = [
            { value: 'loginTime',      label: 'Login Time' },
            { value: 'sourceIp',       label: 'Source IP' },
            { value: 'loginType',      label: 'Login Type' },
            { value: 'loginSubType',   label: 'Login Subtype' },
            { value: 'status',         label: 'Status' },
            { value: 'application',    label: 'Application' },
            { value: 'loginUrl',       label: 'Login URL' },
            { value: 'experience',     label: 'Experience' },
            { value: 'forwardedForIp', label: 'Fwd For IP' },
        ];
        return opts.map(o => ({
            ...o,
            cls: 'groupby-pill' + (this.loginGroupByField === o.value ? ' groupby-pill-active' : ''),
        }));
    }

    get loginGroupByActive() { return !!this.loginGroupByField; }

    get loginGroupedRows() {
        if (!this.loginGroupByField) return [];
        const field = this.loginGroupByField;
        const map   = new Map();

        this.loginRowsFiltered.forEach(row => {
            let gval = row[field] || '(blank)';
            if (field === 'loginTime' && gval !== '(blank)') {
                gval = gval.substring(0, 10);
            }
            if (!map.has(gval)) map.set(gval, []);
            map.get(gval).push(row);
        });

        return [...map.entries()]
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([gval, rows]) => ({
                key:        gval,
                groupValue: gval,
                count:      rows.length,
                countPlural: rows.length === 1 ? '' : 's',
                expanded:   !!this._loginExpandedGrps[gval],
                caretCls:   this._loginExpandedGrps[gval] ? 'grp-caret grp-caret-open' : 'grp-caret',
                rows,
            }));
    }

    handleLoginGroupBy(evt) {
        const val = evt.currentTarget.dataset.val;
        this.loginGroupByField    = this.loginGroupByField === val ? '' : val;
        this._loginExpandedGrps   = {};
    }

    clearLoginGroupBy() {
        this.loginGroupByField  = '';
        this._loginExpandedGrps = {};
    }

    handleGroupToggle(evt) {
        const key = evt.currentTarget.dataset.grpkey;
        this._loginExpandedGrps = {
            ...this._loginExpandedGrps,
            [key]: !this._loginExpandedGrps[key],
        };
    }

    expandAllGroups() {
        const next = {};
        this.loginGroupedRows.forEach(g => { next[g.key] = true; });
        this._loginExpandedGrps = next;
    }

    collapseAllGroups() {
        this._loginExpandedGrps = {};
    }

    handleLoginSearch(evt)         { this.loginSearch = evt.target.value; }
    clearLoginSearch()             { this.loginSearch = ''; }
    handleLoginStatusFilter(evt)   { this.loginStatusFilter  = evt.target.value; }
    handleLoginCountryFilter(evt)  { this.loginCountryFilter = evt.target.value; }
    handleLoginTlsFilter(evt)      { this.loginTlsFilter     = evt.target.value; }

    resetLoginFilters() {
        this.loginSearch = ''; this.loginStatusFilter = ''; this.loginCountryFilter = '';
        this.loginTlsFilter = ''; this.loginSortCol = 'loginTime'; this.loginSortDir = 'desc';
    }
    handleLoginSort(evt) {
        const col = evt.currentTarget.dataset.col;
        if (this.loginSortCol === col) { this.loginSortDir = this.loginSortDir === 'asc' ? 'desc' : 'asc'; }
        else { this.loginSortCol = col; this.loginSortDir = 'asc'; }
    }

    // ── RULE TAG POPOVER ──────────────────────────

    handleRuleTagEnter(evt) {
        this._ruleTagHovered = true;
        clearTimeout(this._popoverHideTimer);

        const key = evt.currentTarget.dataset.rules;
        const def = RULE_DEFINITIONS[key];
        if (!def) return;

        const rect        = evt.currentTarget.getBoundingClientRect();
        const popoverW    = 400;
        const gap         = 10;
        const viewportW   = window.innerWidth || document.documentElement.clientWidth;

        // Prefer right of the tag; flip left if not enough space
        let left;
        if (rect.right + gap + popoverW <= viewportW) {
            left = rect.right + gap;
        } else {
            left = Math.max(8, rect.left - gap - popoverW);
        }

        // Vertically align top of popover with top of tag
        const top = rect.top;

        this.rulePopoverTitle = def.title;
        this.rulePopoverItems = def.rules.map(r => ({
            ...r,
            sevCls: SEV_PILL_CLS[r.severity] || 'rule-sev rule-sev-low',
        }));
        // position: fixed so viewport coords work inside Salesforce iframes/scroll containers
        this.rulePopoverStyle   = `position:fixed;top:${top}px;left:${left}px;width:${popoverW}px;`;
        this.rulePopoverVisible = true;
    }

    handleRuleTagLeave() {
        this._ruleTagHovered = false;
        this._schedulePopoverHide();
    }

    handlePopoverEnter() {
        this._popoverHovered = true;
        clearTimeout(this._popoverHideTimer);
    }

    handlePopoverLeave() {
        this._popoverHovered = false;
        this._schedulePopoverHide();
    }

    _schedulePopoverHide() {
        this._popoverHideTimer = setTimeout(() => {
            if (!this._ruleTagHovered && !this._popoverHovered) {
                this.rulePopoverVisible = false;
            }
        }, 120);
    }

    // ── UNIVERSAL LINK HANDLER ────────────────────

    handleLinkClick(evt) {
        evt.preventDefault();
        evt.stopPropagation();
        const url = evt.currentTarget.dataset.url;
        if (url) window.open(url, '_blank', 'noopener,noreferrer');
    }

    // ── TAB HANDLING ──────────────────────────────

    get tabs() {
        return TABS.map(t => ({
            ...t,
            cls:      'tab-btn' + (t.id === this.activeTab ? ' tab-active' : ''),
            count:    this._tabCount(t.id),
            countCls: this._tabCountCls(t.id),
        }));
    }

    _tabCount(id) {
        const m = {
            dormant:    this._dormantUsers.length,
            privileged: this._privilegedUsers.length,
            export:     this.exportUsers.length,
            password:   this.passwordUsers.length,
            logins:     this.failedLogins.length,
            audit:      this.auditEvents.length,
        };
        return m[id] || null;
    }

    _tabCountCls(id) {
        return ['privileged', 'logins', 'audit'].includes(id)
            ? 'tab-count tab-count-critical'
            : 'tab-count';
    }

    get shellCls()  { return this.isDarkTheme ? 'soc-shell' : 'soc-shell soc-shell--light'; }
    get themeIcon() { return this.isDarkTheme ? '☀' : '🌙'; }
    handleThemeToggle() { this.isDarkTheme = !this.isDarkTheme; }

    handleTabClick(evt) { this.activeTab = evt.currentTarget.dataset.id; }
    handleRefresh()     { this._loadCsvAccess(); this._loadAll(); }

    get isTabOverview()   { return this.activeTab === 'overview'; }
    get isTabDormant()    { return this.activeTab === 'dormant'; }
    get isTabPrivileged() { return this.activeTab === 'privileged'; }
    get isTabExport()     { return this.activeTab === 'export'; }
    get isTabPassword()   { return this.activeTab === 'password'; }
    get isTabLogins()     { return this.activeTab === 'logins'; }
    get isTabAudit()      { return this.activeTab === 'audit'; }

    get hasDormantUsers()    { return this._dormantUsers.length    > 0; }
    get hasPrivilegedUsers() { return this._privilegedUsers.length > 0; }
    get hasExportUsers()     { return this.exportUsers.length      > 0; }
    get hasPasswordUsers()   { return this.passwordUsers.length    > 0; }
    get hasFailedLogins()    { return this.failedLogins.length     > 0; }
    get hasAuditEvents()     { return this.auditEvents.length      > 0; }
}