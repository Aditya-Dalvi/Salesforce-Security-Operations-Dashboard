public without sharing class SocDashboardController {

    // ─────────────────────────────────────────────
    // PERMISSION METADATA
    // ─────────────────────────────────────────────
    // Add/remove API names here to change what the dashboard tracks.
    // Every name must exist as a Boolean field on BOTH Profile and PermissionSet.

    private static final Map<String, String> PERM_LABEL = new Map<String, String>{
        'PermissionsModifyAllData'                 => 'ModifyAllData',
        'PermissionsViewAllData'                   => 'ViewAllData',
        'PermissionsViewEncryptedData'              => 'ViewEncryptedData',
        'PermissionsManageUsers'                    => 'ManageUsers',
        'PermissionsManageProfilesPermissionsets'   => 'ManageProfilesAndPermSets',
        'PermissionsCustomizeApplication'           => 'CustomizeApplication',
        'PermissionsManageRoles'                    => 'ManageRoles',
        'PermissionsManageSharing'                  => 'ManageSharing',
        'PermissionsAuthorApex'                     => 'AuthorApex',
        'PermissionsModifyMetadata'                 => 'ModifyMetadata',
        'PermissionsManageSandboxes'                => 'ManageSandboxes',
        'PermissionsViewSetup'                      => 'ViewSetup',
        'PermissionsDataExport'                     => 'DataExport',
        'PermissionsExportReport'                   => 'ExportReport',
        'PermissionsQueryAllFiles'                  => 'QueryAllFiles',
        'PermissionsBulkApiHardDelete'               => 'BulkHardDelete',
        'PermissionsApiEnabled'                      => 'APIEnabled',
        'PermissionsPasswordNeverExpires'            => 'PasswordNeverExpires',
        'PermissionsForceTwoFactor'                  => 'ForceTwoFactor'
    };

    private static final Map<String, String> PERM_SEVERITY = new Map<String, String>{
        'PermissionsModifyAllData'                 => 'Critical',
        'PermissionsViewAllData'                   => 'High',
        'PermissionsViewEncryptedData'              => 'Critical',
        'PermissionsManageUsers'                    => 'Critical',
        'PermissionsManageProfilesPermissionsets'   => 'Critical',
        'PermissionsCustomizeApplication'           => 'High',
        'PermissionsManageRoles'                    => 'High',
        'PermissionsManageSharing'                  => 'High',
        'PermissionsAuthorApex'                      => 'High',
        'PermissionsModifyMetadata'                  => 'Critical',
        'PermissionsManageSandboxes'                 => 'Medium',
        'PermissionsViewSetup'                       => 'Low',
        'PermissionsDataExport'                      => 'High',
        'PermissionsExportReport'                    => 'High',
        'PermissionsQueryAllFiles'                   => 'Critical',
        'PermissionsBulkApiHardDelete'                => 'Critical',
        'PermissionsApiEnabled'                       => 'Medium',
        'PermissionsPasswordNeverExpires'             => 'High',
        'PermissionsForceTwoFactor'                   => 'Critical'
    };

    private static final List<String> PRIVILEGED_PERMS = new List<String>{
        'PermissionsModifyAllData', 'PermissionsViewAllData', 'PermissionsViewEncryptedData',
        'PermissionsManageUsers', 'PermissionsManageProfilesPermissionsets', 'PermissionsCustomizeApplication',
        'PermissionsManageRoles', 'PermissionsManageSharing', 'PermissionsAuthorApex',
        'PermissionsModifyMetadata', 'PermissionsManageSandboxes', 'PermissionsViewSetup'
    };

    private static final List<String> EXPORT_PERMS = new List<String>{
        'PermissionsDataExport', 'PermissionsExportReport', 'PermissionsQueryAllFiles',
        'PermissionsBulkApiHardDelete', 'PermissionsApiEnabled'
    };

    // ─────────────────────────────────────────────
    // WRAPPER CLASSES
    // ─────────────────────────────────────────────

    public class SocSummary {
        @AuraEnabled public Integer dormantUsers;
        @AuraEnabled public Integer dormantPrivilegedUsers;
        @AuraEnabled public Integer modifyAllDataUsers;
        @AuraEnabled public Integer viewAllDataUsers;
        @AuraEnabled public Integer viewEncryptedUsers;
        @AuraEnabled public Integer mfaDisabledUsers;
        @AuraEnabled public Integer mfaBypassUsers;
        @AuraEnabled public Integer exportEnabledUsers;
        @AuraEnabled public Integer passwordNeverExpiresUsers;
        @AuraEnabled public Integer failedLoginsLast24h;
        @AuraEnabled public Integer packageInstallEvents;
        @AuraEnabled public Integer criticalRiskUsers;
    }

    // One risk flag on a UserRow, tagged with where it came from.
    public class FlagDetail {
        @AuraEnabled public String permName;      // base permission label, e.g. 'ModifyAllData'
        @AuraEnabled public String source;        // 'Profile' | 'Permission Set' | 'Profile + Permission Set' | 'N/A'
        @AuraEnabled public String sourceDetail;  // e.g. 'Profile (System Administrator); Permission Set (Sales Extra)'
        @AuraEnabled public String label;         // display text, e.g. 'ModifyAllData (Profile)'
        @AuraEnabled public String severity;      // per-flag severity for pill coloring
    }

    // NOTE: `permissionSetName` was added to support the "Search by Permission
    // Set" filter on the Dormant Accounts, Privileged Access, Export/Download,
    // and Password Policy tabs (implemented the same way as the Profile
    // filter already on those tabs). It holds a comma-joined list of the
    // user's assigned, non-profile-owned Permission Set labels (empty string
    // if none), resolved via resolvePermissionSetNames() below.
    public class UserRow {
        @AuraEnabled public String  userId;
        @AuraEnabled public String  userName;
        @AuraEnabled public String  name;
        @AuraEnabled public String  profileName;
        @AuraEnabled public String  profileId;
        @AuraEnabled public String  lastLoginDate;
        @AuraEnabled public Boolean isActive;
        @AuraEnabled public String  riskReason;
        @AuraEnabled public String  severity;
        @AuraEnabled public Integer dormantDays;
        @AuraEnabled public List<FlagDetail> flagDetails;
        @AuraEnabled public String  permissionSetName;
        // Password Policy extra fields
        @AuraEnabled public String  lastPasswordChangeDate;
        @AuraEnabled public Integer passwordExpiryDays;
    }

    public class LoginRow {
        @AuraEnabled public String userId;
        @AuraEnabled public String userName;
        @AuraEnabled public String userFullName;
        @AuraEnabled public String sourceIp;
        @AuraEnabled public String status;
        @AuraEnabled public String loginTime;
        @AuraEnabled public String browser;
        @AuraEnabled public String country;
        @AuraEnabled public String tlsProtocol;
        @AuraEnabled public String loginType;
        @AuraEnabled public String loginSubType;
        @AuraEnabled public String application;
        @AuraEnabled public String loginUrl;
        @AuraEnabled public String experience;
        @AuraEnabled public String forwardedForIp;
    }

    // NOTE: `severity` was removed from AuditRow per the "Remove Severity from
    // Audit Trail" requirement. `permissionSetName` supports the Audit Trail's
    // "Search by Permission Set" filter, and is resolved via the same shared
    // resolvePermissionSetNames() helper used for the other four tabs.
    public class AuditRow {
        @AuraEnabled public String action;
        @AuraEnabled public String section;
        @AuraEnabled public String createdByName;
        @AuraEnabled public String createdById;
        @AuraEnabled public String createdDate;
        @AuraEnabled public String display;
        @AuraEnabled public String permissionSetName;
    }

    // Internal-only (never returned to LWC directly)
    private class PermState {
        Boolean granted;
        String  source;
        String  sourceDetail;
    }

    // ─────────────────────────────────────────────
    // PERMISSION RESOLUTION HELPERS
    // ─────────────────────────────────────────────

    /**
     * Finds active users who have ANY of the given permission API names set to true,
     * either on their Profile or via an assigned (non-profile-owned) Permission Set.
     */
    private static Set<Id> getCandidateUserIds(List<String> permNames) {
        Set<Id> ids = new Set<Id>();
        if (permNames == null || permNames.isEmpty()) return ids;

        List<String> profConds = new List<String>();
        for (String p : permNames) profConds.add('Profile.' + p + ' = true');
        String profSoql = 'SELECT Id FROM User WHERE IsActive = true AND (' +
            String.join(profConds, ' OR ') + ') LIMIT 5000';
        for (SObject rec : Database.query(profSoql)) ids.add((Id) rec.get('Id'));

        List<String> psConds = new List<String>();
        for (String p : permNames) psConds.add('PermissionSet.' + p + ' = true');
        String psSoql = 'SELECT AssigneeId FROM PermissionSetAssignment ' +
            'WHERE Assignee.IsActive = true AND PermissionSet.IsOwnedByProfile = false AND (' +
            String.join(psConds, ' OR ') + ') LIMIT 5000';
        for (SObject rec : Database.query(psSoql)) ids.add((Id) rec.get('AssigneeId'));

        return ids;
    }

    /**
     * Builds, for each userId, an effective (Profile OR Permission Set) state
     * for every requested permission, plus where it came from.
     */
    private static Map<Id, Map<String, PermState>> buildEffectivePermissionMap(
        List<String> permNames, Set<Id> userIds
    ) {
        Map<Id, Map<String, PermState>> result = new Map<Id, Map<String, PermState>>();
        if (userIds == null || userIds.isEmpty() || permNames == null || permNames.isEmpty()) return result;
        for (Id uid : userIds) result.put(uid, new Map<String, PermState>());

        // Profile side
        String profFieldList = 'Profile.' + String.join(permNames, ', Profile.');
        String userSoql = 'SELECT Id, Profile.Name, ' + profFieldList + ' FROM User WHERE Id IN :userIds';
        for (SObject rec : Database.query(userSoql)) {
            SObject prof = rec.getSObject('Profile');
            if (prof == null) continue;
            String profName = (String) prof.get('Name');
            Id uid = (Id) rec.get('Id');
            for (String permName : permNames) {
                Boolean val = (Boolean) prof.get(permName);
                if (val == true) mergeFlag(result.get(uid), permName, 'Profile (' + profName + ')');
            }
        }

        // Permission Set side (excludes the auto-generated profile-shadow permission set)
        String psFieldList = 'PermissionSet.' + String.join(permNames, ', PermissionSet.');
        String psSoql = 'SELECT AssigneeId, PermissionSet.Label, ' + psFieldList +
            ' FROM PermissionSetAssignment WHERE AssigneeId IN :userIds AND PermissionSet.IsOwnedByProfile = false';
        for (SObject rec : Database.query(psSoql)) {
            SObject ps = rec.getSObject('PermissionSet');
            if (ps == null) continue;
            Id uid = (Id) rec.get('AssigneeId');
            if (!result.containsKey(uid)) continue;
            String psLabel = (String) ps.get('Label');
            for (String permName : permNames) {
                Boolean val = (Boolean) ps.get(permName);
                if (val == true) mergeFlag(result.get(uid), permName, 'Permission Set (' + psLabel + ')');
            }
        }

        // Finalize the 'source' summary label
        for (Id uid : result.keySet()) {
            for (String permName : result.get(uid).keySet()) {
                PermState st = result.get(uid).get(permName);
                Boolean hasProfile = st.sourceDetail.contains('Profile (');
                Boolean hasPermSet = st.sourceDetail.contains('Permission Set (');
                if (hasProfile && hasPermSet)      st.source = 'Profile + Permission Set';
                else if (hasProfile)               st.source = 'Profile';
                else if (hasPermSet)               st.source = 'Permission Set';
                else                                st.source = 'N/A';
            }
        }
        return result;
    }

    private static void mergeFlag(Map<String, PermState> userPerms, String permName, String sourcePiece) {
        PermState st = userPerms.get(permName);
        if (st == null) {
            st = new PermState();
            st.granted = false;
            st.sourceDetail = '';
            userPerms.put(permName, st);
        }
        st.granted = true;
        if (String.isBlank(st.sourceDetail)) {
            st.sourceDetail = sourcePiece;
        } else if (!st.sourceDetail.contains(sourcePiece)) {
            st.sourceDetail += '; ' + sourcePiece;
        }
    }

    private static Boolean isGranted(Map<Id, Map<String, PermState>> permMap, Id uid, String permName) {
        if (permMap == null || !permMap.containsKey(uid)) return false;
        PermState st = permMap.get(uid).get(permName);
        return st != null && st.granted == true;
    }

    private static String sourceOf(Map<Id, Map<String, PermState>> permMap, Id uid, String permName) {
        if (permMap == null || !permMap.containsKey(uid)) return 'N/A';
        PermState st = permMap.get(uid).get(permName);
        return st != null ? st.source : 'N/A';
    }

    private static String sourceDetailOf(Map<Id, Map<String, PermState>> permMap, Id uid, String permName) {
        if (permMap == null || !permMap.containsKey(uid)) return '';
        PermState st = permMap.get(uid).get(permName);
        return st != null ? st.sourceDetail : '';
    }

    private static FlagDetail makeFlag(Map<Id, Map<String, PermState>> permMap, Id uid, String permApiName) {
        FlagDetail fd = new FlagDetail();
        String baseLabel = PERM_LABEL.containsKey(permApiName)
            ? PERM_LABEL.get(permApiName)
            : permApiName.replace('Permissions', '');
        String src = sourceOf(permMap, uid, permApiName);
        fd.permName     = baseLabel;
        fd.source        = src;
        fd.sourceDetail  = sourceDetailOf(permMap, uid, permApiName);
        fd.label         = baseLabel + ' (' + src + ')';
        fd.severity      = PERM_SEVERITY.containsKey(permApiName) ? PERM_SEVERITY.get(permApiName) : 'Medium';
        return fd;
    }

    private static String joinLabels(List<FlagDetail> flags) {
        List<String> labels = new List<String>();
        for (FlagDetail f : flags) labels.add(f.label);
        return String.join(labels, ', ');
    }

    private static Integer sevRank(String sev) {
        if (sev == 'Critical') return 3;
        if (sev == 'High')     return 2;
        if (sev == 'Medium')   return 1;
        if (sev == 'Low')      return 0;
        return -1;
    }

    private static String maxSeverity(String a, String b) {
        if (a == null) return b;
        if (b == null) return a;
        return sevRank(a) >= sevRank(b) ? a : b;
    }

    /**
     * Shared "Search by Permission Set" resolver.
     * Returns, for every Id in userIds, the comma-joined list of that user's
     * assigned, non-profile-owned Permission Set labels (empty string if the
     * user has none). Used by every tab that exposes a Permission Set filter:
     * Dormant Accounts, Privileged Access, Export/Download, Password Policy,
     * and Audit Trail (there, resolved against each event's actor).
     */
    private static Map<Id, String> resolvePermissionSetNames(Set<Id> userIds) {
        Map<Id, String> result = new Map<Id, String>();
        if (userIds == null || userIds.isEmpty()) return result;

        Map<Id, List<String>> namesByUser = new Map<Id, List<String>>();
        for (PermissionSetAssignment psa : [
            SELECT AssigneeId, PermissionSet.Label
            FROM PermissionSetAssignment
            WHERE AssigneeId IN :userIds
            AND PermissionSet.IsOwnedByProfile = false
        ]) {
            if (!namesByUser.containsKey(psa.AssigneeId)) {
                namesByUser.put(psa.AssigneeId, new List<String>());
            }
            namesByUser.get(psa.AssigneeId).add(psa.PermissionSet.Label);
        }

        for (Id uid : userIds) {
            List<String> names = namesByUser.containsKey(uid) ? namesByUser.get(uid) : new List<String>();
            names.sort();
            result.put(uid, names.isEmpty() ? '' : String.join(names, ', '));
        }
        return result;
    }

    // ─────────────────────────────────────────────
    // MFA BYPASS FIELD RESOLUTION
    // ─────────────────────────────────────────────
    // 'PermissionsBypassMFAForUiLogins' does not exist as a field on PermissionSet
    // in any Salesforce release, which is why the original query failed with
    // "No such column" at compile time. The closest real permission is
    // "Waive Multi-Factor Authentication for Exempt Users". Its exact Apex API
    // field name can differ by org/API version, so instead of hardcoding a name
    // that might not exist in this org, we resolve it dynamically at runtime
    // against a list of known candidate names. If none match, the count safely
    // falls back to 0 instead of breaking deployment.
    //
    // To find the confirmed field name for this org, run in Execute Anonymous:
    //   Map<String, Schema.SObjectField> fieldMap = Schema.SObjectType.PermissionSet.fields.getMap();
    //   for (String fieldName : fieldMap.keySet()) {
    //       if (fieldName.contains('mfa') || fieldName.contains('waive') || fieldName.contains('multifactor')) {
    //           System.debug(fieldMap.get(fieldName).getDescribe().getName());
    //       }
    //   }
    // Then move the confirmed name to the front of MFA_BYPASS_CANDIDATE_FIELDS below.

    private static final List<String> MFA_BYPASS_CANDIDATE_FIELDS = new List<String>{
        'PermissionsWaiveMFAWhitelistedIps',
        'PermissionsBypassMFAForUiLogins'
    };

    private static Boolean mfaBypassFieldResolved = false;
    private static String  mfaBypassFieldName;

    private static String resolveMfaBypassField() {
        if (mfaBypassFieldResolved) return mfaBypassFieldName;
        mfaBypassFieldResolved = true;

        Map<String, Schema.SObjectField> fieldMap = Schema.SObjectType.PermissionSet.fields.getMap();
        for (String candidate : MFA_BYPASS_CANDIDATE_FIELDS) {
            if (fieldMap.containsKey(candidate.toLowerCase())) {
                mfaBypassFieldName = candidate;
                break;
            }
        }
        return mfaBypassFieldName;
    }

    private static Integer getMfaBypassCount() {
        String fieldName = resolveMfaBypassField();
        if (fieldName == null) return 0;

        Set<Id> mfaBypassIds = new Set<Id>();
        String dynSoql = 'SELECT AssigneeId FROM PermissionSetAssignment ' +
            'WHERE PermissionSet.' + fieldName + ' = true AND Assignee.IsActive = true';
        for (SObject rec : Database.query(dynSoql)) {
            mfaBypassIds.add((Id) rec.get('AssigneeId'));
        }
        return mfaBypassIds.size();
    }

    // ─────────────────────────────────────────────
    // SUMMARY CARD
    // ─────────────────────────────────────────────

    @AuraEnabled(cacheable=true)
    public static SocSummary getSummary() {
        SocSummary s = new SocSummary();
        DateTime cutoff90 = DateTime.now().addDays(-90);

        s.dormantUsers = [
            SELECT COUNT() FROM User
            WHERE IsActive = true
            AND (LastLoginDate < :cutoff90 OR LastLoginDate = null)
        ];

        Set<Id> dormantIds = new Set<Id>();
        for (User u : [
            SELECT Id FROM User WHERE IsActive = true
            AND (LastLoginDate < :cutoff90 OR LastLoginDate = null)
            LIMIT 5000
        ]) { dormantIds.add(u.Id); }

        // ── Combined (Profile + Permission Set) counts ──
        List<String> corePerms = new List<String>{
            'PermissionsModifyAllData', 'PermissionsViewAllData', 'PermissionsViewEncryptedData',
            'PermissionsDataExport', 'PermissionsExportReport', 'PermissionsPasswordNeverExpires'
        };
        Set<Id> coreCandidates = getCandidateUserIds(corePerms);
        Map<Id, Map<String, PermState>> corePermMap = buildEffectivePermissionMap(corePerms, coreCandidates);

        Map<Id, Boolean> coreActive = new Map<Id, Boolean>();
        if (!coreCandidates.isEmpty()) {
            for (User u : [SELECT Id, IsActive FROM User WHERE Id IN :coreCandidates]) {
                coreActive.put(u.Id, u.IsActive);
            }
        }

        Integer modifyAll = 0, viewAll = 0, viewEnc = 0, exportOn = 0, pwdNever = 0;
        for (Id uid : coreCandidates) {
            if (coreActive.get(uid) != true) continue;
            if (isGranted(corePermMap, uid, 'PermissionsModifyAllData'))    modifyAll++;
            if (isGranted(corePermMap, uid, 'PermissionsViewAllData'))      viewAll++;
            if (isGranted(corePermMap, uid, 'PermissionsViewEncryptedData')) viewEnc++;
            if (isGranted(corePermMap, uid, 'PermissionsDataExport') ||
                isGranted(corePermMap, uid, 'PermissionsExportReport'))     exportOn++;
            if (isGranted(corePermMap, uid, 'PermissionsPasswordNeverExpires')) pwdNever++;
        }
        s.modifyAllDataUsers       = modifyAll;
        s.viewAllDataUsers         = viewAll;
        s.viewEncryptedUsers       = viewEnc;
        s.exportEnabledUsers       = exportOn;
        s.passwordNeverExpiresUsers = pwdNever;

        // ── MFA disabled — needs the FULL active-user universe, not just candidates ──
        Integer totalActive = [SELECT COUNT() FROM User WHERE IsActive = true];
        Set<Id> force2faIds = getCandidateUserIds(new List<String>{ 'PermissionsForceTwoFactor' });
        Map<Id, Map<String, PermState>> force2faMap =
            buildEffectivePermissionMap(new List<String>{ 'PermissionsForceTwoFactor' }, force2faIds);
        Integer force2faCount = 0;
        for (Id uid : force2faIds) {
            if (isGranted(force2faMap, uid, 'PermissionsForceTwoFactor')) force2faCount++;
        }
        s.mfaDisabledUsers = totalActive - force2faCount;

        // ── Critical risk = ModifyAllData AND ViewEncryptedData AND MFA disabled (all effective) ──
        List<String> critPerms = new List<String>{
            'PermissionsModifyAllData', 'PermissionsViewEncryptedData', 'PermissionsForceTwoFactor'
        };
        Set<Id> critCandidates = getCandidateUserIds(
            new List<String>{ 'PermissionsModifyAllData', 'PermissionsViewEncryptedData' }
        );
        Map<Id, Map<String, PermState>> critMap = buildEffectivePermissionMap(critPerms, critCandidates);
        Map<Id, Boolean> critActive = new Map<Id, Boolean>();
        if (!critCandidates.isEmpty()) {
            for (User u : [SELECT Id, IsActive FROM User WHERE Id IN :critCandidates]) {
                critActive.put(u.Id, u.IsActive);
            }
        }
        Integer critical = 0;
        for (Id uid : critCandidates) {
            if (critActive.get(uid) != true) continue;
            if (isGranted(critMap, uid, 'PermissionsModifyAllData') &&
                isGranted(critMap, uid, 'PermissionsViewEncryptedData') &&
                !isGranted(critMap, uid, 'PermissionsForceTwoFactor')) {
                critical++;
            }
        }
        s.criticalRiskUsers = critical;

        // ── Dormant + privileged (effective ModifyAllData among dormant users) ──
        Map<Id, Map<String, PermState>> dormPermMap =
            buildEffectivePermissionMap(new List<String>{ 'PermissionsModifyAllData' }, dormantIds);
        Integer dormPriv = 0;
        for (Id uid : dormantIds) {
            if (isGranted(dormPermMap, uid, 'PermissionsModifyAllData')) dormPriv++;
        }
        s.dormantPrivilegedUsers = dormPriv;

        // ── MFA bypass (permission-set-driven permission, resolved dynamically) ──
        s.mfaBypassUsers = getMfaBypassCount();

        DateTime last24h = DateTime.now().addHours(-24);
        Integer failedCount = 0;
        for (LoginHistory lh : [
            SELECT Status FROM LoginHistory WHERE LoginTime >= :last24h LIMIT 2000
        ]) { if (lh.Status != 'Success') failedCount++; }
        s.failedLoginsLast24h = failedCount;

        s.packageInstallEvents = [
            SELECT COUNT() FROM SetupAuditTrail
            WHERE Action LIKE '%package%' AND CreatedDate = LAST_N_DAYS:30
        ];

        return s;
    }

    // ─────────────────────────────────────────────
    // DORMANT ACCOUNTS
    // ─────────────────────────────────────────────

    @AuraEnabled(cacheable=false)
    public static Integer getDormantCount() {
        DateTime cutoff90 = DateTime.now().addDays(-90);
        return [
            SELECT COUNT() FROM User WHERE IsActive = true
            AND (LastLoginDate < :cutoff90 OR LastLoginDate = null)
        ];
    }

    @AuraEnabled(cacheable=false)
    public static List<UserRow> getDormantUsers(Integer recordLimit) {
        DateTime cutoff90 = DateTime.now().addDays(-90);
        List<UserRow> rows = new List<UserRow>();
        if (recordLimit == null || recordLimit < 50)  recordLimit = 500;
        if (recordLimit > 10000)                      recordLimit = 10000;

        String soql =
            'SELECT Id, Username, Name, Profile.Id, Profile.Name, LastLoginDate, IsActive, ' +
            'Profile.PermissionsModifyAllData, Profile.PermissionsDataExport, ' +
            'Profile.PermissionsViewEncryptedData ' +
            'FROM User WHERE IsActive = true ' +
            'AND (LastLoginDate < :cutoff90 OR LastLoginDate = null) ' +
            'ORDER BY LastLoginDate ASC NULLS FIRST LIMIT ' + recordLimit;

        List<User> dormantUsers = Database.query(soql);
        Set<Id> dormantIds = new Set<Id>();
        for (User u : dormantUsers) dormantIds.add(u.Id);

        // Combine Profile + Permission Set for the admin-flag callouts on this tab too
        List<String> flagPerms = new List<String>{
            'PermissionsModifyAllData', 'PermissionsViewEncryptedData', 'PermissionsDataExport'
        };
        Map<Id, Map<String, PermState>> permMap = buildEffectivePermissionMap(flagPerms, dormantIds);

        // Search-by-Permission-Set support (same pattern as every other tab below)
        Map<Id, String> permSetNames = resolvePermissionSetNames(dormantIds);

        for (User u : dormantUsers) {
            UserRow r = new UserRow();
            r.userId      = u.Id;
            r.userName    = u.Username;
            r.name        = u.Name;
            r.profileName = u.Profile != null ? u.Profile.Name : 'N/A';
            r.profileId   = u.Profile != null ? u.Profile.Id   : null;
            r.isActive    = u.IsActive;
            r.permissionSetName = permSetNames.containsKey(u.Id) ? permSetNames.get(u.Id) : '';

            if (u.LastLoginDate != null) {
                Long msPerDay = 86400000L;
                r.dormantDays   = (Integer)((DateTime.now().getTime() - u.LastLoginDate.getTime()) / msPerDay);
                r.lastLoginDate = String.valueOf(u.LastLoginDate.date());
            } else {
                r.dormantDays   = -1;
                r.lastLoginDate = 'Never';
            }

            List<FlagDetail> flags = new List<FlagDetail>();
            String sev = 'High';
            for (String permName : flagPerms) {
                if (isGranted(permMap, u.Id, permName)) {
                    FlagDetail fd = makeFlag(permMap, u.Id, permName);
                    flags.add(fd);
                    sev = maxSeverity(sev, fd.severity);
                }
            }
            r.flagDetails = flags;

            String daysLabel = r.dormantDays == -1 ? 'Never logged in' : 'Dormant ' + r.dormantDays + ' days';
            r.riskReason = flags.isEmpty() ? daysLabel : daysLabel + ' · ' + joinLabels(flags);
            r.severity   = flags.isEmpty() ? 'High' : sev;
            rows.add(r);
        }
        return rows;
    }

    // ─────────────────────────────────────────────
    // PRIVILEGED ACCESS — combined Profile + Permission Set, deduped
    // ─────────────────────────────────────────────

    @AuraEnabled(cacheable=false)
    public static List<UserRow> getPrivilegedUsers() {
        List<String> secondaryPerms = new List<String>{
            'PermissionsForceTwoFactor', 'PermissionsDataExport', 'PermissionsPasswordNeverExpires'
        };
        List<String> allPerms = new List<String>();
        allPerms.addAll(PRIVILEGED_PERMS);
        allPerms.addAll(secondaryPerms);

        Set<Id> candidateIds = getCandidateUserIds(PRIVILEGED_PERMS);
        if (candidateIds.isEmpty()) return new List<UserRow>();

        Map<Id, Map<String, PermState>> permMap = buildEffectivePermissionMap(allPerms, candidateIds);

        List<User> userRecs = [
            SELECT Id, Username, Name, Profile.Id, Profile.Name, LastLoginDate, IsActive
            FROM User WHERE Id IN :candidateIds AND IsActive = true
            ORDER BY Name ASC LIMIT 300
        ];

        // Search-by-Permission-Set support
        Set<Id> userRecIds = new Set<Id>();
        for (User u : userRecs) userRecIds.add(u.Id);
        Map<Id, String> permSetNames = resolvePermissionSetNames(userRecIds);

        List<UserRow> rows = new List<UserRow>();
        for (User u : userRecs) {
            List<FlagDetail> flags = new List<FlagDetail>();
            String sev = null;

            for (String permName : PRIVILEGED_PERMS) {
                if (isGranted(permMap, u.Id, permName)) {
                    FlagDetail fd = makeFlag(permMap, u.Id, permName);
                    flags.add(fd);
                    sev = maxSeverity(sev, fd.severity);
                }
            }
            if (flags.isEmpty()) continue; // dedupe safety: only real primary-perm holders

            if (!isGranted(permMap, u.Id, 'PermissionsForceTwoFactor')) {
                FlagDetail fd = new FlagDetail();
                fd.permName = 'MFA Disabled'; fd.source = 'N/A'; fd.sourceDetail = '';
                fd.label = 'MFA Disabled'; fd.severity = 'High';
                flags.add(fd);
                sev = maxSeverity(sev, 'High');
            }
            if (isGranted(permMap, u.Id, 'PermissionsDataExport')) {
                flags.add(makeFlag(permMap, u.Id, 'PermissionsDataExport'));
            }
            if (isGranted(permMap, u.Id, 'PermissionsPasswordNeverExpires')) {
                flags.add(makeFlag(permMap, u.Id, 'PermissionsPasswordNeverExpires'));
            }

            UserRow r = new UserRow();
            r.userId      = u.Id;
            r.userName    = u.Username;
            r.name        = u.Name;
            r.profileName = u.Profile != null ? u.Profile.Name : 'N/A';
            r.profileId   = u.Profile != null ? u.Profile.Id   : null;
            r.lastLoginDate = u.LastLoginDate != null ? String.valueOf(u.LastLoginDate.date()) : 'Never';
            r.isActive    = u.IsActive;
            r.flagDetails = flags;
            r.riskReason  = joinLabels(flags);
            r.severity    = sev;
            r.permissionSetName = permSetNames.containsKey(u.Id) ? permSetNames.get(u.Id) : '';
            rows.add(r);
        }
        return rows;
    }

    // ─────────────────────────────────────────────
    // EXPORT / DOWNLOAD — combined Profile + Permission Set, deduped
    // ─────────────────────────────────────────────

    @AuraEnabled(cacheable=false)
    public static List<UserRow> getExportEnabledUsers() {
        Set<Id> candidateIds = getCandidateUserIds(EXPORT_PERMS);
        if (candidateIds.isEmpty()) return new List<UserRow>();

        Map<Id, Map<String, PermState>> permMap = buildEffectivePermissionMap(EXPORT_PERMS, candidateIds);

        List<User> userRecs = [
            SELECT Id, Username, Name, Profile.Id, Profile.Name, LastLoginDate, IsActive
            FROM User WHERE Id IN :candidateIds AND IsActive = true
            ORDER BY Name ASC LIMIT 300
        ];

        // Search-by-Permission-Set support
        Set<Id> userRecIds = new Set<Id>();
        for (User u : userRecs) userRecIds.add(u.Id);
        Map<Id, String> permSetNames = resolvePermissionSetNames(userRecIds);

        List<UserRow> rows = new List<UserRow>();
        for (User u : userRecs) {
            List<FlagDetail> flags = new List<FlagDetail>();
            String sev = null;
            for (String permName : EXPORT_PERMS) {
                if (isGranted(permMap, u.Id, permName)) {
                    FlagDetail fd = makeFlag(permMap, u.Id, permName);
                    flags.add(fd);
                    sev = maxSeverity(sev, fd.severity);
                }
            }
            if (flags.isEmpty()) continue;

            UserRow r = new UserRow();
            r.userId      = u.Id;
            r.userName    = u.Username;
            r.name        = u.Name;
            r.profileName = u.Profile != null ? u.Profile.Name : 'N/A';
            r.profileId   = u.Profile != null ? u.Profile.Id   : null;
            r.lastLoginDate = u.LastLoginDate != null ? String.valueOf(u.LastLoginDate.date()) : 'Never';
            r.isActive    = u.IsActive;
            r.flagDetails = flags;
            r.riskReason  = joinLabels(flags);
            r.severity    = sev;
            r.permissionSetName = permSetNames.containsKey(u.Id) ? permSetNames.get(u.Id) : '';
            rows.add(r);
        }
        return rows;
    }

    // ─────────────────────────────────────────────
    // PASSWORD NEVER EXPIRES — combined Profile + Permission Set, deduped
    // ─────────────────────────────────────────────

    @AuraEnabled(cacheable=false)
    public static List<UserRow> getPasswordNeverExpiresUsers() {
        Set<Id> candidateIds = getCandidateUserIds(new List<String>{ 'PermissionsPasswordNeverExpires' });
        if (candidateIds.isEmpty()) return new List<UserRow>();

        List<String> allPerms = new List<String>{
            'PermissionsPasswordNeverExpires', 'PermissionsModifyAllData', 'PermissionsForceTwoFactor'
        };
        Map<Id, Map<String, PermState>> permMap = buildEffectivePermissionMap(allPerms, candidateIds);

        List<User> userRecs = [
            SELECT Id, Username, Name, Profile.Id, Profile.Name, LastLoginDate, IsActive,
                   LastPasswordChangeDate
            FROM User WHERE Id IN :candidateIds AND IsActive = true
            ORDER BY Name ASC LIMIT 300
        ];

        // Search-by-Permission-Set support
        Set<Id> userRecIds = new Set<Id>();
        for (User u : userRecs) userRecIds.add(u.Id);
        Map<Id, String> permSetNames = resolvePermissionSetNames(userRecIds);

        List<UserRow> rows = new List<UserRow>();
        for (User u : userRecs) {
            if (!isGranted(permMap, u.Id, 'PermissionsPasswordNeverExpires')) continue;

            Boolean isAdmin = isGranted(permMap, u.Id, 'PermissionsModifyAllData');
            Boolean noMfa   = !isGranted(permMap, u.Id, 'PermissionsForceTwoFactor');

            List<FlagDetail> flags = new List<FlagDetail>();
            flags.add(makeFlag(permMap, u.Id, 'PermissionsPasswordNeverExpires'));
            String sev = 'High';
            if (isAdmin) {
                flags.add(makeFlag(permMap, u.Id, 'PermissionsModifyAllData'));
                sev = 'Critical';
            }
            if (noMfa) {
                FlagDetail fd = new FlagDetail();
                fd.permName = 'MFA Disabled'; fd.source = 'N/A'; fd.sourceDetail = '';
                fd.label = 'MFA Disabled'; fd.severity = 'High';
                flags.add(fd);
            }

            UserRow r = new UserRow();
            r.userId      = u.Id;
            r.userName    = u.Username;
            r.name        = u.Name;
            r.profileName = u.Profile != null ? u.Profile.Name : 'N/A';
            r.profileId   = u.Profile != null ? u.Profile.Id   : null;
            r.lastLoginDate = u.LastLoginDate != null ? String.valueOf(u.LastLoginDate.date()) : 'Never';
            r.isActive    = u.IsActive;

            r.lastPasswordChangeDate = u.LastPasswordChangeDate != null
                ? String.valueOf(u.LastPasswordChangeDate)
                : null;
            r.passwordExpiryDays = 0;

            r.flagDetails = flags;
            r.riskReason  = joinLabels(flags);
            r.severity    = sev;
            r.permissionSetName = permSetNames.containsKey(u.Id) ? permSetNames.get(u.Id) : '';
            rows.add(r);
        }
        return rows;
    }

    // ─────────────────────────────────────────────
    // PRIVILEGED ACCESS (legacy alias kept off — see getPrivilegedUsers above)
    // ─────────────────────────────────────────────

    // ─────────────────────────────────────────────
    // FAILED LOGINS — unchanged from original
    // ─────────────────────────────────────────────

    @AuraEnabled(cacheable=false)
    public static List<LoginRow> getRecentFailedLogins(Integer hoursBack) {
        List<LoginRow> rows = new List<LoginRow>();
        if (hoursBack == null || hoursBack < 1) hoursBack = 48;
        if (hoursBack > 8760)                    hoursBack = 8760;

        DateTime cutoff = DateTime.now().addHours(-hoursBack);

        List<LoginHistory> loginList = new List<LoginHistory>();
        for (LoginHistory lh : [
            SELECT UserId, LoginTime, Status, SourceIp, Browser,
                   CountryIso, TlsProtocol, Application,
                   LoginType, LoginSubType, LoginUrl,
                   NetworkId, ForwardedForIp
            FROM LoginHistory
            WHERE LoginTime >= :cutoff
            ORDER BY LoginTime DESC
            LIMIT 1000
        ]) {
            if (lh.Status != 'Success') {
                loginList.add(lh);
                if (loginList.size() >= 500) break;
            }
        }

        Set<Id> userIds = new Set<Id>();
        for (LoginHistory lh : loginList) {
            if (lh.UserId != null) userIds.add(lh.UserId);
        }
        Map<Id, User> userMap = new Map<Id, User>([
            SELECT Id, Name, Username FROM User WHERE Id IN :userIds
        ]);

        for (LoginHistory lh : loginList) {
            LoginRow r   = new LoginRow();
            r.userId     = lh.UserId;
            r.sourceIp   = lh.SourceIp;
            r.status     = lh.Status;
            r.loginTime  = lh.LoginTime != null ? String.valueOf(lh.LoginTime) : '';
            r.browser    = lh.Browser;
            r.country    = lh.CountryIso;
            r.tlsProtocol = lh.TlsProtocol;
            r.loginType      = lh.LoginType;
            r.loginSubType   = lh.LoginSubType;
            r.application    = lh.Application;
            r.loginUrl       = lh.LoginUrl;
            r.experience     = lh.NetworkId;
            r.forwardedForIp = lh.ForwardedForIp;

            if (lh.UserId != null && userMap.containsKey(lh.UserId)) {
                User u = userMap.get(lh.UserId);
                r.userFullName = u.Name;
                r.userName     = u.Username;
            } else {
                r.userFullName = 'Unknown';
                r.userName     = String.valueOf(lh.UserId);
            }
            rows.add(r);
        }
        return rows;
    }

    // ─────────────────────────────────────────────
    // AUDIT TRAIL
    // ─────────────────────────────────────────────
    // CHANGE LOG:
    //   - Severity has been removed from AuditRow / this method per the
    //     "Remove Severity from Audit Trail" requirement. The event-relevance
    //     filtering logic (package/permission/profile/manage) and the 2000-row
    //     cap are unchanged.
    //   - A "Search by Permission Set" filter was added on the LWC side. To
    //     support it, this method resolves each event's actor (CreatedBy) to
    //     their assigned, non-profile-owned Permission Set label(s) using the
    //     shared resolvePermissionSetNames() helper (the same helper used by
    //     Dormant/Privileged/Export/Password below) and returns them as a
    //     comma-separated permissionSetName string.

    @AuraEnabled(cacheable=false)
    public static List<AuditRow> getAuditEvents(String fromDate, String toDate, Integer recordLimit) {
        List<AuditRow> rows = new List<AuditRow>();
        if (recordLimit == null || recordLimit < 1) recordLimit = 5000;
        if (recordLimit > 50000)                    recordLimit = 50000;

        String soql =
            'SELECT Action, Section, CreatedBy.Id, CreatedBy.Name, CreatedDate, Display ' +
            'FROM SetupAuditTrail ' +
            'WHERE (Action LIKE \'%package%\' OR Action LIKE \'%permission%\' OR Action LIKE \'%profile%\')';

        if (String.isNotBlank(fromDate)) {
            DateTime fd = DateTime.valueOf(fromDate.replace('T', ' ').replace('Z', ''));
            soql += ' AND CreatedDate >= ' + fd.format('yyyy-MM-dd\'T\'HH:mm:ss\'Z\'');
        }
        if (String.isNotBlank(toDate)) {
            DateTime td = DateTime.valueOf(toDate.replace('T', ' ').replace('Z', ''));
            soql += ' AND CreatedDate <= ' + td.format('yyyy-MM-dd\'T\'HH:mm:ss\'Z\'');
        }
        soql += ' ORDER BY CreatedDate DESC LIMIT ' + recordLimit;

        // Pass 1: apply the same "relevant" filtering / 2000-row cap as before.
        List<SetupAuditTrail> auditList = new List<SetupAuditTrail>();
        for (SetupAuditTrail sat : Database.query(soql)) {
            String actionVal  = sat.Action  != null ? sat.Action.toLowerCase()  : '';
            String sectionVal = sat.Section != null ? sat.Section.toLowerCase() : '';
            Boolean relevant  = actionVal.contains('package') || actionVal.contains('permission')
                             || actionVal.contains('profile') || sectionVal.contains('manage');
            if (!relevant) continue;
            auditList.add(sat);
            if (auditList.size() >= 2000) break;
        }

        // Pass 2: resolve non-profile-owned Permission Set names for each event's actor.
        Set<Id> createdByIds = new Set<Id>();
        for (SetupAuditTrail sat : auditList) {
            if (sat.CreatedBy != null) createdByIds.add(sat.CreatedBy.Id);
        }
        Map<Id, String> permSetsByUser = resolvePermissionSetNames(createdByIds);

        for (SetupAuditTrail sat : auditList) {
            AuditRow r      = new AuditRow();
            r.action        = sat.Action;
            r.section       = sat.Section;
            r.createdByName = sat.CreatedBy != null ? sat.CreatedBy.Name : 'Unknown';
            r.createdById   = sat.CreatedBy != null ? sat.CreatedBy.Id   : null;
            r.createdDate   = String.valueOf(sat.CreatedDate);
            r.display       = sat.Display;

            r.permissionSetName = (sat.CreatedBy != null && permSetsByUser.containsKey(sat.CreatedBy.Id))
                ? permSetsByUser.get(sat.CreatedBy.Id)
                : '';

            rows.add(r);
        }
        return rows;
    }
}