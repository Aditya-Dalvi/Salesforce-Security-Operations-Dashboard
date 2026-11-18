/**
 * SocFreezeController
 * Handles freeze / unfreeze of dormant User accounts via UserLogin object.
 * Also provides a list of currently frozen users for the dashboard.
 *
 * CSV DOWNLOAD AUTHORIZATION:
 *   Only users whose Profile is:
 *      1. System Administrator
 *      2. Custom Admin
 *   are permitted to use SOC CSV download functionality.
 *
 * NOTE:
 *   canDownloadCsv() checks the CURRENTLY LOGGED-IN USER (the person viewing
 *   the SOC dashboard) — NOT the users displayed in the dashboard's tables.
 *
 * SECURITY NOTE:
 *   This is a UI-layer + Apex-authorization control. CSV files are still
 *   assembled client-side (in socDashboard.js) from data already delivered
 *   to the browser for rendering the tables. canDownloadCsv() prevents
 *   unauthorized users from ever seeing or using the download option, but
 *   for a stronger, exfiltration-resistant control the CSV generation
 *   itself should eventually move server-side (Apex builds and returns the
 *   file; unauthorized users never receive the row data at all).
 *
 * HOW FREEZE WORKS IN SALESFORCE:
 *   Salesforce does NOT have an IsFrozen field on User.
 *   Freezing is done by upserting a UserLogin record with IsFrozen = true.
 *   UserLogin.UserId is the lookup to User; there is one UserLogin per User.
 */
public without sharing class SocFreezeController {

    // ─────────────────────────────────────────────
    // CSV ACCESS CONFIGURATION
    // ─────────────────────────────────────────────

    /**
     * Profile names allowed to download SOC CSV files.
     * If your custom administrator profile has a different name,
     * update 'Custom Admin' to match it exactly.
     */
    private static final Set<String> CSV_ALLOWED_PROFILES = new Set<String>{
        'System Administrator',
        'Custom Admin'
    };

    // ─────────────────────────────────────────────
    // CSV DOWNLOAD AUTHORIZATION
    // ─────────────────────────────────────────────

    /**
     * Returns TRUE only when the CURRENTLY LOGGED-IN Salesforce user
     * (UserInfo.getUserId()) is authorized to download SOC CSV files —
     * i.e. their Profile is in CSV_ALLOWED_PROFILES.
     *
     * Allowed:   System Administrator, Custom Admin
     * Not allowed: Standard User, Sales/Branch/Integration profiles, or
     *              any other profile not explicitly listed above.
     */
    @AuraEnabled(cacheable=true)
    public static Boolean canDownloadCsv() {
        User currentUser = [
            SELECT Id, Profile.Name
            FROM User
            WHERE Id = :UserInfo.getUserId()
            LIMIT 1
        ];

        if (currentUser.Profile == null) return false;
        return CSV_ALLOWED_PROFILES.contains(currentUser.Profile.Name);
    }

    // ─────────────────────────────────────────────
    // WRAPPER — returned to LWC for frozen users list
    // ─────────────────────────────────────────────
    public class FrozenUserRow {
        @AuraEnabled public String userId;
        @AuraEnabled public String userName;
        @AuraEnabled public String name;
        @AuraEnabled public String profileName;
        @AuraEnabled public String profileId;
        @AuraEnabled public String lastLoginDate;
        @AuraEnabled public String frozenDate;      // when we froze them (UserLogin.LastModifiedDate)
        @AuraEnabled public String userUrl;
        @AuraEnabled public String profileUrl;
    }

    public class FreezeResult {
        @AuraEnabled public Boolean success;
        @AuraEnabled public Integer frozenCount;
        @AuraEnabled public Integer skippedCount;   // sysadmins / integration users skipped
        @AuraEnabled public String  message;
        @AuraEnabled public List<String> skippedNames;
    }

    // ─────────────────────────────────────────────
    // FREEZE selected user IDs
    // Called from LWC with a list of selected userId strings
    // ─────────────────────────────────────────────
    @AuraEnabled
    public static FreezeResult freezeUsers(List<String> userIds) {
        FreezeResult result = new FreezeResult();
        result.frozenCount  = 0;
        result.skippedCount = 0;
        result.skippedNames = new List<String>();

        if (userIds == null || userIds.isEmpty()) {
            result.success = false;
            result.message = 'No users selected.';
            return result;
        }

        // Safety check: never freeze System Administrators or Integration users
        List<User> users = [
            SELECT Id, Name, Profile.Name, UserType
            FROM User
            WHERE Id IN :userIds
            AND IsActive = true
        ];

        List<Id> safeToFreeze = new List<Id>();
        for (User u : users) {
            String profName = u.Profile != null ? u.Profile.Name : '';
            Boolean isAdmin       = profName == 'System Administrator';
            Boolean isIntegration = profName.toLowerCase().contains('integration');
            Boolean isNonStandard = u.UserType != 'Standard';

            if (isAdmin || isIntegration || isNonStandard) {
                result.skippedCount++;
                result.skippedNames.add(u.Name + ' (' + profName + ')');
            } else {
                safeToFreeze.add(u.Id);
            }
        }

        if (safeToFreeze.isEmpty()) {
            result.success = false;
            result.message = 'All selected users were skipped (System Administrators / Integration users cannot be frozen).';
            return result;
        }

        // Salesforce auto-creates a UserLogin for every User — always update existing ones
        // UserLogin.UserId is NOT writeable, so we cannot create new UserLogin records
        List<UserLogin> toUpdate = new List<UserLogin>();
        for (UserLogin ul : [
            SELECT Id, UserId, IsFrozen
            FROM UserLogin
            WHERE UserId IN :safeToFreeze
        ]) {
            ul.IsFrozen = true;
            toUpdate.add(ul);
        }

        if (toUpdate.isEmpty()) {
            result.success = false;
            result.message = 'No UserLogin records found for selected users. This should not happen — please contact your Salesforce admin.';
            return result;
        }

        try {
            update toUpdate;
            result.success     = true;
            result.frozenCount = toUpdate.size();
            result.message     = result.frozenCount + ' user(s) frozen successfully.'
                + (result.skippedCount > 0 ? ' ' + result.skippedCount + ' skipped.' : '');
        } catch (DmlException e) {
            result.success = false;
            result.message = 'Freeze failed: ' + e.getMessage();
        }
        return result;
    }

    // ─────────────────────────────────────────────
    // UNFREEZE selected user IDs
    // ─────────────────────────────────────────────
    @AuraEnabled
    public static FreezeResult unfreezeUsers(List<String> userIds) {
        FreezeResult result = new FreezeResult();
        result.frozenCount  = 0;
        result.skippedCount = 0;
        result.skippedNames = new List<String>();

        if (userIds == null || userIds.isEmpty()) {
            result.success = false;
            result.message = 'No users selected.';
            return result;
        }

        List<UserLogin> toUpdate = new List<UserLogin>();
        for (UserLogin ul : [
            SELECT Id, UserId, IsFrozen
            FROM UserLogin
            WHERE UserId IN :userIds
            AND IsFrozen = true
        ]) {
            ul.IsFrozen = false;
            toUpdate.add(ul);
        }

        if (toUpdate.isEmpty()) {
            result.success = false;
            result.message = 'None of the selected users are currently frozen.';
            return result;
        }

        try {
            update toUpdate;
            result.success     = true;
            result.frozenCount = toUpdate.size();
            result.message     = result.frozenCount + ' user(s) unfrozen successfully.';
        } catch (DmlException e) {
            result.success = false;
            result.message = 'Unfreeze failed: ' + e.getMessage();
        }
        return result;
    }

    // ─────────────────────────────────────────────
    // GET FROZEN USERS — for the Frozen Accounts sub-tab
    // ─────────────────────────────────────────────
    @AuraEnabled(cacheable=false)
    public static List<FrozenUserRow> getFrozenUsers() {
        List<FrozenUserRow> rows = new List<FrozenUserRow>();

        // Get all currently frozen UserLogin records
        List<UserLogin> frozenLogins = [
            SELECT UserId, IsFrozen, LastModifiedDate
            FROM UserLogin
            WHERE IsFrozen = true
            ORDER BY LastModifiedDate DESC
            LIMIT 500
        ];

        if (frozenLogins.isEmpty()) return rows;

        Set<Id> frozenUserIds = new Set<Id>();
        Map<Id, UserLogin> loginMap = new Map<Id, UserLogin>();
        for (UserLogin ul : frozenLogins) {
            frozenUserIds.add(ul.UserId);
            loginMap.put(ul.UserId, ul);
        }

        for (User u : [
            SELECT Id, Username, Name, Profile.Id, Profile.Name, LastLoginDate, IsActive
            FROM User
            WHERE Id IN :frozenUserIds
            ORDER BY Name ASC
        ]) {
            FrozenUserRow r    = new FrozenUserRow();
            r.userId           = u.Id;
            r.userName         = u.Username;
            r.name             = u.Name;
            r.profileName      = u.Profile != null ? u.Profile.Name : 'N/A';
            r.profileId        = u.Profile != null ? u.Profile.Id   : null;
            r.lastLoginDate    = u.LastLoginDate != null ? String.valueOf(u.LastLoginDate.date()) : 'Never';
            r.userUrl          = '/lightning/r/User/' + u.Id + '/view';
            r.profileUrl       = u.Profile != null ? '/lightning/r/Profile/' + u.Profile.Id + '/view' : null;

            UserLogin ul = loginMap.get(u.Id);
            r.frozenDate = ul != null ? String.valueOf(ul.LastModifiedDate) : '';
            rows.add(r);
        }
        return rows;
    }
}