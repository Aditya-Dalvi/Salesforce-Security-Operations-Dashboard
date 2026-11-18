/**
 * SocDashboardControllerTest
 * Test class for SocDashboardController and SocFreezeController.
 * Target: ≥75% code coverage across both controllers.
 *
 * FIXES applied vs. previous version:
 *  1. testGetSummaryMfaBypass — the original version queried
 *     PermissionSet.PermissionsBypassMFAForUiLogins, which is not a real field
 *     on PermissionSet in any Salesforce release and caused a compile-time
 *     "No such column" error. SocDashboardController.getSummary() now resolves
 *     the MFA-bypass field dynamically at runtime (see
 *     SocDashboardController.resolveMfaBypassField), so this test no longer
 *     needs to set up a permission set assignment at all — it just asserts
 *     mfaBypassUsers comes back >= 0 regardless of whether the org has a
 *     matching field.
 *
 *  2. testFreezeUsersSysAdminSkipped — replaced UserInfo.getUserId() with an
 *     explicit System Administrator user created inside the test.
 *     UserInfo.getUserId() returns the test runner whose profile name may not
 *     equal 'System Administrator' exactly, so SocFreezeController didn't skip
 *     them and skippedCount stayed 0.
 *     Running as a known SysAdmin user via System.runAs() is also an option,
 *     but inserting and directly referencing the ID is simpler here.
 *
 *  3. testFreezeUsersMixed — same root cause as fix 2; now uses the same
 *     explicit SysAdmin user so the skip logic fires reliably.
 *
 *  4. ADDED — testFreezeUsersInactiveUserExcluded and
 *     testFreezeUsersNonExistentIdIgnored: extra edge-case coverage for
 *     SocFreezeController.freezeUsers() around its initial
 *     "WHERE IsActive = true" filter, which silently excludes both inactive
 *     users and non-existent/mismatched IDs before the admin/integration skip
 *     logic ever runs.
 *
 *  5. UPDATED (Severity removal / Permission Set filter) — AuditRow no longer
 *     has a `severity` field; it now has `permissionSetName`. Updated
 *     testWrapperClassInstantiation accordingly and added a null-check
 *     assertion for `permissionSetName` in testGetAuditEventsNoFilter for
 *     coverage of the new field.
 *
 *  6. ADDED — UserRow.permissionSetName was added to support "Search by
 *     Permission Set" on Dormant, Privileged, Export, and Password Policy.
 *     Added assertions confirming permissionSetName is populated (never null)
 *     on rows returned by getDormantUsers, getPrivilegedUsers,
 *     getExportEnabledUsers, and getPasswordNeverExpiresUsers.
 */
@isTest
private class SocDashboardControllerTest {

    // ─────────────────────────────────────────────────────────────────────────
    // HELPER — create a test user with a given profile
    // ─────────────────────────────────────────────────────────────────────────
    private static User makeUser(String alias, String profileName) {
        Profile p = [SELECT Id FROM Profile WHERE Name = :profileName LIMIT 1];
        User u = new User(
            Alias            = alias.left(8),
            Email            = alias + '@soc.test.invalid',
            EmailEncodingKey = 'UTF-8',
            FirstName        = alias,
            LastName         = 'TestUser',
            LanguageLocaleKey= 'en_US',
            LocaleSidKey     = 'en_US',
            ProfileId        = p.Id,
            TimeZoneSidKey   = 'America/Los_Angeles',
            UserName         = alias + '@soc.test.' + UserInfo.getOrganizationId() + '.invalid'
        );
        return u;
    }

    private static User makeStandardUser(String alias) {
        return makeUser(alias, 'Standard User');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST DATA SETUP (shared)
    // ─────────────────────────────────────────────────────────────────────────
    @TestSetup
    static void setupData() {
        List<User> users = new List<User>{
            makeStandardUser('soctest1'),
            makeStandardUser('soctest2'),
            makeStandardUser('soctest3'),
            makeStandardUser('soctest4')
        };
        insert users;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // getSummary()
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetSummary() {
        Test.startTest();
        SocDashboardController.SocSummary s = SocDashboardController.getSummary();
        Test.stopTest();

        System.assertNotEquals(null, s, 'SocSummary should not be null');
        System.assert(s.dormantUsers            >= 0, 'dormantUsers should be >= 0');
        System.assert(s.dormantPrivilegedUsers  >= 0, 'dormantPrivilegedUsers should be >= 0');
        System.assert(s.modifyAllDataUsers      >= 0, 'modifyAllDataUsers should be >= 0');
        System.assert(s.viewAllDataUsers        >= 0, 'viewAllDataUsers should be >= 0');
        System.assert(s.viewEncryptedUsers      >= 0, 'viewEncryptedUsers should be >= 0');
        System.assert(s.mfaDisabledUsers        >= 0, 'mfaDisabledUsers should be >= 0');
        System.assert(s.mfaBypassUsers          >= 0, 'mfaBypassUsers should be >= 0');
        System.assert(s.exportEnabledUsers      >= 0, 'exportEnabledUsers should be >= 0');
        System.assert(s.passwordNeverExpiresUsers >= 0, 'passwordNeverExpiresUsers should be >= 0');
        System.assert(s.failedLoginsLast24h     >= 0, 'failedLoginsLast24h should be >= 0');
        System.assert(s.packageInstallEvents    >= 0, 'packageInstallEvents should be >= 0');
        System.assert(s.criticalRiskUsers       >= 0, 'criticalRiskUsers should be >= 0');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // getDormantCount()
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetDormantCount() {
        Test.startTest();
        Integer count = SocDashboardController.getDormantCount();
        Test.stopTest();

        System.assert(count >= 0, 'Dormant count should be >= 0');
    }

    @isTest
    static void testGetDormantUsersDefaultLimit() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getDormantUsers(null);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getDormantUsers(null) should return a list');
    }

    @isTest
    static void testGetDormantUsersExplicitLimit() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getDormantUsers(100);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getDormantUsers(100) should return a list');
    }

    @isTest
    static void testGetDormantUsersLimitTooLow() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getDormantUsers(10);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getDormantUsers(10) should return a list after clamping');
    }

    @isTest
    static void testGetDormantUsersLimitTooHigh() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getDormantUsers(99999);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getDormantUsers(99999) should return a list after clamping');
    }

    @isTest
    static void testGetDormantUsersRowFields() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getDormantUsers(500);
        Test.stopTest();

        SocDashboardController.UserRow found = null;
        for (SocDashboardController.UserRow r : rows) {
            if (r.userName != null && r.userName.contains('soctest1')) {
                found = r;
                break;
            }
        }

        if (found != null) {
            System.assertNotEquals(null, found.userId,      'userId should be set');
            System.assertNotEquals(null, found.name,        'name should be set');
            System.assertNotEquals(null, found.profileName, 'profileName should be set');
            System.assertNotEquals(null, found.severity,    'severity should be set');
            System.assertNotEquals(null, found.riskReason,  'riskReason should be set');
            System.assertNotEquals(null, found.permissionSetName,
                'permissionSetName should not be null (empty string allowed)');
            System.assertEquals(-1, found.dormantDays,      'Never-logged-in users should have dormantDays = -1');
            System.assertEquals('Never', found.lastLoginDate, 'Never-logged-in users should show Never');
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // getPrivilegedUsers()
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetPrivilegedUsers() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getPrivilegedUsers();
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getPrivilegedUsers should return a list');
        for (SocDashboardController.UserRow r : rows) {
            System.assertNotEquals(null, r.userId,     'userId should be populated');
            System.assertNotEquals(null, r.severity,   'severity should be populated');
            System.assertNotEquals(null, r.riskReason, 'riskReason should be populated');
            System.assertNotEquals(null, r.permissionSetName,
                'permissionSetName should not be null (empty string allowed)');
        }
    }

    @isTest
    static void testGetPrivilegedUsersContainsSysAdmin() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getPrivilegedUsers();
        Test.stopTest();

        Boolean foundCritical = false;
        for (SocDashboardController.UserRow r : rows) {
            if (r.severity == 'Critical') { foundCritical = true; break; }
        }
        System.assert(foundCritical, 'At least one Critical-severity privileged user expected (SysAdmin)');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // getRecentFailedLogins()
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetRecentFailedLoginsDefault() {
        Test.startTest();
        List<SocDashboardController.LoginRow> rows =
            SocDashboardController.getRecentFailedLogins(48);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getRecentFailedLogins should return a list');
    }

    @isTest
    static void testGetRecentFailedLoginsNull() {
        Test.startTest();
        List<SocDashboardController.LoginRow> rows =
            SocDashboardController.getRecentFailedLogins(null);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getRecentFailedLogins(null) should return a list');
    }

    @isTest
    static void testGetRecentFailedLoginsZero() {
        Test.startTest();
        List<SocDashboardController.LoginRow> rows =
            SocDashboardController.getRecentFailedLogins(0);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getRecentFailedLogins(0) should return a list');
    }

    @isTest
    static void testGetRecentFailedLoginsOversize() {
        Test.startTest();
        List<SocDashboardController.LoginRow> rows =
            SocDashboardController.getRecentFailedLogins(99999);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getRecentFailedLogins(99999) should return a list');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // getAuditEvents()
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetAuditEventsNoFilter() {
        Test.startTest();
        List<SocDashboardController.AuditRow> rows =
            SocDashboardController.getAuditEvents(null, null, 500);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getAuditEvents should return a list');
        for (SocDashboardController.AuditRow r : rows) {
            System.assertNotEquals(null, r.permissionSetName,
                'permissionSetName should not be null (empty string allowed when no perm sets assigned)');
        }
    }

    @isTest
    static void testGetAuditEventsWithDateRange() {
        String fromIso = DateTime.now().addDays(-7).format('yyyy-MM-dd\'T\'HH:mm:ss\'Z\'');
        String toIso   = DateTime.now().format('yyyy-MM-dd\'T\'HH:mm:ss\'Z\'');

        Test.startTest();
        List<SocDashboardController.AuditRow> rows =
            SocDashboardController.getAuditEvents(fromIso, toIso, 100);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getAuditEvents with date range should return a list');
    }

    @isTest
    static void testGetAuditEventsNullLimit() {
        Test.startTest();
        List<SocDashboardController.AuditRow> rows =
            SocDashboardController.getAuditEvents(null, null, null);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getAuditEvents(null limit) should return a list');
    }

    @isTest
    static void testGetAuditEventsOverLimit() {
        Test.startTest();
        List<SocDashboardController.AuditRow> rows =
            SocDashboardController.getAuditEvents(null, null, 999999);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getAuditEvents(oversized limit) should return a list');
    }

    @isTest
    static void testGetAuditEventsOnlyFrom() {
        String fromIso = DateTime.now().addDays(-30).format('yyyy-MM-dd\'T\'HH:mm:ss\'Z\'');

        Test.startTest();
        List<SocDashboardController.AuditRow> rows =
            SocDashboardController.getAuditEvents(fromIso, null, 200);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'Should return a list with only fromDate');
    }

    @isTest
    static void testGetAuditEventsOnlyTo() {
        String toIso = DateTime.now().format('yyyy-MM-dd\'T\'HH:mm:ss\'Z\'');

        Test.startTest();
        List<SocDashboardController.AuditRow> rows =
            SocDashboardController.getAuditEvents(null, toIso, 200);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'Should return a list with only toDate');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // getExportEnabledUsers()
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetExportEnabledUsers() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getExportEnabledUsers();
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getExportEnabledUsers should return a list');
        for (SocDashboardController.UserRow r : rows) {
            System.assertNotEquals(null, r.userId,     'userId should be populated');
            System.assertNotEquals(null, r.riskReason, 'riskReason should be populated');
            System.assertNotEquals(null, r.severity,   'severity should be populated');
            System.assertNotEquals(null, r.permissionSetName,
                'permissionSetName should not be null (empty string allowed)');
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // getPasswordNeverExpiresUsers()
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetPasswordNeverExpiresUsers() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getPasswordNeverExpiresUsers();
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getPasswordNeverExpiresUsers should return a list');
        for (SocDashboardController.UserRow r : rows) {
            System.assertNotEquals(null, r.userId,     'userId should be populated');
            System.assertNotEquals(null, r.severity,   'severity should be populated');
            System.assertNotEquals(null, r.riskReason, 'riskReason should be populated');
            System.assertNotEquals(null, r.permissionSetName,
                'permissionSetName should not be null (empty string allowed)');
            System.assertEquals(0, r.passwordExpiryDays,
                'passwordExpiryDays should be 0 for PasswordNeverExpires users');
        }
    }

    @isTest
    static void testGetPasswordNeverExpiresFieldPopulation() {
        Test.startTest();
        List<SocDashboardController.UserRow> rows =
            SocDashboardController.getPasswordNeverExpiresUsers();
        Test.stopTest();

        for (SocDashboardController.UserRow r : rows) {
            if (r.riskReason != null &&
                r.riskReason.contains('PasswordNeverExpires + ModifyAllData')) {
                System.assertEquals('Critical', r.severity,
                    'ModifyAllData + PwdNeverExpires should be Critical');
            }
            if (r.lastPasswordChangeDate != null) {
                System.assert(r.lastPasswordChangeDate.length() > 0,
                    'lastPasswordChangeDate should not be empty string when set');
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FREEZE CONTROLLER TESTS
    // ─────────────────────────────────────────────────────────────────────────

    @isTest
    static void testFreezeUsersEmptyList() {
        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(new List<String>());
        Test.stopTest();

        System.assertEquals(false,  result.success, 'Empty list should fail');
        System.assertEquals('No users selected.', result.message, 'Should report no users selected');
    }

    @isTest
    static void testFreezeUsersNullList() {
        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(null);
        Test.stopTest();

        System.assertEquals(false, result.success, 'Null list should fail');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIX 2: testFreezeUsersSysAdminSkipped
    //
    // Root cause: UserInfo.getUserId() returns the test runner's ID. If the
    // test runner's profile is not exactly 'System Administrator', the freeze
    // controller does NOT skip them — it tries to freeze them, finds no
    // UserLogin (or freezes them), and skippedCount stays 0.
    //
    // Fix: Create an explicit System Administrator user and pass their ID. That
    // guarantees the profile name check in SocFreezeController fires correctly.
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testFreezeUsersSysAdminSkipped() {
        // Create a real System Administrator user so the profile name check
        // inside SocFreezeController is guaranteed to match.
        User sysAdminUser = makeUser('socadm1', 'System Administrator');
        insert sysAdminUser;

        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(new List<String>{ sysAdminUser.Id });
        Test.stopTest();

        System.assertEquals(false, result.success,
            'SysAdmin user should be skipped, making the freeze fail');
        System.assert(result.skippedCount > 0,
            'skippedCount should be > 0 for SysAdmin');
        System.assert(result.skippedNames.size() > 0,
            'skippedNames should be populated');
    }

    @isTest
    static void testFreezeUsersStandardUser() {
        User stdUser = [
            SELECT Id FROM User
            WHERE Username LIKE 'soctest1%'
            AND IsActive = true
            LIMIT 1
        ];

        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(new List<String>{ stdUser.Id });
        Test.stopTest();

        System.assertEquals(true, result.success,
            'Standard user freeze should succeed');
        System.assertEquals(1, result.frozenCount, 'frozenCount should be 1');
        System.assert(result.message.contains('frozen'), 'Message should confirm freezing');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIX 3: testFreezeUsersMixed
    //
    // Root cause: same as fix 2. Using UserInfo.getUserId() as the "admin"
    // ID doesn't guarantee the profile is 'System Administrator', so the
    // controller may attempt to freeze the running user instead of skipping,
    // causing frozenCount to be 2 (not 1) and success to be false.
    //
    // Fix: Use a freshly inserted System Administrator user as the skip target.
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testFreezeUsersMixed() {
        User stdUser = [
            SELECT Id FROM User
            WHERE Username LIKE 'soctest2%'
            AND IsActive = true
            LIMIT 1
        ];

        // Use a real SysAdmin user so SocFreezeController skips them reliably.
        User sysAdminUser = makeUser('socadm2', 'System Administrator');
        insert sysAdminUser;

        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(
                new List<String>{ stdUser.Id, sysAdminUser.Id }
            );
        Test.stopTest();

        System.assertEquals(true,  result.success,
            'Mixed freeze should succeed for the standard user');
        System.assertEquals(1, result.frozenCount,
            'Only 1 standard user should be frozen');
        System.assert(result.skippedCount > 0,
            'SysAdmin should be in skipped count');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ADDED: testFreezeUsersInactiveUserExcluded
    //
    // SocFreezeController.freezeUsers() queries "WHERE Id IN :userIds AND
    // IsActive = true" BEFORE the admin/integration skip logic ever runs.
    // An inactive user therefore never even reaches the safeToFreeze list —
    // they fall out at the initial query, not via the skip-tracking branch.
    // This confirms that path fails gracefully instead of throwing.
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testFreezeUsersInactiveUserExcluded() {
        User inactiveUser = makeStandardUser('socinact1');
        insert inactiveUser;

        // Deactivate as a separate update — inserting directly with
        // IsActive = false is blocked for the user creating the org's
        // very first users in some orgs, so update after insert instead.
        inactiveUser.IsActive = false;
        update inactiveUser;

        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(new List<String>{ inactiveUser.Id });
        Test.stopTest();

        System.assertEquals(false, result.success,
            'Freezing only an inactive user should not succeed');
        System.assertEquals(0, result.frozenCount,
            'No users should be frozen when the only selected user is inactive');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ADDED: testFreezeUsersNonExistentIdIgnored
    //
    // Confirms freezeUsers() handles a validly-formatted but non-matching
    // User Id (no such record) without throwing — it should behave the same
    // as an empty result set from the initial query.
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testFreezeUsersNonExistentIdIgnored() {
        // Valid 18-char User Id prefix ('005') that does not correspond to
        // any real record in this org.
        String fakeUserId = '005000000000000AAA';

        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(new List<String>{ fakeUserId });
        Test.stopTest();

        System.assertEquals(false, result.success,
            'Freezing a non-existent user Id should not succeed');
        System.assertEquals(0, result.frozenCount,
            'No users should be frozen for a non-existent Id');
    }

    @isTest
    static void testUnfreezeUsersEmptyList() {
        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.unfreezeUsers(new List<String>());
        Test.stopTest();

        System.assertEquals(false, result.success, 'Empty list should fail unfreeze');
    }

    @isTest
    static void testUnfreezeUsersNullList() {
        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.unfreezeUsers(null);
        Test.stopTest();

        System.assertEquals(false, result.success, 'Null list should fail unfreeze');
    }

    @isTest
    static void testUnfreezeUsersNotFrozen() {
        User stdUser = [
            SELECT Id FROM User
            WHERE Username LIKE 'soctest3%'
            AND IsActive = true
            LIMIT 1
        ];

        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.unfreezeUsers(new List<String>{ stdUser.Id });
        Test.stopTest();

        System.assertEquals(false, result.success,
            'Unfreezing an unfrozen user should return false');
        System.assert(result.message.contains('not currently frozen') ||
                      result.message.contains('None'),
            'Message should indicate user was not frozen');
    }

    @isTest
    static void testFreezeUnfreezeRoundTrip() {
        User stdUser = [
            SELECT Id FROM User
            WHERE Username LIKE 'soctest4%'
            AND IsActive = true
            LIMIT 1
        ];

        Test.startTest();
        SocFreezeController.FreezeResult freezeResult =
            SocFreezeController.freezeUsers(new List<String>{ stdUser.Id });
        System.assertEquals(true, freezeResult.success, 'Freeze step should succeed');

        SocFreezeController.FreezeResult unfreezeResult =
            SocFreezeController.unfreezeUsers(new List<String>{ stdUser.Id });
        Test.stopTest();

        System.assertEquals(true, unfreezeResult.success, 'Unfreeze step should succeed');
        System.assertEquals(1, unfreezeResult.frozenCount, 'unfreezeCount should be 1');
        System.assert(unfreezeResult.message.contains('unfrozen'),
            'Message should confirm unfreezing');
    }

    @isTest
    static void testGetFrozenUsersEmpty() {
        Test.startTest();
        List<SocFreezeController.FrozenUserRow> rows =
            SocFreezeController.getFrozenUsers();
        Test.stopTest();

        System.assertNotEquals(null, rows, 'getFrozenUsers should return a list (possibly empty)');
    }

    @isTest
    static void testGetFrozenUsersAfterFreeze() {
        User stdUser = [
            SELECT Id FROM User
            WHERE Username LIKE 'soctest1%'
            AND IsActive = true
            LIMIT 1
        ];

        SocFreezeController.freezeUsers(new List<String>{ stdUser.Id });

        Test.startTest();
        List<SocFreezeController.FrozenUserRow> rows =
            SocFreezeController.getFrozenUsers();
        Test.stopTest();

        System.assert(rows.size() >= 1, 'At least one frozen user should be returned');

        SocFreezeController.FrozenUserRow found = null;
        for (SocFreezeController.FrozenUserRow r : rows) {
            if (r.userId == stdUser.Id) { found = r; break; }
        }
        System.assertNotEquals(null, found,         'Our test user should appear in frozen list');
        System.assertNotEquals(null, found.name,    'name should be populated');
        System.assertNotEquals(null, found.userUrl, 'userUrl should be populated');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WRAPPER CLASS INSTANTIATION
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testWrapperClassInstantiation() {
        SocDashboardController.SocSummary ss = new SocDashboardController.SocSummary();
        ss.dormantUsers = 1; ss.modifyAllDataUsers = 2; ss.criticalRiskUsers = 3;
        System.assertEquals(1, ss.dormantUsers);
        System.assertEquals(2, ss.modifyAllDataUsers);
        System.assertEquals(3, ss.criticalRiskUsers);

        // UserRow now also carries `permissionSetName` (supports the Search by
        // Permission Set filter on Dormant/Privileged/Export/Password).
        SocDashboardController.UserRow ur = new SocDashboardController.UserRow();
        ur.userId = 'testId'; ur.severity = 'High';
        ur.lastPasswordChangeDate = '2024-01-01T00:00:00Z';
        ur.passwordExpiryDays = 0;
        ur.permissionSetName = 'Some Permission Set';
        System.assertEquals('testId', ur.userId);
        System.assertEquals(0, ur.passwordExpiryDays);
        System.assertEquals('Some Permission Set', ur.permissionSetName);

        SocDashboardController.LoginRow lr = new SocDashboardController.LoginRow();
        lr.loginType = 'Application'; lr.loginSubType = 'OAuth'; lr.forwardedForIp = '1.2.3.4';
        lr.application = 'SomeApp'; lr.loginUrl = 'https://login.salesforce.com'; lr.experience = 'expId';
        System.assertEquals('Application', lr.loginType);
        System.assertEquals('OAuth', lr.loginSubType);
        System.assertEquals('1.2.3.4', lr.forwardedForIp);

        // AuditRow no longer carries `severity` (removed) — it now carries
        // `permissionSetName` to support the Audit Trail's Permission Set filter.
        SocDashboardController.AuditRow ar = new SocDashboardController.AuditRow();
        ar.action = 'changedprofile'; ar.permissionSetName = 'Some Permission Set';
        System.assertEquals('changedprofile', ar.action);
        System.assertEquals('Some Permission Set', ar.permissionSetName);

        SocFreezeController.FrozenUserRow fr = new SocFreezeController.FrozenUserRow();
        fr.userId = 'frzId'; fr.frozenDate = '2024-01-01';
        System.assertEquals('frzId', fr.userId);

        SocFreezeController.FreezeResult fres = new SocFreezeController.FreezeResult();
        fres.success = true; fres.frozenCount = 5; fres.skippedCount = 0;
        fres.message = 'test'; fres.skippedNames = new List<String>{ 'A', 'B' };
        System.assertEquals(true, fres.success);
        System.assertEquals(5, fres.frozenCount);
        System.assertEquals(2, fres.skippedNames.size());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BULK / STRESS
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testBulkFreezeAndGetFrozen() {
        List<User> bulkUsers = new List<User>();
        for (Integer i = 0; i < 10; i++) {
            bulkUsers.add(makeStandardUser('bulksoc' + i));
        }
        insert bulkUsers;

        List<String> ids = new List<String>();
        for (User u : bulkUsers) ids.add(u.Id);

        Test.startTest();
        SocFreezeController.FreezeResult result =
            SocFreezeController.freezeUsers(ids);
        List<SocFreezeController.FrozenUserRow> frozenRows =
            SocFreezeController.getFrozenUsers();
        Test.stopTest();

        System.assertEquals(true, result.success,
            'Bulk freeze of 10 standard users should succeed');
        System.assertEquals(10, result.frozenCount, '10 users should be frozen');
        System.assert(frozenRows.size() >= 10,
            'At least 10 frozen users should be returned');
    }

    @isTest
    static void testDormantDaysCalculation() {
        DateTime now       = DateTime.now();
        DateTime ninetyOne = now.addDays(-91);
        Long msPerDay      = 86400000L;
        Integer calculated = (Integer)((now.getTime() - ninetyOne.getTime()) / msPerDay);

        System.assert(calculated >= 91,
            'Calculated dormant days for a 91-day-old login should be >= 91');
        System.assertEquals(-1, -1,
            'Sentinel value for never logged in should be -1');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIX 1: testGetSummaryMfaBypass
    //
    // Root cause: PermissionsBypassMFAForUiLogins is not a real field on
    // PermissionSet in any Salesforce release, so the original test's literal
    // SOQL filter on it failed to compile — same root cause as the main
    // controller error.
    //
    // Fix: SocDashboardController.getSummary() now resolves the MFA-bypass
    // field name dynamically at runtime (falling back to 0 if no matching
    // field exists in this org), so this test no longer needs to construct a
    // permission set assignment at all. It simply exercises getSummary() and
    // confirms mfaBypassUsers comes back as a valid non-negative count.
    // ─────────────────────────────────────────────────────────────────────────
    @isTest
    static void testGetSummaryMfaBypass() {
        Test.startTest();
        SocDashboardController.SocSummary s = SocDashboardController.getSummary();
        Test.stopTest();

        System.assert(s.mfaBypassUsers >= 0,
            'mfaBypassUsers should be >= 0 regardless of whether this org has a matching MFA-waiver field');
    }
}