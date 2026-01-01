"""
Test Suite for justInvest Access Control Mechanism
Tests RBAC policy enforcement with adequate coverage
"""

import unittest


class TestAccessControl(unittest.TestCase):
    """Test cases for RBAC access control mechanism"""

    def setUp(self):
        """Set up test fixtures before each test"""
        from Problem1_4 import JustInvestSystem, Role, Permission, UserRepository

        self.system = JustInvestSystem()
        self.Permission = Permission
        self.Role = Role

        # Create test users for each role
        self.test_users = {
            'client': ('testClient', 'TestPass1!', Role.CLIENT),
            'premium': ('testPremium', 'TestPass2!', Role.PREMIUM_CLIENT),
            'advisor': ('testAdvisor', 'TestPass3!', Role.FINANCIAL_ADVISOR),
            'planner': ('testPlanner', 'TestPass4!', Role.FINANCIAL_PLANNER),
            'teller': ('testTeller', 'TestPass5!', Role.TELLER),
        }

        # Enroll all test users
        for username, password, role in self.test_users.values():
            self.system.enroll_user(username, password, password, role)

    def tearDown(self):
        """Clean up after each test"""
        if self.system.is_logged_in():
            self.system.logout()

    # ========================================================================
    # Category 1: Client Permissions (3 tests)
    # ========================================================================

    def test_client_can_view_account_balance(self):
        """Test that Client can view account balance"""
        username, password, role = self.test_users['client']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_ACCOUNT_BALANCE
        )

        self.assertTrue(success, "Client should be able to view account balance")
        self.assertIn("executed successfully", msg.lower())

    def test_client_can_view_portfolio(self):
        """Test that Client can view investment portfolio"""
        username, password, role = self.test_users['client']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_INVESTMENT_PORTFOLIO
        )

        self.assertTrue(success, "Client should be able to view portfolio")

    def test_client_cannot_modify_portfolio(self):
        """Test that Client CANNOT modify investment portfolio"""
        username, password, role = self.test_users['client']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.MODIFY_INVESTMENT_PORTFOLIO
        )

        self.assertFalse(success, "Client should NOT be able to modify portfolio")
        self.assertIn("denied", msg.lower())

    def test_client_can_view_fa_contact(self):
        """Test Client can view Financial Advisor contact (policy requirement)"""
        username, password, role = self.test_users['client']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_FINANCIAL_ADVISOR_CONTACT
        )

        self.assertTrue(success, "Client should be able to view FA contact")

    # ========================================================================
    # Category 2: Premium Client Permissions (2 tests)
    # ========================================================================

    def test_premium_client_can_modify_portfolio(self):
        """Test that Premium Client CAN modify portfolio (unlike regular Client)"""
        username, password, role = self.test_users['premium']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.MODIFY_INVESTMENT_PORTFOLIO
        )

        self.assertTrue(success, "Premium Client should be able to modify portfolio")

    def test_premium_client_can_view_fp_contact(self):
        """Test that Premium Client can view Financial Planner contact"""
        username, password, role = self.test_users['premium']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_FINANCIAL_PLANNER_CONTACT
        )

        self.assertTrue(success, "Premium Client should view FP contact")

    # ========================================================================
    # Category 3: Employee Role Permissions (3 tests)
    # ========================================================================

    def test_advisor_can_view_private_instruments(self):
        """Test that Financial Advisor can view private consumer instruments"""
        username, password, role = self.test_users['advisor']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_PRIVATE_CONSUMER_INSTRUMENTS
        )

        self.assertTrue(success, "FA should view private instruments")

    def test_advisor_cannot_view_money_market(self):
        """Test that Financial Advisor CANNOT view money market instruments"""
        username, password, role = self.test_users['advisor']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_MONEY_MARKET_INSTRUMENTS
        )

        self.assertFalse(success, "FA should NOT view money market instruments")

    def test_planner_can_view_money_market(self):
        """Test that Financial Planner CAN view money market instruments"""
        username, password, role = self.test_users['planner']
        self.system.login(username, password)

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_MONEY_MARKET_INSTRUMENTS
        )

        self.assertTrue(success, "FP should view money market instruments")

    # ========================================================================
    # Category 4: Teller Permissions (2 tests)
    # ========================================================================

    def test_teller_can_view_balance(self):
        """Test that Teller can view account balance (during business hours)"""
        username, password, role = self.test_users['teller']
        success, login_msg = self.system.login(username, password)

        # Only test if within business hours
        if success:
            result, msg = self.system.execute_operation(
                self.Permission.VIEW_ACCOUNT_BALANCE
            )
            self.assertTrue(result, "Teller should view balance during business hours")
        else:
            # Outside business hours - verify rejection
            self.assertIn("business hours", login_msg.lower())

    def test_teller_cannot_modify_portfolio(self):
        """Test that Teller CANNOT modify portfolio"""
        username, password, role = self.test_users['teller']
        success, login_msg = self.system.login(username, password)

        if success:  # Only test if login succeeded (during business hours)
            result, msg = self.system.execute_operation(
                self.Permission.MODIFY_INVESTMENT_PORTFOLIO
            )
            self.assertFalse(result, "Teller should NOT modify portfolio")

    # ========================================================================
    # Category 5: Permission Count Validation (5 tests)
    # ========================================================================

    def test_client_has_exactly_3_permissions(self):
        """Verify Client role has exactly 3 permissions"""
        username, password, role = self.test_users['client']
        self.system.login(username, password)

        permissions = self.system.get_user_permissions()
        self.assertEqual(len(permissions), 3, "Client should have exactly 3 permissions")

    def test_premium_client_has_exactly_5_permissions(self):
        """Verify Premium Client role has exactly 5 permissions"""
        username, password, role = self.test_users['premium']
        self.system.login(username, password)

        permissions = self.system.get_user_permissions()
        self.assertEqual(len(permissions), 5, "Premium Client should have exactly 5 permissions")

    def test_advisor_has_exactly_4_permissions(self):
        """Verify Financial Advisor role has exactly 4 permissions"""
        username, password, role = self.test_users['advisor']
        self.system.login(username, password)

        permissions = self.system.get_user_permissions()
        self.assertEqual(len(permissions), 4, "FA should have exactly 4 permissions")

    def test_planner_has_exactly_5_permissions(self):
        """Verify Financial Planner role has exactly 5 permissions"""
        username, password, role = self.test_users['planner']
        self.system.login(username, password)

        permissions = self.system.get_user_permissions()
        self.assertEqual(len(permissions), 5, "FP should have exactly 5 permissions")

    def test_teller_has_exactly_2_permissions(self):
        """Verify Teller role has exactly 2 permissions"""
        username, password, role = self.test_users['teller']
        success, _ = self.system.login(username, password)

        if success:  # Only test during business hours
            permissions = self.system.get_user_permissions()
            self.assertEqual(len(permissions), 2, "Teller should have exactly 2 permissions")

    # ========================================================================
    # Category 6: Cross-Role Verification (2 tests)
    # ========================================================================

    def test_all_employees_can_view_client_data(self):
        """Verify all employee roles can view client account data"""
        employee_roles = ['advisor', 'planner', 'teller']

        for role_key in employee_roles:
            with self.subTest(role=role_key):
                username, password, role = self.test_users[role_key]
                login_success, _ = self.system.login(username, password)

                if login_success:  # Account for Teller time restrictions
                    success, msg = self.system.execute_operation(
                        self.Permission.VIEW_ACCOUNT_BALANCE
                    )
                    self.assertTrue(success, f"{role.value} should view client data")
                    self.system.logout()

    def test_only_advisors_and_planners_modify_portfolio(self):
        """Verify only FA and FP can modify portfolios"""
        can_modify = ['advisor', 'planner']
        cannot_modify = ['client', 'teller']

        # Test roles that SHOULD have permission
        for role_key in can_modify:
            with self.subTest(role=role_key, expect="granted"):
                username, password, role = self.test_users[role_key]
                self.system.login(username, password)

                success, msg = self.system.execute_operation(
                    self.Permission.MODIFY_INVESTMENT_PORTFOLIO
                )
                self.assertTrue(success, f"{role.value} should modify portfolio")
                self.system.logout()

        # Test roles that SHOULD NOT have permission
        for role_key in cannot_modify:
            with self.subTest(role=role_key, expect="denied"):
                username, password, role = self.test_users[role_key]
                login_success, _ = self.system.login(username, password)

                if login_success:  # Account for Teller time restrictions
                    success, msg = self.system.execute_operation(
                        self.Permission.MODIFY_INVESTMENT_PORTFOLIO
                    )
                    self.assertFalse(success, f"{role.value} should NOT modify portfolio")
                    self.system.logout()

    # ========================================================================
    # Category 7: Authorization Without Authentication (1 test)
    # ========================================================================

    def test_no_operation_without_login(self):
        """Verify that operations fail when not logged in"""
        # Ensure no user is logged in
        if self.system.is_logged_in():
            self.system.logout()

        success, msg = self.system.execute_operation(
            self.Permission.VIEW_ACCOUNT_BALANCE
        )

        self.assertFalse(success, "Should not execute operation without login")
        self.assertIn("not logged in", msg.lower())


if __name__ == '__main__':
    unittest.main()
