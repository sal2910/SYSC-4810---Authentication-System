"""
Test Suite for justInvest Login Mechanism and Access Control
Tests login authentication, session management, and policy enforcement
"""

import unittest
import os
from pathlib import Path
from datetime import datetime


class TestLoginMechanismAndAccessControl(unittest.TestCase):
    """Test cases for login mechanism and access control policy enforcement"""

    def setUp(self):
        """Set up test fixtures before each test"""
        from Problem1_4 import JustInvestSystem, Role, Permission

        # Use a test-specific password file
        self.test_file = "test_login_passwd.txt"
        self.system = JustInvestSystem()
        self.system.user_repository.filepath = Path(self.test_file)
        self.system.user_repository._ensure_file_exists()

        self.Role = Role
        self.Permission = Permission

        # Create test users for all roles
        self.test_users = {
            'client': {
                'username': 'testClient',
                'password': 'Client123!',
                'role': Role.CLIENT,
                'expected_permissions': 3
            },
            'premium': {
                'username': 'testPremium',
                'password': 'Premium1!',
                'role': Role.PREMIUM_CLIENT,
                'expected_permissions': 5
            },
            'advisor': {
                'username': 'testAdvisor',
                'password': 'Advisor1!',
                'role': Role.FINANCIAL_ADVISOR,
                'expected_permissions': 4
            },
            'planner': {
                'username': 'testPlanner',
                'password': 'Planner1!',
                'role': Role.FINANCIAL_PLANNER,
                'expected_permissions': 5
            },
            'teller': {
                'username': 'testTeller',
                'password': 'Teller123!',
                'role': Role.TELLER,
                'expected_permissions': 2
            }
        }

        # Enroll all test users
        for user_data in self.test_users.values():
            self.system.enroll_user(
                user_data['username'],
                user_data['password'],
                user_data['password'],
                user_data['role']
            )

    def tearDown(self):
        """Clean up after each test"""
        # Logout if logged in
        if self.system.is_logged_in():
            self.system.logout()

        # Remove test password file
        if Path(self.test_file).exists():
            os.remove(self.test_file)

    # ========================================================================
    # Category 1: Successful Login (3 tests)
    # ========================================================================

    def test_login_with_valid_credentials(self):
        """Test successful login with correct username and password"""
        user_data = self.test_users['client']

        success, msg = self.system.login(user_data['username'], user_data['password'])

        self.assertTrue(success, "Login with valid credentials should succeed")
        self.assertIn("welcome", msg.lower())
        self.assertTrue(self.system.is_logged_in(), "User should be logged in")

    def test_login_establishes_session(self):
        """Test that login establishes a valid session"""
        user_data = self.test_users['premium']

        self.system.login(user_data['username'], user_data['password'])

        # Verify session is established
        current_user = self.system.get_current_user()
        self.assertIsNotNone(current_user, "Current user should be set")
        self.assertEqual(current_user.username, user_data['username'],
                         "Session should be for correct user")

        # Verify session info is available
        session_info = self.system.get_current_user_info()
        self.assertIsNotNone(session_info, "Session info should be available")
        self.assertIn('login_time', session_info, "Login time should be recorded")

    def test_login_loads_correct_role_and_permissions(self):
        """Test that login correctly loads user role and permissions"""
        user_data = self.test_users['advisor']

        self.system.login(user_data['username'], user_data['password'])

        current_user = self.system.get_current_user()

        # Verify role
        self.assertEqual(current_user.role, user_data['role'],
                         "User role should be loaded correctly")

        # Verify permissions count
        permissions = self.system.get_user_permissions()
        self.assertEqual(len(permissions), user_data['expected_permissions'],
                         f"{user_data['role'].value} should have {user_data['expected_permissions']} permissions")

    # ========================================================================
    # Category 2: Failed Login (4 tests)
    # ========================================================================

    def test_login_with_wrong_password(self):
        """Test that login fails with incorrect password"""
        user_data = self.test_users['client']
        wrong_password = "WrongPass1!"

        success, msg = self.system.login(user_data['username'], wrong_password)

        self.assertFalse(success, "Login with wrong password should fail")
        self.assertIn("invalid credentials", msg.lower())
        self.assertFalse(self.system.is_logged_in(), "User should not be logged in")

    def test_login_with_nonexistent_user(self):
        """Test that login fails for non-existent user"""
        success, msg = self.system.login("nonexistent", "Password1!")

        self.assertFalse(success, "Login with non-existent user should fail")
        self.assertIn("invalid credentials", msg.lower())
        self.assertFalse(self.system.is_logged_in(), "No user should be logged in")

    def test_login_case_sensitive_username(self):
        """Test that username is case-sensitive"""
        user_data = self.test_users['client']
        wrong_case_username = user_data['username'].upper()

        success, msg = self.system.login(wrong_case_username, user_data['password'])

        self.assertFalse(success, "Login should fail with wrong username case")

    def test_login_case_sensitive_password(self):
        """Test that password is case-sensitive"""
        user_data = self.test_users['client']
        wrong_case_password = user_data['password'].lower()

        success, msg = self.system.login(user_data['username'], wrong_case_password)

        self.assertFalse(success, "Login should fail with wrong password case")

    # ========================================================================
    # Category 3: Session Management (3 tests)
    # ========================================================================

    def test_logout_clears_session(self):
        """Test that logout properly clears the session"""
        user_data = self.test_users['client']

        # Login
        self.system.login(user_data['username'], user_data['password'])
        self.assertTrue(self.system.is_logged_in(), "User should be logged in")

        # Logout
        self.system.logout()

        # Verify session is cleared
        self.assertFalse(self.system.is_logged_in(), "User should be logged out")
        self.assertIsNone(self.system.get_current_user(), "Current user should be None")
        self.assertIsNone(self.system.get_current_user_info(), "Session info should be None")

    def test_operations_fail_without_login(self):
        """Test that operations cannot be executed without login"""
        # Ensure no one is logged in
        self.assertFalse(self.system.is_logged_in())

        # Try to execute operation
        success, msg = self.system.execute_operation(self.Permission.VIEW_ACCOUNT_BALANCE)

        self.assertFalse(success, "Operation should fail without login")
        self.assertIn("not logged in", msg.lower())

    def test_multiple_logins_replace_session(self):
        """Test that logging in as different user replaces previous session"""
        user1 = self.test_users['client']
        user2 = self.test_users['premium']

        # Login as first user
        self.system.login(user1['username'], user1['password'])
        self.assertEqual(self.system.get_current_user().username, user1['username'])

        # Logout and login as second user
        self.system.logout()
        self.system.login(user2['username'], user2['password'])

        # Verify session is for second user
        current_user = self.system.get_current_user()
        self.assertEqual(current_user.username, user2['username'],
                         "Session should be for second user")
        self.assertEqual(current_user.role, user2['role'],
                         "Role should be for second user")


if __name__ == '__main__':
    unittest.main()
