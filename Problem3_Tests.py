"""
Test Suite for justInvest Enrollment and Proactive Password Checker
Tests user enrollment workflow and password policy enforcement
"""

import unittest
import os
from pathlib import Path


class TestEnrollmentAndPasswordChecker(unittest.TestCase):
    """Test cases for enrollment mechanism and proactive password checker"""

    def setUp(self):
        """Set up test fixtures before each test"""
        from Problem1_4 import JustInvestSystem, Role, PasswordValidator

        # Use a test-specific password file
        self.test_file = "test_enrollment_passwd.txt"
        self.system = JustInvestSystem()
        self.system.user_repository.filepath = Path(self.test_file)
        self.system.user_repository._ensure_file_exists()

        self.validator = PasswordValidator()
        self.Role = Role

    def tearDown(self):
        """Clean up after each test"""
        # Remove test password file
        if Path(self.test_file).exists():
            os.remove(self.test_file)

    # ========================================================================
    # Category 1: Password Length Requirements (3 tests)
    # ========================================================================

    def test_password_minimum_length(self):
        """Test that passwords under 8 characters are rejected"""
        short_password = "Short1!"  # 7 characters

        is_valid, msg = self.validator.validate(short_password, "testuser")

        self.assertFalse(is_valid, "Password under 8 characters should be rejected")
        self.assertIn("8 characters", msg.lower())

    def test_password_maximum_length(self):
        """Test that passwords over 12 characters are rejected"""
        long_password = "VeryLongPass1!"  # 14 characters

        is_valid, msg = self.validator.validate(long_password, "testuser")

        self.assertFalse(is_valid, "Password over 12 characters should be rejected")
        self.assertIn("12 characters", msg.lower())

    def test_password_valid_length(self):
        """Test that passwords between 8-12 characters pass length check"""
        valid_passwords = ["Valid123!", "Pass1234!", "Test@567"]

        for password in valid_passwords:
            with self.subTest(password=password):
                # Check length requirement specifically
                requirements = self.validator.check_requirements(password, "testuser")
                self.assertTrue(requirements['length'],
                                f"{password} should pass length requirement")

    # ========================================================================
    # Category 2: Character Type Requirements (4 tests)
    # ========================================================================

    def test_password_requires_uppercase(self):
        """Test that passwords without uppercase letters are rejected"""
        no_upper = "0uppercase1!"

        is_valid, msg = self.validator.validate(no_upper, "testuser")

        self.assertFalse(is_valid, "Password without uppercase should be rejected")
        self.assertIn("uppercase", msg.lower())

    def test_password_requires_lowercase(self):
        """Test that passwords without lowercase letters are rejected"""
        no_lower = "0LOWERCASE1!"

        is_valid, msg = self.validator.validate(no_lower, "testuser")

        self.assertFalse(is_valid, "Password without lowercase should be rejected")
        self.assertIn("lowercase", msg.lower())

    def test_password_requires_digit(self):
        """Test that passwords without digits are rejected"""
        no_digit = "NoDigits!"

        is_valid, msg = self.validator.validate(no_digit, "testuser")

        self.assertFalse(is_valid, "Password without digit should be rejected")
        self.assertIn("digit", msg.lower())

    def test_password_requires_special_character(self):
        """Test that passwords without special characters are rejected"""
        no_special = "NoSpecial123"

        is_valid, msg = self.validator.validate(no_special, "testuser")

        self.assertFalse(is_valid, "Password without special character should be rejected")
        self.assertIn("special", msg.lower())

    # ========================================================================
    # Category 3: Weak Password Detection (3 tests)
    # ========================================================================

    def test_common_weak_password_rejected(self):
        """Test that common weak passwords are rejected"""
        weak_passwords = ["password123", "12345678", "qwerty123"]

        for weak_pwd in weak_passwords:
            with self.subTest(password=weak_pwd):
                is_valid, msg = self.validator.validate(weak_pwd, "testuser")
                self.assertFalse(is_valid, f"{weak_pwd} should be rejected as weak")


    def test_weak_password_case_insensitive(self):
        """Test that weak password check is case-insensitive"""
        # "password123" is in weak list, test uppercase variant
        is_valid, msg = self.validator.validate("PASSWORD123", "testuser")

        self.assertFalse(is_valid, "Uppercase variant of weak password should be rejected")

    def test_strong_password_accepted(self):
        """Test that strong passwords are not flagged as weak"""
        strong_password = "MyStr0ng!"

        requirements = self.validator.check_requirements(strong_password, "testuser")

        self.assertTrue(requirements['not_weak'],
                        "Strong password should not be flagged as weak")

    # ========================================================================
    # Category 4: Username Matching (2 tests)
    # ========================================================================

    def test_password_cannot_match_username(self):
        """Test that password matching username is rejected"""
        username = "johnDoe"
        password = "johnDoe1!"  # Matches username with added chars

        is_valid, msg = self.validator.validate(password, username)
        self.assertFalse(is_valid, "Password matching username should be rejected")
        self.assertIn("username", msg.lower())

    def test_username_match_case_insensitive(self):
        """Test that username match check is case-insensitive"""
        username = "JohnDoe"
        password = "johndoe1!"  # Different case but same

        is_valid, msg = self.validator.validate(password, username)

        self.assertFalse(is_valid, "Case-insensitive username match should be rejected")

    # ========================================================================
    # Category 5: Valid Password Acceptance (2 tests)
    # ========================================================================

    def test_valid_password_accepted(self):
        """Test that valid passwords meeting all requirements are accepted"""
        valid_passwords = [
            "Valid123!",
            "MyPass456@",
            "Str0ng#Test",
            "Good&Pass1"
        ]

        for password in valid_passwords:
            with self.subTest(password=password):
                is_valid, msg = self.validator.validate(password, "testuser")
                self.assertTrue(is_valid, f"{password} should be accepted")
                self.assertEqual(msg, "Password is valid")

    def test_all_requirements_met(self):
        """Test that a valid password meets all individual requirements"""
        password = "Test123!"
        username = "differentuser"

        requirements = self.validator.check_requirements(password, username)

        # All requirements should be True
        for req_name, req_met in requirements.items():
            with self.subTest(requirement=req_name):
                self.assertTrue(req_met, f"Requirement '{req_name}' should be met")

    # ========================================================================
    # Category 6: Enrollment Success Cases (3 tests)
    # ========================================================================

    def test_enroll_user_with_valid_credentials(self):
        """Test successful user enrollment with valid credentials"""
        username = "newuser"
        password = "Valid123!"
        role = self.Role.CLIENT

        success, msg = self.system.enroll_user(username, password, password, role)

        self.assertTrue(success, "Valid enrollment should succeed")
        self.assertIn("enrolled successfully", msg.lower())

        # Verify user was created
        user = self.system.user_repository.get_user(username)
        self.assertIsNotNone(user, "User should exist in repository")
        self.assertEqual(user.role, role, "Role should match")

    def test_enroll_users_with_different_roles(self):
        """Test enrolling users with different roles"""
        test_cases = [
            ("client1", "Client234!", self.Role.CLIENT),
            ("premium1", "Premium2!", self.Role.PREMIUM_CLIENT),
            ("advisor1", "Advisor2!", self.Role.FINANCIAL_ADVISOR),
            ("planner1", "Planner2!", self.Role.FINANCIAL_PLANNER),
            ("teller1", "Teller234!", self.Role.TELLER),
        ]

        for username, password, role in test_cases:
            with self.subTest(role=role):
                success, msg = self.system.enroll_user(username, password, password, role)
                self.assertTrue(success, f"Should enroll {role.value}")

                # Verify role was set correctly
                user = self.system.user_repository.get_user(username)
                self.assertEqual(user.role, role, f"Role should be {role.value}")

    def test_enrolled_user_can_login(self):
        """Test that enrolled user can successfully log in"""
        username = "logintest"
        password = "Login123!"

        # Enroll user
        success, msg = self.system.enroll_user(username, password, password, self.Role.CLIENT)
        self.assertTrue(success, "Enrollment should succeed")

        # Attempt login
        login_success, login_msg = self.system.login(username, password)
        self.assertTrue(login_success, "Enrolled user should be able to login")
        self.assertIn("welcome", login_msg.lower())

    # ========================================================================
    # Category 7: Enrollment Failure Cases (5 tests)
    # ========================================================================

    def test_enroll_duplicate_username(self):
        """Test that duplicate usernames are rejected"""
        username = "duplicates"

        # Enroll first time
        success1, msg1 = self.system.enroll_user(username, "PassUs3d!", "PassUs3d!", self.Role.CLIENT)
        self.assertTrue(success1, "First enrollment should succeed")

        # Try to enroll again with same username
        success2, msg2 = self.system.enroll_user(username, "Different2!", "Different2!", self.Role.PREMIUM_CLIENT)
        self.assertFalse(success2, "Duplicate username should be rejected")
        self.assertIn("already exists", msg2.lower())

    def test_enroll_password_mismatch(self):
        """Test that mismatched password confirmation is rejected"""
        username = "mismatch"
        password = "Password1!"
        confirm = "Different2!"

        success, msg = self.system.enroll_user(username, password, confirm, self.Role.CLIENT)

        self.assertFalse(success, "Mismatched passwords should be rejected")
        self.assertIn("do not match", msg.lower())

    def test_enroll_invalid_username_format(self):
        """Test that invalid username formats are rejected"""
        invalid_usernames = ["user:name", "test:user", ":invalid"]

        for username in invalid_usernames:
            with self.subTest(username=username):
                success, msg = self.system.enroll_user(username, "Valid123!", "Valid123!", self.Role.CLIENT)
                self.assertFalse(success, f"Username '{username}' should be rejected")
                self.assertIn("invalid", msg.lower())

    def test_enroll_with_weak_password(self):
        """Test that enrollment with weak password is rejected"""
        username = "weaktest"
        weak_password = "password123"  # Common weak password

        success, msg = self.system.enroll_user(username, weak_password, weak_password, self.Role.CLIENT)

        self.assertFalse(success, "Weak password should prevent enrollment")
        self.assertIn("validation failed", msg.lower())

    def test_enroll_with_invalid_password_policy(self):
        """Test that passwords violating policy prevent enrollment"""
        invalid_cases = [
            ("short1!", "too short"),
            ("VeryLongPass1!", "too long"),
            ("nouppercase1!", "no uppercase"),
            ("NOLOWERCASE1!", "no lowercase"),
            ("NoDigits!", "no digit"),
            ("NoSpecial123", "no special char"),
        ]

        for password, reason in invalid_cases:
            with self.subTest(reason=reason):
                success, msg = self.system.enroll_user(f"user_{reason.replace(' ', '_')}",
                                                       password, password, self.Role.CLIENT)
                self.assertFalse(success, f"Should reject password: {reason}")

    # ========================================================================
    # Category 8: Password Requirements Check (2 tests)
    # ========================================================================

    def test_check_requirements_returns_all_fields(self):
        """Test that check_requirements returns all expected fields"""
        requirements = self.validator.check_requirements("Test123!", "user")

        expected_fields = ['length', 'uppercase', 'lowercase', 'digit',
                           'special', 'not_weak', 'not_username']

        for field in expected_fields:
            with self.subTest(field=field):
                self.assertIn(field, requirements, f"Should include '{field}' requirement")

    def test_check_requirements_accurate_for_partial_password(self):
        """Test that check_requirements accurately reports partial compliance"""
        # Password missing digit and special char
        password = "DigitSpecial"
        requirements = self.validator.check_requirements(password, "user")

        # Should pass these
        self.assertTrue(requirements['length'], "Should pass length")
        self.assertTrue(requirements['uppercase'], "Should pass uppercase")
        self.assertTrue(requirements['lowercase'], "Should pass lowercase")

        # Should fail these
        self.assertFalse(requirements['digit'], "Should fail digit requirement")
        self.assertFalse(requirements['special'], "Should fail special char requirement")

    # ========================================================================
    # Category 9: Integration Tests (2 tests)
    # ========================================================================

    def test_enrollment_creates_valid_user_object(self):
        """Test that enrollment creates properly initialized User object"""
        username = "integration"
        password = "Integrate1!"
        role = self.Role.FINANCIAL_ADVISOR

        success, msg = self.system.enroll_user(username, password, password, role)
        self.assertTrue(success)

        # Get the created user
        user = self.system.user_repository.get_user(username)

        # Verify User object properties
        self.assertEqual(user.username, username, "Username should match")
        self.assertEqual(user.role, role, "Role should match")
        self.assertIsNotNone(user.password_hash, "Password hash should exist")
        self.assertNotEqual(user.password_hash, password, "Password should be hashed, not plaintext")
        self.assertGreater(user.created, 0, "Created timestamp should be set")
        self.assertIsNotNone(user.permissions, "Permissions should be initialized")


if __name__ == '__main__':
    unittest.main()
