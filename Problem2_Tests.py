"""
Test Suite for justInvest Password File Management
Tests password file storage, retrieval, and authentication
"""

import unittest
import os
from pathlib import Path
import time


class TestPasswordFile(unittest.TestCase):
    """Test cases for password file management system"""

    def setUp(self):
        """Set up test fixtures before each test"""
        from Problem1_4 import UserRepository, PasswordHashers, User, Role

        # Use a test-specific password file
        self.test_file = "test_passwd.txt"
        self.repository = UserRepository(self.test_file)
        self.hasher = PasswordHashers()
        self.User = User
        self.Role = Role

        # Create test users
        self.test_password = "TestPass1!"
        self.test_user_data = [
            ("alice", "Alice123!", Role.CLIENT),
            ("bob", "Bob456!", Role.PREMIUM_CLIENT),
            ("charlie", "Charlie78!", Role.FINANCIAL_ADVISOR),
        ]

    def tearDown(self):
        """Clean up after each test"""
        # Remove test password file
        if Path(self.test_file).exists():
            os.remove(self.test_file)

    # ========================================================================
    # Category 1: User Storage (3 tests)
    # ========================================================================

    def test_save_user_creates_record(self):
        """Test that saving a user creates a record in the password file"""
        # Create and save a user
        password_hash = self.hasher.hash_password(self.test_password)
        user = self.User("testuser", password_hash, self.Role.CLIENT)

        success, msg = self.repository.save_user(user)

        self.assertTrue(success, "User should be saved successfully")
        self.assertIn("saved successfully", msg.lower())

        # Verify file exists and has content
        self.assertTrue(Path(self.test_file).exists(), "Password file should exist")

        with open(self.test_file, 'r') as f:
            content = f.read()
            self.assertIn("testuser", content, "Username should be in file")

    def test_save_multiple_users(self):
        """Test that multiple users can be saved to the password file"""
        users_created = []

        # Save multiple users
        for username, password, role in self.test_user_data:
            password_hash = self.hasher.hash_password(password)
            user = self.User(username, password_hash, role)
            success, msg = self.repository.save_user(user)

            self.assertTrue(success, f"User {username} should be saved")
            users_created.append(username)

        # Verify all users are in the file
        with open(self.test_file, 'r') as f:
            content = f.read()
            for username in users_created:
                self.assertIn(username, content, f"{username} should be in file")

    def test_password_file_format(self):
        """Test that password file follows correct format (username:hash:role:metadata)"""
        # Create and save a user
        password_hash = self.hasher.hash_password(self.test_password)
        user = self.User("formattest", password_hash, self.Role.CLIENT)
        self.repository.save_user(user)

        # Read the file and check format
        with open(self.test_file, 'r') as f:
            lines = [line for line in f if not line.startswith('#') and line.strip()]

        self.assertGreater(len(lines), 0, "Should have at least one user record")

        # Check format: username:hash:role:metadata
        user_line = lines[0].strip()
        parts = user_line.split(':')

        self.assertEqual(len(parts), 4, "Record should have 4 fields separated by colons")
        self.assertEqual(parts[0], "formattest", "First field should be username")
        self.assertIn("Client", parts[2], "Third field should contain role")
        self.assertIn("created=", parts[3], "Fourth field should contain metadata")

    # ========================================================================
    # Category 2: User Retrieval (4 tests)
    # ========================================================================

    def test_get_user_returns_correct_user(self):
        """Test that get_user retrieves the correct user"""
        # Save a user
        password_hash = self.hasher.hash_password(self.test_password)
        original_user = self.User("retrievetest", password_hash, self.Role.PREMIUM_CLIENT)
        self.repository.save_user(original_user)

        # Retrieve the user
        retrieved_user = self.repository.get_user("retrievetest")

        self.assertIsNotNone(retrieved_user, "User should be retrieved")
        self.assertEqual(retrieved_user.username, "retrievetest", "Username should match")
        self.assertEqual(retrieved_user.role, self.Role.PREMIUM_CLIENT, "Role should match")
        self.assertEqual(retrieved_user.password_hash, password_hash, "Password hash should match")

    def test_get_user_returns_none_for_nonexistent_user(self):
        """Test that get_user returns None for non-existent user"""
        retrieved_user = self.repository.get_user("nonexistent")

        self.assertIsNone(retrieved_user, "Should return None for non-existent user")

    def test_get_all_users_returns_all_records(self):
        """Test that get_all_users retrieves all users from file"""
        # Save multiple users
        expected_usernames = []
        for username, password, role in self.test_user_data:
            password_hash = self.hasher.hash_password(password)
            user = self.User(username, password_hash, role)
            self.repository.save_user(user)
            expected_usernames.append(username)

        # Retrieve all users
        all_users = self.repository.get_all_users()

        self.assertEqual(len(all_users), len(expected_usernames),
                         "Should retrieve all saved users")

        retrieved_usernames = [user.username for user in all_users]
        for expected_username in expected_usernames:
            self.assertIn(expected_username, retrieved_usernames,
                          f"{expected_username} should be in retrieved users")

    def test_user_exists_check(self):
        """Test user_exists method accurately checks user presence"""
        # Save a user
        password_hash = self.hasher.hash_password(self.test_password)
        user = self.User("existstest", password_hash, self.Role.CLIENT)
        self.repository.save_user(user)

        # Test existence
        self.assertTrue(self.repository.user_exists("existstest"),
                        "Should return True for existing user")
        self.assertFalse(self.repository.user_exists("doesnotexist"),
                         "Should return False for non-existent user")

    # ========================================================================
    # Category 3: Password Verification (3 tests)
    # ========================================================================

    def test_authenticate_user_with_correct_password(self):
        """Test authentication succeeds with correct password"""
        username = "authtest"
        password = "AuthTest1!"

        # Save user with hashed password
        password_hash = self.hasher.hash_password(password)
        user = self.User(username, password_hash, self.Role.CLIENT)
        self.repository.save_user(user)

        # Authenticate with correct password
        authenticated_user = self.repository.authenticate_user(username, password)

        self.assertIsNotNone(authenticated_user, "Authentication should succeed")
        self.assertEqual(authenticated_user.username, username, "Should return correct user")

    def test_authenticate_user_with_wrong_password(self):
        """Test authentication fails with incorrect password"""
        username = "authtest2"
        correct_password = "AuthTest2!"
        wrong_password = "WrongPass1!"

        # Save user
        password_hash = self.hasher.hash_password(correct_password)
        user = self.User(username, password_hash, self.Role.CLIENT)
        self.repository.save_user(user)

        # Authenticate with wrong password
        authenticated_user = self.repository.authenticate_user(username, wrong_password)

        self.assertIsNone(authenticated_user, "Authentication should fail with wrong password")

    def test_authenticate_nonexistent_user(self):
        """Test authentication fails for non-existent user"""
        authenticated_user = self.repository.authenticate_user("nobody", "Password1!")

        self.assertIsNone(authenticated_user,
                          "Authentication should fail for non-existent user")

    # ========================================================================
    # Category 4: Password Hashing (3 tests)
    # ========================================================================

    def test_password_hash_is_not_plaintext(self):
        """Test that stored password is hashed, not plaintext"""
        password = "PlainText1!"
        password_hash = self.hasher.hash_password(password)
        user = self.User("hashtest", password_hash, self.Role.CLIENT)
        self.repository.save_user(user)

        # Read file and verify password is not in plaintext
        with open(self.test_file, 'r') as f:
            content = f.read()

        self.assertNotIn(password, content,
                         "Plaintext password should NOT be in file")
        self.assertIn("hashtest", content, "Username should be in file")

    def test_same_password_different_hashes(self):
        """Test that same password produces different hashes (due to unique salts)"""
        password = "SamePass1!"

        # Hash the same password twice
        hash1 = self.hasher.hash_password(password)
        hash2 = self.hasher.hash_password(password)

        self.assertNotEqual(hash1, hash2,
                            "Same password should produce different hashes (unique salts)")

        # But both should verify correctly
        self.assertTrue(self.hasher.verify_password(password, hash1))
        self.assertTrue(self.hasher.verify_password(password, hash2))

    def test_hash_format_contains_algorithm_info(self):
        """Test that hash string contains algorithm information"""
        password = "FormatTest1!"
        password_hash = self.hasher.hash_password(password)

        # Hash should contain algorithm identifier
        self.assertTrue(
            password_hash.startswith('$argon2') or password_hash.startswith('pbkdf2_sha256'),
            "Hash should start with algorithm identifier"
        )

        # Hash should contain salt separator
        self.assertIn('$', password_hash, "Hash should contain $ separator")

    # ========================================================================
    # Category 5: File Integrity (2 tests)
    # ========================================================================

    def test_file_created_with_header(self):
        """Test that password file is created with proper header"""
        # File should be created in setUp
        self.assertTrue(Path(self.test_file).exists(), "Password file should be created")

        with open(self.test_file, 'r') as f:
            first_line = f.readline()

        self.assertTrue(first_line.startswith('#'),
                        "First line should be a comment (header)")

    def test_malformed_line_handling(self):
        """Test that repository handles malformed lines gracefully"""
        # Add a valid user first
        password_hash = self.hasher.hash_password("Valid123!")
        user = self.User("validuser", password_hash, self.Role.CLIENT)
        self.repository.save_user(user)

        # Manually add a malformed line to the file
        with open(self.test_file, 'a') as f:
            f.write("malformed_line_without_proper_format\n")
            f.write("only:two:fields\n")

        # get_all_users should still work and return valid users only
        all_users = self.repository.get_all_users()

        self.assertEqual(len(all_users), 1,
                         "Should retrieve only valid users, skipping malformed lines")
        self.assertEqual(all_users[0].username, "validuser",
                         "Should retrieve the valid user")

    # ========================================================================
    # Category 6: User Metadata (2 tests)
    # ========================================================================

    def test_user_creation_timestamp_stored(self):
        """Test that user creation timestamp is stored"""
        before_time = int(time.time())

        password_hash = self.hasher.hash_password("TimeTest1!")
        user = self.User("timetest", password_hash, self.Role.CLIENT)
        self.repository.save_user(user)

        after_time = int(time.time())

        # Retrieve and check timestamp
        retrieved_user = self.repository.get_user("timetest")

        self.assertIsNotNone(retrieved_user.created, "Created timestamp should exist")
        self.assertGreaterEqual(retrieved_user.created, before_time,
                                "Created time should be after or equal to start time")
        self.assertLessEqual(retrieved_user.created, after_time,
                             "Created time should be before or equal to end time")

    def test_user_role_preserved(self):
        """Test that user role is correctly preserved in storage"""
        roles_to_test = [
            self.Role.CLIENT,
            self.Role.PREMIUM_CLIENT,
            self.Role.FINANCIAL_ADVISOR,
            self.Role.FINANCIAL_PLANNER,
            self.Role.TELLER
        ]

        for role in roles_to_test:
            with self.subTest(role=role):
                username = f"roletest_{role.value.replace(' ', '_').lower()}"
                password_hash = self.hasher.hash_password("RoleTest1!")
                user = self.User(username, password_hash, role)
                self.repository.save_user(user)

                # Retrieve and verify role
                retrieved_user = self.repository.get_user(username)
                self.assertEqual(retrieved_user.role, role,
                                 f"Role {role.value} should be preserved")


if __name__ == '__main__':
    unittest.main()
