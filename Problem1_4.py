"""
justInvest Complete Integrated Authentication and Access Control System
Integrates all components: RBAC, Password Management, Enrollment, and Login

This system implements:
- Problem 1: Role-Based Access Control (RBAC)
- Problem 2: Secure Password File Management
- Problem 3: User Enrollment with Proactive Password Checking
- Problem 4: User Login and Access Control Display
"""

import getpass
import secrets
import base64
from datetime import datetime, time as dt_time
import time
from enum import Enum
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
import hashlib

# try to import argon2, fallback to PBKDF2 if unavailable
try:
    from argon2 import PasswordHasher, Type
    from argon2.exceptions import VerifyMismatchError, InvalidHash

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


    class VerifyMismatchError(Exception):
        pass


    class InvalidHash(Exception):
        pass


    print("WARNING: argon2-cffi not available, using PBKDF2-SHA256 fallback")


# ============================================================================
# ENUMERATIONS & CONSTANTS
# ============================================================================
class Permission(Enum):
    """System Permissions (from Problem 1 - RBAC)"""
    VIEW_ACCOUNT_BALANCE = "view_account_balance"
    VIEW_INVESTMENT_PORTFOLIO = "view_investment_portfolio"
    MODIFY_INVESTMENT_PORTFOLIO = "modify_investment_portfolio"
    VIEW_FINANCIAL_ADVISOR_CONTACT = "view_financial_advisor_contact"
    VIEW_FINANCIAL_PLANNER_CONTACT = "view_financial_planner_contact"
    VIEW_MONEY_MARKET_INSTRUMENTS = "view_money_market_instruments"
    VIEW_PRIVATE_CONSUMER_INSTRUMENTS = "view_private_consumer_instruments"


class Role(Enum):
    """User roles in the system"""
    CLIENT = "Client"
    PREMIUM_CLIENT = "Premium Client"
    FINANCIAL_ADVISOR = "Financial Advisor"
    FINANCIAL_PLANNER = "Financial Planner"
    TELLER = "Teller"


# ============================================================================
# ROLE-PERMISSION MATRIX (RBAC POLICY)
# ============================================================================
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.CLIENT: {
        Permission.VIEW_ACCOUNT_BALANCE,
        Permission.VIEW_INVESTMENT_PORTFOLIO,
        Permission.VIEW_FINANCIAL_ADVISOR_CONTACT
    },
    Role.PREMIUM_CLIENT: {
        Permission.VIEW_ACCOUNT_BALANCE,
        Permission.VIEW_INVESTMENT_PORTFOLIO,
        Permission.MODIFY_INVESTMENT_PORTFOLIO,
        Permission.VIEW_FINANCIAL_ADVISOR_CONTACT,
        Permission.VIEW_FINANCIAL_PLANNER_CONTACT
    },
    Role.FINANCIAL_ADVISOR: {
        Permission.VIEW_ACCOUNT_BALANCE,
        Permission.VIEW_INVESTMENT_PORTFOLIO,
        Permission.MODIFY_INVESTMENT_PORTFOLIO,
        Permission.VIEW_PRIVATE_CONSUMER_INSTRUMENTS
    },
    Role.FINANCIAL_PLANNER: {
        Permission.VIEW_ACCOUNT_BALANCE,
        Permission.VIEW_INVESTMENT_PORTFOLIO,
        Permission.MODIFY_INVESTMENT_PORTFOLIO,
        Permission.VIEW_MONEY_MARKET_INSTRUMENTS,
        Permission.VIEW_PRIVATE_CONSUMER_INSTRUMENTS
    },
    Role.TELLER: {
        Permission.VIEW_ACCOUNT_BALANCE,
        Permission.VIEW_INVESTMENT_PORTFOLIO
    }
}

# Password configuration
COMMON_WEAK_PASSWORDS = {
    "password", "password123", "12345678", "qwerty123", "abc123!@#",
    "welcome123", "admin123!", "letmein1!", "monkey123", "dragon123",
    "passw0rd!", "p@ssw0rd", "password1!", "123456!@#", "qwerty123!"
}

PASSWORD_FILE = "passwd.txt"


# ============================================================================
# USER CLASS - Core representation of a system user
# ============================================================================
class User:
    """
    Represents a system user with credentials, role, and permissions.
    This is the class that encapsulates all user-related information and
    behavior.
    """

    def __init__(self, username: str, password_hash: str, role: Role, created: int = None):
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.created = created or int(time.time())
        self._permissions: Optional[Set[Permission]] = None

    @property
    def permissions(self) -> Set[Permission]:
        """Get permissions for this user based on their role"""
        if self._permissions is None:
            self._permissions = ROLE_PERMISSIONS.get(self.role, set())
        return self._permissions

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission"""
        return permission in self.permissions

    def get_permission_labels(self) -> List[str]:
        """Get human-readable permission descriptions"""
        labels = {
            Permission.VIEW_ACCOUNT_BALANCE: "View Account Balance",
            Permission.VIEW_INVESTMENT_PORTFOLIO: "View Investment Portfolio",
            Permission.MODIFY_INVESTMENT_PORTFOLIO: "Modify Investment Portfolio",
            Permission.VIEW_FINANCIAL_ADVISOR_CONTACT: "View Financial Advisor Contact",
            Permission.VIEW_FINANCIAL_PLANNER_CONTACT: "View Financial Planner Contact",
            Permission.VIEW_MONEY_MARKET_INSTRUMENTS: "View Money Market Instruments",
            Permission.VIEW_PRIVATE_CONSUMER_INSTRUMENTS: "View Private Consumer Instruments",
        }
        return [labels[perm] for perm in self.permissions]

    def check_temporal_constraints(self) -> Tuple[bool, str]:
        """Check if user can access the system based on temporal constraints"""
        if self.role != Role.TELLER:
            return True, "No temporal constraints"

        current_time = datetime.now().time()
        business_start = dt_time(9, 0)
        business_end = dt_time(17, 0)

        if business_start <= current_time <= business_end:
            return True, "Within business hours"
        else:
            return False, "Teller access restricted to business hours (9 AM - 5 PM)"

    def to_password_record(self) -> str:
        """Convert to password file format"""
        metadata = f"created={self.created}"
        return f"{self.username}:{self.password_hash}:{self.role.value}:{metadata}\n"

    @classmethod
    def from_password_record(cls, line: str) -> 'User':
        """Create User from password file record"""
        parts = line.strip().split(':')
        if len(parts) != 4:
            raise ValueError(f"Invalid record format: {line}")
        username, hash_string, role_str, metadata_str = parts

        # Parse the metadata
        metadata = {}
        for item in metadata_str.split(','):
            if '=' in item:
                key, value = item.split('=', 1)
                metadata[key] = value

        created = int(metadata.get('created', int(time.time())))

        return cls(
            username=username,
            password_hash=hash_string,
            role=Role(role_str),
            created=created
        )

    def __repr__(self):
        return f"User (username = {self.username}, role = {self.role.value}, permissions = {len(self.permissions)})"

    def get_info_dict(self) -> Dict:
        """Get user info as a dictionary"""
        return {
            'username': self.username,
            'role': self.role.value,
            'permissions_count': len(self.permissions),
            'created': datetime.fromtimestamp(self.created).strftime('%Y-%m-%d %H:%M:%S')
        }


# ============================================================================
# PROACTIVE PASSWORD CHECKER (PASSWORD POLICY)
# ============================================================================
class PasswordValidator:
    """
    Proactive Password Checker
    Validates passwords against security policy in real time
    """

    @staticmethod
    def validate(password: str, username: str) -> Tuple[bool, str]:
        """
        Validates the password against all policy requirements
        :param password: password to be validated
        :param username: username of the user
        :return: (is_valid, error_message)
        """
        # Length check (8-12 characters)
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if len(password) > 12:
            return False, "Password must be at most 12 characters"

        # Character requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%*&" for c in password)

        if not has_upper:
            return False, "Password must contain at least one uppercase letter"
        if not has_lower:
            return False, "Password must contain at least one lowercase letter"
        if not has_digit:
            return False, "Password must contain at least one digit"
        if not has_special:
            return False, "Password must contain at least one special character (!@#$*&)"

        # Weak password check (case-insensitive)
        if password.lower() in COMMON_WEAK_PASSWORDS:
            return False, "Password is too common and must not be used"

        # Username match check (case-insensitive)
        if username.lower() in password.lower():
            return False, "Password cannot match username. (Username cannot be contained in the password)"

        return True, "Password is valid"

    @staticmethod
    def check_requirements(password: str, username: str = "") -> Dict[str, bool]:
        """Check individual requirements (for real-time feedback)"""
        return {
            'length': 8 <= len(password) <= 12,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'digit': any(c.isdigit() for c in password),
            'special': any(c in "!@#$%*&" for c in password),
            'not_weak': password.lower() not in COMMON_WEAK_PASSWORDS,
            'not_username': username == "" or password.lower() != username.lower()
        }


# ============================================================================
# PROBLEM 2: PASSWORD FILE MANAGEMENT
# ============================================================================
class HashConfig:
    """Password hashing configuration"""

    # Argon2id parameters
    ARGON2_TIME_COST = 3  # iterations
    ARGON2_MEMORY_COST = 65536  # KB (64 MB)
    ARGON2_PARALLELISM = 4  # threads
    ARGON2_HASH_LENGTH = 32  # bytes
    ARGON2_SALT_LENGTH = 16  # bytes

    # PBKDF2 parameters (fallback)
    PBKDF2_ITERATIONS = 600000  # OWASP recommendation for 2023+
    PBKDF2_HASH_LENGTH = 32  # bytes
    PBKDF2_SALT_LENGTH = 16  # bytes


class PasswordHashers:
    """Handles password hashing and verification using PBKDF2-SHA256"""

    def __init__(self):
        if ARGON2_AVAILABLE:
            self.hasher = PasswordHasher(
                time_cost=HashConfig.ARGON2_TIME_COST,
                memory_cost=HashConfig.ARGON2_MEMORY_COST,
                parallelism=HashConfig.ARGON2_PARALLELISM,
                hash_len=HashConfig.ARGON2_HASH_LENGTH,
                salt_len=HashConfig.ARGON2_SALT_LENGTH,
                type=Type.ID  # Argon2id
            )
            self.algorithm = "argon2id"
        else:
            self.hasher = None
            self.algorithm = "pbkdf2_sha256"

    def hash_password(self, password: str) -> str:
        """
        Hashes a password using Argon2id or PBKDF-SHA256
        :param password: password to be hashed
        :return: PHC-format hash string
        """
        if ARGON2_AVAILABLE:
            # Argon2 library returns PHC-format string automatically
            return self.hasher.hash(password)
        else:
            # PBKDF2 fallback - create PHC-format string manually
            salt = secrets.token_bytes(HashConfig.PBKDF2_SALT_LENGTH)
            iterations = HashConfig.PBKDF2_ITERATIONS

            hash_bytes = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iterations,
                dklen=HashConfig.PBKDF2_HASH_LENGTH
            )

            # Create PHC-format string
            salt_b64 = base64.b64encode(salt).decode('ascii').rstrip('=')
            hash_b64 = base64.b64encode(hash_bytes).decode('ascii').rstrip('=')

            return f"pbkdf2_sha256$i={iterations}${salt_b64}${hash_b64}"

    def verify_password(self, password: str, hash_string: str) -> bool:
        """
        Verify a password against a hash string
        :param password: password to be verified
        :param hash_string: hash to be compared against
        :return: True if password matches, False otherwise
        """
        try:
            if hash_string.startswith('$argon2'):
                # Argon 2 hash
                if not ARGON2_AVAILABLE:
                    raise RuntimeError("Argon2 hash found but library not available")
                self.hasher.verify(hash_string, password)
                return True
            elif hash_string.startswith('pbkdf2_sha256'):
                # PBKDF2 hash
                return self._verify_pbkdf2(password, hash_string)
            else:
                raise ValueError(f"Unknown hash format: {hash_string}")
        except (VerifyMismatchError, InvalidHash, ValueError):
            return False

    @staticmethod
    def _verify_pbkdf2(password: str, hash_string: str) -> bool:
        """ Verify PBKDF2 hash"""
        try:
            # Parse PHC-format string
            parts = hash_string.split('$')
            if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
                return False

            # Extract parameters
            params = dict(p.split('=') for p in parts[1].split(',') if '=' in p)
            iterations = int(params.get('i', HashConfig.PBKDF2_ITERATIONS))

            # Decode salt and hash
            salt_b64 = parts[2]
            expected_hash_b64 = parts[3]

            # Add padding if needed
            salt_b64 += '=' * (-len(salt_b64) % 4)
            expected_hash_b64 += '=' * (-len(expected_hash_b64) % 4)

            salt = base64.b64decode(salt_b64)
            expected_hash = base64.b64decode(expected_hash_b64)

            # Compute hash of provided password
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iterations,
                dklen=len(expected_hash)
            )

            # Constant-time comparison
            return secrets.compare_digest(computed_hash, expected_hash)
        except (ValueError, KeyError, Exception) as e:
            print(f"Password verification error: {e}")
            return False

    def needs_rehash(self, hash_string: str) -> bool:
        """
        Check if hash needs to be updated (parameters changed)
        Returns True if rehashing recommended
        """
        if ARGON2_AVAILABLE and hash_string.startswith('$argon2'):
            return self.hasher.check_needs_rehash(hash_string)
        return False


class UserRepository:
    """
    Manages user storage and retrieval (Password File Management)
    """

    def __init__(self, filepath: str = PASSWORD_FILE):
        self.filepath = Path(filepath)
        self.hasher = PasswordHashers()
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        """Create password file if it doesn't exist"""
        if not self.filepath.exists():
            self.filepath.touch(mode=0o600)
            with open(self.filepath, 'w') as f:
                f.write("# JustInvest Password File\n")
                f.write("# Format: username:hash_string:role:metadata\n")
                f.write("# DO NOT EDIT MANUALLY\n")

    def save_user(self, user: User) -> Tuple[bool, str]:
        """
        Save a User to the password file
        :param user: user to add to the password file
        :return: (success, message)
        """
        if self.user_exists(user.username):
            return False, "User already exists"
        try:
            # Read existing content
            with open(self.filepath, 'a') as f:
                f.write(user.to_password_record())
                return True, f"User '{user.username}' saved successfully"

        except Exception as e:
            return False, f"Failed to save user: {str(e)}"

    def get_user(self, username: str) -> Optional[User]:
        """
        Retrieve a User from the password file
        :param username: Username of user to be retrieved
        :return: User object or None if not found
        """
        try:
            with open(self.filepath, 'r') as f:
                for line in f:
                    if line.startswith('#') or not line.strip():
                        continue

                    try:
                        user = User.from_password_record(line)
                        if user.username == username:
                            return user
                    except ValueError:
                        continue
            return None
        except FileNotFoundError:
            return None

    def user_exists(self, username: str) -> bool:
        """Check if user exists"""
        return self.get_user(username) is not None

    def get_all_users(self) -> List[User]:
        """Get all users from the password file"""
        users = []
        try:
            with open(self.filepath, 'r') as f:
                for line in f:
                    if line.startswith('#') or not line.strip():
                        continue

                    try:
                        user = User.from_password_record(line)
                        users.append(user)
                    except ValueError:
                        continue
        except FileNotFoundError:
            pass

        return users

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user credential and return User Object if valid
        :param username: username of user to be authenticated
        :param password: password of user to be authenticated
        :return: User object or None
        """
        user = self.get_user(username)
        if user is None:
            return None
        if self.hasher.verify_password(password, user.password_hash):
            return user

        return None


# ============================================================================
# PROBLEM 1: ACCESS CONTROL (RBAC)
# ============================================================================
class AccessController:
    """
    RBAC Access Control Enforcement
    Works with User objects to enforce authorization
    """

    @staticmethod
    def authorize(user: User, permission: Permission) -> Tuple[bool, str]:
        """
        Authorize user for a specific permissions
        Returns (is_authorized, message)
        """
        # Check the temporal constraints first
        temporal_ok, temporal_msg = user.check_temporal_constraints()
        if not temporal_ok:
            return False, temporal_msg

        # Check permission
        if user.has_permission(permission):
            return True, "Access Granted"
        else:
            return False, f"Access Denied: {user.role.value} does not have permission"

    @staticmethod
    def get_authorized_operations(user: User) -> List[Tuple[int, str]]:
        """ Get the list of operations a user is authorized to perform"""
        # Check the temporal constraints first
        temporal_ok, _ = user.check_temporal_constraints()
        if not temporal_ok:
            return []

        operations = user.get_permission_labels()
        return [(i + 1, op) for i, op in enumerate(operations)]


# ============================================================================
# PROBLEM 3 & 4: INTEGRATED SYSTEM (Enrollment and Login)
# ============================================================================
class JustInvestSystem:
    """
    Main integrated system combining all components with User-centric architecture
    """

    def __init__(self):
        self.user_repository = UserRepository()
        self.access_controller = AccessController()
        self.password_validator = PasswordValidator()
        self.password_hasher = PasswordHashers()

        self.current_user: Optional[User] = None
        self.session_start: Optional[datetime] = None

    # ========================================================================
    # PROBLEM 3: USER ENROLLMENT
    # ========================================================================
    def enroll_user(self, username: str, password: str, confirm_password: str,
                    role: Role) -> Tuple[bool, str]:
        """
        Enroll a new user in the system. Creates a user object and persist it
        :param username: username of the user
        :param password: password to be used
        :param confirm_password: confirmation of the password to be used
        :param role: what role the user should have
        :return: (bool, message)
        """
        # Validate the username
        if not username or ':' in username:
            return False, "Invalid username format"

        # Check is user already exists
        if self.user_repository.user_exists(username):
            return False, f"User '{username}' already exists"

        # Check password confirmation
        if password != confirm_password:
            return False, "Passwords do not match"

        # Validate Password (with proactive password checker)
        is_valid, message = self.password_validator.validate(password, username)
        if not is_valid:
            return False, f"Password validation failed: {message}"

        # Hash password
        try:
            password_hash = self.password_hasher.hash_password(password)
        except Exception as e:
            return False, f"Password hashing failed: {str(e)}"

        # Create User object
        user = User(
            username=username,
            password_hash=password_hash,
            role=role
        )

        # Save to repository
        success, save_message = self.user_repository.save_user(user)

        if success:
            return True, f"User '{username}' enrolled successfully as {role.value}"
        else:
            return False, save_message

    def check_password_requirements(self, password: str, username: str = "") -> Dict[str, bool]:
        """
        Check password against all requirements (for real-time feedback)
        :param password: password to be checked
        :param username: username associated with the password
        :return: dictionary of requirement -> met status
        """
        return self.password_validator.check_requirements(password, username)

    # ========================================================================
    # PROBLEM 4: USER LOGIN
    # ========================================================================
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticates a user and establishes a session
        :param username: username of user to be logged in
        :param password: password inputted
        :return: (success, message)
        """
        # Authenticate and get User object
        user = self.user_repository.authenticate_user(username, password)

        if user is None:
            return False, "Invalid credentials"

        # Check temporal constraints
        temporal_ok, temporal_msg = user.check_temporal_constraints()
        if not temporal_ok:
            return False, temporal_msg

        # Establish session with User object
        self.current_user = user
        self.session_start = datetime.now()

        return True, f"Welcome {username}!"

    def logout(self):
        """End user session"""
        self.current_user = None
        self.session_start = None

    def is_logged_in(self) -> bool:
        """Check if user is currently logged in"""
        return self.current_user is not None

    def get_current_user(self) -> Optional[User]:
        """Get the currently logged-in User object"""
        return self.current_user

    # ========================================================================
    # ACCESS CONTROL AND AUTHORIZATION
    # ========================================================================
    def get_current_user_info(self) -> Optional[Dict[str, str]]:
        """Get information about the currently logged-in user"""
        if not self.current_user:
            return None

        info = self.current_user.get_info_dict()
        info['login_time'] = self.session_start.strftime('%Y-%m-%d %H:%M:%S') if self.session_start else 'N/A'
        info['session_duration'] = str(datetime.now() - self.session_start) if self.session_start else 'N/A'

        return info

    def get_user_permissions(self) -> List[str]:
        """Get list of permission for current user"""
        if not self.current_user:
            return []
        return self.current_user.get_permission_labels()

    def get_available_operations(self) -> List[Tuple[int, str]]:
        """Get numbered list of available operations for current user"""
        if not self.current_user:
            return []
        return self.access_controller.get_authorized_operations(self.current_user)

    def execute_operation(self, permission: Permission) -> Tuple[bool, str]:
        """
        Execute an operation if the user is authorized
        :param permission: permission to be checked
        :return: (success, message)
        """
        if not self.current_user:
            return False, "Not logged in"

        authorized, message = self.access_controller.authorize(self.current_user, permission)

        if authorized:
            return True, f"Operation '{permission.value}' executed successfully!"
        else:
            return False, message

    def get_system_stats(self) -> Dict:
        """Get system statistics"""
        all_users = self.user_repository.get_all_users()

        role_counts = {}
        for role in Role:
            role_counts[role.value] = sum(1 for u in all_users if u.role == role)

        return {
            'total_users': len(all_users),
            'role_distribution': role_counts,
            'current_sessions': 1 if self.current_user else 0
        }


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================
def print_header(title: str):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_user_info(user: User):
    """Print detailed user information"""
    print(f"\n USER PROFILE")
    print("-" * 70)
    print(f"   Username: {user.username}")
    print(f"   Role: {user.role.value}")
    print(f"   Permissions: {len(user.permissions)}")
    print(f"   Account Created: {datetime.fromtimestamp(user.created).strftime('%Y-%m-%d %H:%M:%S')}")


def display_dashboard(system: JustInvestSystem):
    """Display user dashboard after login"""
    user = system.get_current_user()
    if not user:
        return

    print_header("justInvest System - Dashboard")

    # User Information
    info = system.get_current_user_info()
    print("\n SESSION INFORMATION:")
    print(f"   Username: {info['username']}")
    print(f"   Role: {info['role']}")
    print(f"   Login Time: {info['login_time']}")
    print(f"   Session Duration: {info['session_duration']}")

    # Temporal status
    temporal_ok, temporal_msg = user.check_temporal_constraints()
    status_icon = ":)" if temporal_ok else "!"
    print(f"   Access Status: {status_icon} {temporal_msg}")

    # Available Operations
    print("\n AVAILABLE OPERATIONS/YOUR PERMISSIONS:")
    operations = system.get_available_operations()
    if operations:
        for num, op in operations:
            print(f"   {num}. {op}")
    else:
        print("   No operations available at this time")

    print("\n" + "=" * 70)


def enrollment_flow(system: JustInvestSystem):
    """Handle user enrollment (Problem 3)"""
    print_header("User Enrollment")

    # Get username
    username = input("\nEnter username: ").strip()
    if not username:
        print("Username cannot be empty")
        return

    # Get role
    print("\nSelect role:")
    roles = list(Role)
    for i, role in enumerate(roles, 1):
        print(f"{i}. {role.value}")

    try:
        role_choice = int(input("\nChoice: "))
        if not (1 <= role_choice <= len(roles)):
            print("Invalid role selection")
            return
        role = roles[role_choice - 1]
    except ValueError:
        print("Invalid input")
        return

    # Get password
    print("\n PASSWORD REQUIREMENTS:")
    print("   • 8-12 characters")
    print("   • At least one uppercase letter")
    print("   • At least one lowercase letter")
    print("   • At least one digit")
    print("   • At least one special character (!@#$%*&)")
    print("   • Not a common weak password")
    print("   • Does not match username")

    password = getpass.getpass(prompt="Enter password: ")
    confirm_password = getpass.getpass(prompt="Confirm password: ")

    # Attempt enrollment
    success, message = system.enroll_user(username, password, confirm_password, role)

    if success:
        print(f"\n{message}")

        # Show created user
        user = system.user_repository.get_user(username)
        if user:
            print_user_info(user)
    else:
        print(f"\n{message}")


def login_flow(system: JustInvestSystem) -> bool:
    """Handle user login (Problem 4). Returns True if successful."""
    print_header("User Login")

    username = input("\nUsername: ").strip()
    password = getpass.getpass(prompt="Password: ")

    success, msg = system.login(username, password)

    if success:
        print(f"\nACCESS GRANTED! {msg}")
        return True
    else:
        print(f"\nACCESS DENIED! {msg}")
        return False


def show_system_stats(system: JustInvestSystem):
    """Display system statistics"""
    print_header("System Statistics")

    stats = system.get_system_stats()

    print(f"\n SYSTEM OVERVIEW:")
    print(f"   Total Users: {stats['total_users']}")
    print(f"   Active Sessions: {stats['current_sessions']}")

    print(f"\n ROLE DISTRIBUTION:")
    for role, count in stats['role_distribution'].items():
        print(f"   {role}: {count}")


def main():
    """Main application loop"""
    system = JustInvestSystem()

    print_header("justInvest System")
    print("Integrated Authentication and Access Control System")
    print("User-Centric Architecture with RBAC")

    while True:
        if not system.is_logged_in():
            # Main Menu (not logged in)
            print("\n" + "-" * 70)
            print("1. Enroll new user")
            print("2. Login")
            print("3. View system statistics")
            print("4. Exit")

            choice = input("\nSelect option: ").strip()

            if choice == "1":
                enrollment_flow(system)
            elif choice == "2":
                if login_flow(system):
                    display_dashboard(system)
            elif choice == "3":
                show_system_stats(system)
            elif choice == "4":
                print("\nGoodbye!")
                break
            else:
                print("Invalid option. Please choose an option from 1-4")

        else:
            # Logged in menu
            user = system.get_current_user()
            print("1. View User Profile")
            print("2. Perform an Operation")
            print("3. Logout")

            choice = input("\nSelect option: ").strip()

            if choice == "1":
                print_user_info(user)
            elif choice == "2":
                operations = AccessController.get_authorized_operations(user)

                if not operations:
                    print("You currently have no authorized operations.")
                    continue

                print("\n AVAILABLE OPERATIONS/YOUR PERMISSIONS:")
                for num, op in operations:
                    print(f"   {num}. {op}")

                try:
                    choice_num = int(input("\nWhich operation would you like to execute? (Numerical Input): ").strip())
                    if choice_num not in range(1, len(operations) + 1):
                        print("Invalid selection.")
                        continue
                except ValueError:
                    print("Invalid input. Please enter a number.")
                    continue

                # Map the selected number to the permission enum
                selected_permission_label = operations[choice_num - 1][1]

                # Find the corresponding Permission enum
                permission_mapping = {perm.value: perm for perm in system.current_user.permissions}
                selected_permission = permission_mapping.get(selected_permission_label.replace(" ", "_").lower())

                if selected_permission is None:
                    print("Error: Could not find permission to execute.")
                    continue

                _, msg = system.execute_operation(selected_permission)
                print(f"\n {msg}")

            elif choice == "3":
                username = user.username
                system.logout()
                print(f"\n {username} logged out successfully")
            else:
                print("Invalid option. Please choose an option from 1-4")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
