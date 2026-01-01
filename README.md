# justInvest Authentication and Access Control System

A complete Role-Based Access Control (RBAC) system with secure password management, user enrollment, and login functionality for the justInvest financial services platform.

## System Requirements

- **Python Version**: 3.10 or later
- **Operating System**: Windows, macOS, or Linux
- **Dependencies**: Standard library only (no external packages required for basic functionality)

### Optional Dependencies

For enhanced password hashing (Argon2id instead of PBKDF2-SHA256 fallback):
```bash
pip install argon2-cffi
```

**Note**: The system works without this package using PBKDF2-SHA256 as a fallback. But Argon2 installation is recommended.

## Installation

1. **Download the files**:
   - `Problem1_4.py` - Main system implementation
   - `Problem1_Tests.py` - Access control tests
   - `Problem2_Tests.py` - Password file management tests
   - `Problem3_Tests.py` - Enrollment and password checker tests
   - `Problem4_Tests.py` - Login mechanism tests

2. **No additional setup required** - all required modules are in Python's standard library.

## Running the Application

### Interactive Mode

Run the main application to access the interactive menu:
```bash
python Problem1_4.py
```

**Main Menu Options**:
1. Enroll new user
2. Login
3. View system statistics
4. Exit

**After Login**:
1. View User Profile
2. Perform an Operation
3. Logout

### Example Usage
```
=================================================================
  justInvest System
=================================================================
Integrated Authentication and Access Control System
User-Centric Architecture with RBAC

----------------------------------------------------------------------
1. Enroll new user
2. Login
3. View system statistics
4. Exit

Select option: 1
```

## Running the Test Suites

### Run All Tests at Once
```bash
# Access Control Tests
python Problem1_Tests.py

# Password File Tests
python Problem2_Tests.py

# Enrollment Tests
python Problem3_Tests.py

# Login Mechanism Tests
python Problem4_Tests.py
```


## Troubleshooting

### Issue: "ImportError: No module named 'Problem1'"

**Solution**: Ensure `Problem1.py` is in the same directory as the test files.
```bash
ls
# Should show: Problem1.py, test_access_control.py, etc.
```

### Issue: "ModuleNotFoundError: No module named 'argon2'"

**Solution**: This is expected if argon2-cffi is not installed. The system will automatically use PBKDF2-SHA256 fallback.
```
WARNING: argon2-cffi not available, using PBKDF2-SHA256 fallback
```

To install argon2-cffi (optional but recommended):
```bash
pip install argon2-cffi
```


### Issue: Tests fail with temporal constraint errors (Teller tests)

**Solution**: Teller tests may behave differently outside business hours (9 AM - 5 PM). This is expected behavior and tests account for this.

### Issue: "PermissionError: [Errno 13] Permission denied: 'passwd.txt'"

**Solution**: Ensure the file isn't open in another program. Close any text editors viewing the password file.


## Quick Start Example
```python
# Start the application
python Problem1.py

# 1. Enroll a new user
Select option: 1
Enter username: john
Select role: 1 (Client)
Enter password: MyPass123!
Confirm password: MyPass123!

# User 'john' enrolled successfully as Client
# User profile is displayed

# 2. Login
Select option: 2
Username: john
Password: MyPass123!

# ACCESS GRANTED! Welcome john!

# 3. View available operations
# Dashboard is displayed
# Your permissions will be displayed based on your role
```


## License

This is an educational project for SYSC 4810 - Network and Software Security.

**Python Version**: 3.12.3  
**Status**: Complete and tested
