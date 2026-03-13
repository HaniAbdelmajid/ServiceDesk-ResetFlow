# ServiceDesk ResetFlow (Password Reset Simulator)

ServiceDesk ResetFlow is a Python project I built to simulate a secure, helpdesk-style password reset workflow.  
It **does not** reset real Windows/Active Directory passwords. Everything runs locally using a **SQLite** database so the full process can be safely demonstrated.

The goal is to model what matters in IT support: identity verification, time-limited reset sessions, temporary lockouts, and audit trails.

---

## What this project demonstrates

### Identity verification
Users must answer **two security questions** before a reset session is created.

### One-time reset code
After verification, the tool issues a **6-digit one-time code** with an expiration timer.  
For demo purposes, the code is printed to the console (in a real environment it would be delivered via email/SMS).

### Rate limiting and lockouts
Repeated verification failures trigger a **temporary lockout**.  
This helps prevent guessing/spam attempts and mirrors basic service desk controls.

### Audit logging
Key actions are recorded to an audit log, including:
- account creation
- verification success/failure
- reset code issued / accepted
- password reset completed
- tech unlock actions
- system lockouts applied

### Roles (user vs tech)
Accounts can be created as:
- `user` (normal user workflow)
- `tech` (support actions like unlocking an account and viewing audit activity)

---

## What is stored locally

Running the program creates a local database file:

- `resetdesk.db`

It stores:
- user profiles (username, email, role)
- password hashes (PBKDF2 with a per-user salt)
- hashed reset codes + expiration timestamps
- attempt history (used for rate limiting)
- temporary lockout records
- audit log entries

Passwords and security answers are **not** stored in plain text.

---

## How to run

From the project folder:
Click run on your IDE of choice for the resetdesk.py file

or

```bash
python resetdesk.py
