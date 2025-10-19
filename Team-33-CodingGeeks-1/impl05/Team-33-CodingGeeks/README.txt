Secure Programming Submission of Implementation

SOCP v1.3  —  Team Submission
=================================
Team: CodingGeeks
Authors: Lavanya Saini, Prakriti Timalsena, Rahul Rajendrakumar Budyal, Rishank Goyal, Ziqian Hui
Contacts: lavanya.saini@adelaide.edu.au, rahulrajendrakumar.budyal@adelaide.edu.au, a1974524@adelaide.edu.au, a1877488@adelaide.edu.au, a1989163@adelaide.edu.au

This archive contains our implementation for the Advanced Secure Protocol Design,
Implementation and Review assignment (SOCP v1.3).  
This submission intentionally created vulnerabilities 
The code is labelled as vulnerable and the backdoors are gated.  
Do NOT run this software on untrusted networks or on production machines.

Requirements
------------
- Python 3.11 (or >=3.10 but tests run with 3.11)
- pip
- sqlite3 CLI (for manual DB inspection)
- Recommended OS: Linux or WSL / Git Bash on Windows (scripts assume UNIX-y tools).

Quick setup
-----------
1) Create and activate a virtual environment:

   python3.11 -m venv .venv
   source .venv/bin/activate   # (on Windows: .venv\\Scripts\\activate)

2) Install dependencies:

   pip install -U pip wheel
   pip install -r requirements.txt

3) Initialize DB (optional; scripts/tests will auto-create a temp DB):

   python -c "from socp.core import store; store.init_db('socp_b.db', 'db/schema.sql')"


Running a server (basic example)
--------------------------------
Example single-server run (for development only):

   python -m socp.cmd.server --config configs/server.yaml

This will start a test server bound to the address in configs/server.yaml.
See configs/ for example bootstrap and server config files.

Running the client (basic example)
----------------------------------
Open a new shell and run:

   python -m socp.cmd.client --server ws://127.0.0.1:7001

Use the client REPL commands:
  /list     - list members (if implemented)
  /tell ID  - send a private message
  /all      - send to public channel
  /file PATH - send file (send/receive behavior depends on server topology)

Backdoor test mode
-------------------------------
This submission contains **vulnerabilities** as part of the assignment.
They are **disabled by default**. To enable them you must:

1) Create the backdoor token (local machine, lab VM only):

   ./scripts/confirm_backdoor_enable.sh
   # when prompted, type: BACKDOOR-ENABLE

   This script creates a token file in a local temp path and appends an audit
   entry. The token is stored outside the repository (default: /tmp/socp_backdoor_token).

2) Enable the environment toggle in the same shell:

   export SOCP_ALLOW_BACKDOOR=1   # Git Bash / Linux
   # (Windows PowerShell: $env:SOCP_ALLOW_BACKDOOR = "1")

3) Run the PoC script to exercise lab features:

   PYTHONPATH=. python3 scripts/poc_insecure_file_send.py

The PoC demonstrates the lab-only behaviour when the token and env var are present.
**We do not describe the vulnerabilities here**

Files included
--------------
- socp/                 (source code)
- scripts/              (test and PoC scripts; enable token script)
- db/schema.sql         (SQLite schema)
- configs/              (example server configs)
- tests/                (unit/smoke tests)
- README.txt            (this file)
- commit.txt            (branch and commit we are submitting)

Submission notes
----------------
- Branch: feat/db-public-readme
- Commit: 07770c4

Please contact the team if you have trouble running the tests or server

Code & Ethics
-----------------
- This code is for part of the assignment and lab-only use and contains intentional vulnerabilities
  to be exploited only within the assigned, isolated VM environment.
- We have not included any real personal data, secrets, or production keys.


Thank you — looking forward to your review and feedback!
