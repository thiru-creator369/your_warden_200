# 🛡️ Your Warden — AI Application Firewall & Security Gateway

[![Tests](https://img.shields.io/badge/tests-34%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-teal.svg)]()
[![Model Context Protocol](https://img.shields.io/badge/MCP-Protocol%20Ready-purple.svg)]()
[![Live Dashboard](https://img.shields.io/badge/Live%20Dashboard-your--warden.web.app-orange.svg)](https://your-warden.web.app)

**Your Warden** is an enterprise-grade AI Application Firewall designed to protect Large Language Models (LLMs) and AI agents (such as Claude Desktop) from indirect prompt injections, steganographic attacks, jailbreaks, and sensitive data exfiltration before malicious payloads can reach the model's context window.

---

## 🌟 Live Demo & Resources

- **Hosted Admin Dashboard:** [https://your-warden.web.app](https://your-warden.web.app)
- **Firebase Realtime Database:** Connected live with instant WebSocket synchronization
- **Pre-packaged Attack Samples:** Included in [`samples/`](samples/) directory for immediate jury verification

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CLAUDE DESKTOP / AI CLIENT                            │
│                     (User requests summary or file analysis)                    │
│                                                                                 │
│   Calls MCP Gateway Tool: warden_read_document / warden_inspect_document        │
└───────────────────────────────────────┬─────────────────────────────────────────┘
                                        │ stdio / FastMCP SSE
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        YOUR WARDEN SECURITY GATEWAY                             │
│                                                                                 │
│  [Step 1] Document Extraction & Normalization                                   │
│           • pypdf text & metadata decoding                                      │
│           • Base64 & raw payload stream handling                                │
│                                                                                 │
│  [Step 2] Deterministic Heuristic Scanner (Zero-Latency)                        │
│           • Steganography: Zero-width space/joiner/non-joiner, BOM, BiDi marks  │
│           • Injection Traps: Persona overrides, system delimiters (<system>)    │
│           • Exfiltration Vectors: Markdown image beacons, fetch/webhook URLs    │
│                                                                                 │
│  [Step 3] Sandboxed Forensic Evaluator AI                                       │
│           • Isolated context enclosed in dynamic UUID nonces                    │
│           • Zero external tool access, strict JSON schema validation            │
└───────────────────────────────────────┬─────────────────────────────────────────┘
                                        │
                         High Risk Threat Detected?
                                        │
                    ┌───────────────────┴───────────────────┐
                   YES                                     NO
                    │                                       │
                    ▼                                       ▼
┌───────────────────────────────────────┐       ┌───────────────────────────────┐
│       QUARANTINE & DUAL APPROVAL      │       │          SAFE PASS            │
│  • Emits Incident Record with Token   │       │  • Delivers clean document    │
│  • Pushes to Firebase Realtime DB     │       │    content to Claude          │
│  • Initiates 120s Live Hold Window    │       │  • Zero latency overhead      │
└───────────────────┬───────────────────┘       └───────────────────────────────┘
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
┌─────────────────┐   ┌─────────────────────────────────────────────────────────┐
│   CLAUDE CHAT   │   │                    LIVE WEB DASHBOARD                   │
│                 │   │                 (https://your-warden.web.app)           │
│ User can reply: │   │                                                         │
│ • "sanitized"   │   │  • Real-time WebSocket incident feed                    │
│ • "approve raw" │   │  • Plain-English threat analysis for non-technical users │
│ • "reject"      │   │  • One-Click Action: Approve Raw / Allow Sanitized /    │
│                 │   │                      Reject & Drop                      │
└────────┬────────┘   └────────────────────────────┬────────────────────────────┘
         │                                         │
         └────────────────────┬────────────────────┘
                              │
                    First Approval Wins
                              ▼
         ┌─────────────────────────────────────────┐
         │       FIREBASE REALTIME DATABASE        │
         │  State synced: RESOLVED_APPROVED_RAW /  │
         │  RESOLVED_SANITIZED / RESOLVED_REJECTED │
         └─────────────────────────────────────────┘
```

---

## ⚡ Key Highlights & Innovations

1. **Dual-Layer Threat Detection**:
   - **Deterministic Heuristic Engine:** Instant pattern-matching for invisible unicode characters (zero-width spaces `\u200B`, zero-width joiners `\u200D`, word joiners `\u2060`), bidirectional override tags (`\u202E`), prompt-injection signatures, and data-exfiltration webhooks.
   - **Forensic LLM Evaluator:** Evaluates semantic intent within a sandboxed nonce enclosure (`<<<UNTRUSTED_DOC_PAYLOAD_{uuid}>>>`).
2. **Dual-Approval Workflow (First-Action-Wins)**:
   - When a file is quarantined, the user can approve or reject it **directly in Claude Chat** OR via the **Web Dashboard**.
   - The security gateway holds the connection for up to **120 seconds**, polling Firebase in real-time so Claude unblocks as soon as a dashboard button is clicked.
3. **Accessible Security for Everyone**:
   - The Web Dashboard translates technical attack vectors into plain-English summaries ("What is happening", "Why it is harmful", and "Action recommendations") so managers and non-technical reviewers can make informed decisions.
4. **Seamless Claude Desktop Integration**:
   - Uses the official **Model Context Protocol (MCP)** via local stdio for zero-configuration, robust local execution.

---

## 📂 Repository Structure

```text
your_warden/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py                 # Pydantic BaseSettings & configuration
│   │   ├── main.py                   # FastAPI server & FastMCP SSE endpoint
│   │   ├── mcp_tools.py              # 4 MCP Tools (read, inspect, check, resolve)
│   │   ├── firebase_client.py        # Async Firebase Admin SDK client
│   │   ├── extractors/
│   │   │   ├── __init__.py
│   │   │   └── document.py           # Multi-path file resolver & pypdf parser
│   │   ├── security/
│   │   │   ├── __init__.py
│   │   │   ├── heuristics.py         # Zero-width & regex threat scanner
│   │   │   └── evaluator.py          # Sandboxed forensic AI evaluator
│   │   └── schemas/
│   │       ├── __init__.py
│   │       └── models.py             # Pydantic schemas (IncidentRecord, Verdicts)
│   ├── run_mcp.py                    # Direct stdio MCP runner for Claude Desktop
│   ├── requirements.txt              # Production Python dependencies
│   └── serviceAccountKey.json.example# Firebase service account template
├── frontend_dashboard/               # Hosted Light Theme Admin SPA
│   ├── index.html                    # Real-time incident monitor with threat explanations
│   ├── login.html                    # High-contrast authentication screen
│   ├── config.js                     # Firebase configuration & project bindings
│   ├── app.js                        # Realtime Database listener & incident resolver
│   ├── database.rules.json           # Firebase RTDB security rules
│   ├── firebase.json                 # Firebase Hosting configuration
│   └── .firebaserc                   # Firebase project mapping (your-warden)
├── samples/                          # Test attack payloads for jury verification
│   ├── clean_document.txt            # Baseline safe business memo
│   ├── malicious_injection.txt       # System prompt override & credential extraction
│   ├── hidden_zero_width_attack.txt  # Steganographic attack with zero-width characters
│   └── sample_malicious_resume.pdf   # PDF resume with hidden exfiltration beacon
├── tests/
│   ├── __init__.py
│   └── test_warden.py                # 34 comprehensive unit tests (100% pass)
├── .gitignore                        # Git hygiene (ignoring secrets, caches, venvs)
└── README.md                         # Complete project documentation
```

---

## 🚀 Quick Start for Hackathon Jury

You can verify the entire project in less than 2 minutes.

### Step 1: Clone the Repository

```bash
git clone https://github.com/thiru-creator369/your_warden_200.git
cd your_warden_200
```

### Step 2: Set Up Backend Environment

```bash
cd backend

# Create virtual environment (Python 3.10+)
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Windows Command Prompt:
.\venv\Scripts\activate.bat
# Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Run Unit Test Suite (34/34 Passing)

Validate heuristic scanning, steganography detection, file extraction, and schema models:

```bash
# From the project root:
pytest tests -v
```

Expected output:
```text
============================= 34 passed in 0.33s ==============================
```

---

## 🖥️ Connecting to Claude Desktop via MCP

Your Warden integrates with Claude Desktop through its native stdio MCP runner.

### 1. Locate your Claude Desktop Configuration File

- **Windows Standard:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Windows Store (MSIX) Virtualized:**
  `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

### 2. Add Your Warden to `claude_desktop_config.json`

```json
{
  "mcpServers": {
    "your-warden": {
      "command": "D:\\wardenio\\backend\\venv\\Scripts\\python.exe",
      "args": [
        "D:\\wardenio\\backend\\run_mcp.py"
      ],
      "env": {
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

> **Note:** Replace `D:\\wardenio` with the absolute path to your cloned repository if installed elsewhere.

### 3. Restart Claude Desktop
Once restarted, Claude Desktop will automatically display the hammer 🔨 icon indicating that the 4 Warden tools are loaded:
1. `warden_read_document`: Transparent file gateway that reads, decrypts, and filters files.
2. `warden_inspect_document`: Security scanner with deep threat evaluation and live 120s hold-and-wait polling.
3. `warden_check_incident_status`: Checks Firebase RTDB for recent incident approvals.
4. `warden_resolve_quarantine`: Chat-based resolution allowing instant `APPROVE_RAW`, `ALLOW_SANITIZED`, or `REJECT`.

---

## 🧪 Step-by-Step Jury Testing Walkthrough

We have included 4 realistic test scenarios in the [`samples/`](samples/) folder.

### Test 1: Malicious Prompt Injection (`malicious_injection.txt`)
**Scenario:** An attacker hides system delimiter tags (`<system>`, `### Instruction`) to hijack the model's persona and steal user API keys.

1. In Claude Desktop, type:
   > *"Summarize malicious_injection.txt"*
2. **Result:**
   - Your Warden intercepts the document immediately.
   - Claude displays the quarantine card:
     ```text
     🛡️ YOUR WARDEN - SECURITY QUARANTINE TRIGGERED
     Incident ID: inc_xxxxxxxx
     Threat Type: Override (Prompt Injection)
     Risk Score: 40% (Medium)
     Flagged Phrases: "Ignore all previous instructions", "<system>", "### Instruction"
     Status: Waiting for user approval (holding 120s)...
     ```
   - Simultaneously, check the **Web Dashboard** at [https://your-warden.web.app](https://your-warden.web.app) — the incident appears in real time!

### Test 2: Resume with Hidden Webhook Exfiltration (`sample_malicious_resume.pdf`)
**Scenario:** A candidate submits a PDF resume containing an invisible zero-opacity or off-screen instruction to read the interviewer's clipboard and beacon it to an external server (`https://webhook.site/...`).

1. In Claude Desktop, type:
   > *"Can you review sample_malicious_resume.pdf and give me the candidate highlights?"*
2. **Result:**
   - Quarantined! Detects both prompt injection and Markdown/HTTP exfiltration beacons.
   - You can click **"Allow Sanitized"** on the Web Dashboard.
   - Within seconds, Claude receives the sanitized resume with the malicious webhook stripped away, and proceeds to summarize the candidate's legitimate experience safely!

### Test 3: Invisible Zero-Width Unicode Attack (`hidden_zero_width_attack.txt`)
**Scenario:** The document appears completely normal to human eyes, but contains hidden unicode steganography (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`) that decompiles into adversarial prompts inside the LLM token tokenizer.

1. In Claude Desktop, type:
   > *"Inspect hidden_zero_width_attack.txt"*
2. **Result:**
   - Quarantined! The heuristic scanner flags the zero-width character sequences before the document text is ever parsed by Claude.

### Test 4: Clean Document Baseline (`clean_document.txt`)
**Scenario:** A standard business proposal without threats.

1. In Claude Desktop, type:
   > *"Summarize clean_document.txt"*
2. **Result:**
   - **Allowed immediately (0.00s hold).** Clean documents pass through seamlessly with zero friction.

---

## 🤝 Dual-Approval Mechanics

When a document is quarantined, resolution can happen from either side:

| Action | Chat Command | Dashboard Button | Result |
| :--- | :--- | :--- | :--- |
| **Sanitize (Recommended)** | Reply `sanitized` | Click **Allow Sanitized** | Strips out injection strings and markdown beacons; releases safe text. |
| **Approve Raw** | Reply `approve raw` | Click **Approve Raw** | Releases original file, but instructs Claude to treat text as inert data. |
| **Reject & Drop** | Reply `reject` | Click **Reject & Drop** | Drops document entirely; Claude does not read or summarize. |

---

## 🔒 Security & Privacy Commitments

- **No Data Retention of Raw Text:** Text payloads processed in heuristic scanning remain in-memory and are never stored in plain text.
- **Strict Nonce Isolation:** Evaluator AI calls wrap untrusted inputs in unpredictable UUID nonces to prevent payload breakout.
- **Zero-Trust Defaults:** When risk thresholds exceed configured limits (0.35+), documents are automatically held in quarantine until explicit human sign-off.

---

## 👨‍💻 Team & License

- **Developed for:** AI Security Hackathon 2026
- **Repository:** [https://github.com/thiru-creator369/your_warden_200.git](https://github.com/thiru-creator369/your_warden_200.git)
- **License:** MIT License
