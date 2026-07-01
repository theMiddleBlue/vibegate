"""Static security-guidance tables keyed by technical category + semantic type.

No network, no LLM: every lookup is O(1) against the dictionaries below.

Each SEMANTIC_GUIDANCE entry carries:
  - validation:        how to validate (library / approach)
  - validation_regex:  a concrete regex to validate the field, or "" when a
                       regex is the wrong tool (the reason is in threat_explanation)
  - sanitization:      how to normalize/neutralize the value
  - specific_risks:    short risk labels
  - threat_explanation: free text explaining WHY it is dangerous and the
                       non-obvious bypasses the implementer must account for
"""

from __future__ import annotations

# Technical category -> generic risks + severity.
TECHNICAL_RISKS = {
    "CLI_ARG": {
        "risks": [
            "Argument injection",
            "Path traversal",
            "Shell injection if passed to exec",
        ],
        "severity": "MEDIUM",
    },
    "STDIN": {
        "risks": [
            "Unvalidated input",
            "Buffer overflow (C/C++)",
            "Injection if used in a query",
        ],
        "severity": "MEDIUM",
    },
    "HTTP_BODY": {
        "risks": [
            "SQL Injection",
            "XSS",
            "Mass Assignment",
            "Deserialization attack",
        ],
        "severity": "HIGH",
    },
    "HTTP_QUERY": {
        "risks": ["Reflected XSS", "Open Redirect", "Parameter tampering"],
        "severity": "HIGH",
    },
    "HTTP_HEADER": {
        "risks": [
            "Header injection",
            "Host header attack",
            "SSRF if used in a URL",
        ],
        "severity": "HIGH",
    },
    "URL_FETCH": {
        "risks": [
            "SSRF",
            "Internal service / cloud-metadata access",
            "Credential theft via metadata endpoint",
        ],
        "severity": "HIGH",
    },
    "ENV_VAR": {
        "risks": ["Credential exposure in logs", "Config injection"],
        "severity": "LOW",
    },
    "FILE_PATH": {
        "risks": ["Path traversal", "Directory traversal", "Symlink attack"],
        "severity": "HIGH",
    },
    "EXEC_INPUT": {
        "risks": [
            "Command injection",
            "OS command execution",
            "Remote Code Execution",
        ],
        "severity": "CRITICAL",
    },
    "DB_QUERY": {
        "risks": ["SQL Injection", "NoSQL Injection", "Data exfiltration"],
        "severity": "CRITICAL",
    },
    "CREDENTIAL": {
        "risks": ["Credential stuffing", "Brute force", "Log exposure"],
        "severity": "HIGH",
    },
    "TEMPLATE_INJECTION": {
        "risks": [
            "Server-Side Template Injection",
            "Remote Code Execution",
            "Sandbox escape",
        ],
        "severity": "CRITICAL",
    },
    "INSECURE_DESERIALIZATION": {
        "risks": [
            "Arbitrary object instantiation",
            "Remote Code Execution",
            "Denial of Service",
        ],
        "severity": "CRITICAL",
    },
    "NOSQL_QUERY": {
        "risks": [
            "NoSQL operator injection",
            "Authentication bypass",
            "Data exfiltration",
        ],
        "severity": "CRITICAL",
    },
    "PATH_TRAVERSAL": {
        "risks": [
            "Arbitrary file read/write",
            "Directory traversal",
            "Remote Code Execution via file overwrite",
        ],
        "severity": "CRITICAL",
    },
    "XXE": {
        "risks": [
            "Local file disclosure",
            "SSRF via external entity",
            "Denial of Service (billion laughs)",
        ],
        "severity": "CRITICAL",
    },
    "XSS_SINK": {
        "risks": [
            "Stored/Reflected Cross-Site Scripting",
            "Session hijacking",
            "Account takeover",
        ],
        "severity": "CRITICAL",
    },
    "OPEN_REDIRECT": {
        "risks": ["Phishing via a trusted domain", "OAuth token theft"],
        "severity": "HIGH",
    },
    "MASS_ASSIGNMENT": {
        "risks": [
            "Privilege escalation via unexpected fields",
            "Data integrity bypass",
        ],
        "severity": "HIGH",
    },
    "FILE_UPLOAD": {
        "risks": [
            "Remote Code Execution via renamed webshell",
            "Path traversal / arbitrary file write",
            "Existing file overwrite",
        ],
        "severity": "CRITICAL",
    },
}

# Semantic type -> validation, sanitization, specific risks, regex, threat model.
SEMANTIC_GUIDANCE = {
    "EMAIL": {
        "validation": "RFC 5322 regex or a dedicated library (email-validator, pydantic EmailStr)",
        "validation_regex": r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        "sanitization": "Lowercase, strip whitespace, max 254 chars",
        "specific_risks": [
            "Email injection in SMTP headers",
            "Phishing via redirect",
        ],
        "threat_explanation": (
            "An email value is frequently concatenated into SMTP headers; an unescaped CR/LF "
            "lets an attacker inject extra headers (Bcc, Reply-To) or a whole new message body "
            "(SMTP header injection). The address is also used as an account identifier, so loose "
            "parsing enables account takeover via Unicode/IDN homoglyphs or sub-addressing "
            "(user+tag@). Validate the syntax, reject embedded control characters, normalize the "
            "domain, and never trust the value as proof of identity until it is verified."
        ),
    },
    "PHONE_NUMBER": {
        "validation": "libphonenumber (Google), E.164 format",
        "validation_regex": r"^\+?[1-9]\d{6,14}$",
        "sanitization": "Strip non-numeric characters before validation",
        "specific_risks": ["SMS pumping fraud", "Enumeration via timing"],
        "threat_explanation": (
            "If a phone number triggers an outbound SMS (OTP, verification), an attacker can drive "
            "traffic to premium or high-cost destinations they control (SMS pumping / toll fraud), "
            "turning your send path into a billing attack. Numbers are also a PII identifier, so "
            "unauthenticated lookup endpoints enable user enumeration. Validate to E.164, enforce "
            "per-number and per-IP rate limits, and apply geo/cost allowlists before sending."
        ),
    },
    "MOBILE_NUMBER": {
        "validation": "libphonenumber with type=MOBILE",
        "validation_regex": r"^\+?[1-9]\d{6,14}$",
        "sanitization": "Normalize to E.164",
        "specific_risks": ["SMS pumping fraud"],
        "threat_explanation": (
            "Same threat surface as a generic phone number but specifically SMS-deliverable, which "
            "makes SMS pumping fraud and OTP-flooding more directly exploitable. Confirm the line "
            "type is actually mobile, rate-limit sends per number, and cap cost by destination "
            "before dispatching any message."
        ),
    },
    "PASSWORD": {
        "validation": "Min 12 chars, breach check (Have I Been Pwned API)",
        "validation_regex": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,128}$",
        "sanitization": "NEVER log, NEVER compare in plaintext — hash with bcrypt/argon2",
        "specific_risks": [
            "Timing attack in comparison",
            "Log injection",
            "Shoulder surfing",
        ],
        "threat_explanation": (
            "The regex shown enforces composition only; do not over-rely on it — NIST guidance "
            "favours length and breach-checking over character-class rules, which mostly push users "
            "toward predictable patterns. The real risks are downstream: plaintext comparison leaks "
            "timing, plaintext storage/logging leaks the secret outright, and a fast hash (MD5/SHA) "
            "makes offline cracking trivial. Hash with bcrypt/argon2/scrypt, compare in constant "
            "time, never log the value, and cap length (e.g. 128) to avoid hash DoS on long inputs."
        ),
    },
    "PIN": {
        "validation": "Digits only, fixed length (4-8), rate limiting",
        "validation_regex": r"^\d{4,8}$",
        "sanitization": "Hash with bcrypt, even for a PIN",
        "specific_risks": [
            "Brute force (10^4 - 10^6 combinations)",
            "Timing attack",
        ],
        "threat_explanation": (
            "A PIN has a tiny keyspace (10^4 to 10^6), so it is brute-forceable in seconds without "
            "strict server-side throttling and lockout — client-side limits are bypassable. Treat it "
            "like a password: hash it, compare in constant time, and enforce attempt counters tied to "
            "the account, not just the session or IP."
        ),
    },
    "API_KEY": {
        "validation": "Expected format (prefix + length), entropy check",
        "validation_regex": r"^[A-Za-z0-9_\-]{16,256}$",
        "sanitization": "NEVER log in plaintext, mask in output (sk-****)",
        "specific_risks": ["Key leakage in logs", "Credential stuffing"],
        "threat_explanation": (
            "API keys are bearer credentials: anyone holding the string has full access, so leakage "
            "into logs, error messages, URLs (query strings end up in proxies/analytics), or client "
            "bundles is an immediate compromise. Prefer the provider's exact prefix/length format over "
            "the generic regex, store only a hash, mask on display, and support rotation/revocation so "
            "a leaked key can be killed fast."
        ),
    },
    "JWT_TOKEN": {
        "validation": "Verify signature, expiry, audience, issuer",
        "validation_regex": r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
        "sanitization": "Do not log, validate algorithm (reject 'none')",
        "specific_risks": ["Algorithm confusion attack", "Token replay"],
        "threat_explanation": (
            "The regex only checks the three-segment shape — it proves nothing about authenticity. The "
            "dangerous bugs are cryptographic: accepting alg=none skips verification entirely, and "
            "alg confusion (RS256 verified as HS256 using the public key as the HMAC secret) forges "
            "tokens. Always pin the expected algorithm, verify the signature against the right key, and "
            "check exp/nbf/aud/iss; never decode-and-trust claims without verifying first."
        ),
    },
    "URL": {
        "validation": (
            "Server-side fetch of a user URL requires ALL THREE steps below, in order — a "
            "scheme/regex check or a blocklist applied to the raw hostname string is NOT "
            "sufficient on its own and is a fail. "
            "STEP 1 — Parse + scheme allowlist: parse with urllib.parse / the URL API and reject "
            "any scheme that is not http or https (block file:, gopher:, dict:, ftp:, etc.). "
            "STEP 2 — Resolve THEN validate the resolved IP: do not test the hostname string; call "
            "the resolver (socket.getaddrinfo) to get every IP the host resolves to, and reject the "
            "request if ANY resolved address is private/loopback/link-local/metadata, checking both "
            "IPv4 AND IPv6 (use ipaddress and is_private / is_loopback / is_link_local / is_reserved, "
            "plus an explicit block of 169.254.169.254 and ::ffff:169.254.169.254). This is the step "
            "that stops host.docker.internal, internal hostnames, and DNS-rebinding payloads — a raw "
            "blocklist does not. "
            "STEP 3 — Pin + connect to the resolved IP: keep the validated IP from step 2 and open "
            "the connection to THAT IP, passing the original hostname as the Host header and the TLS "
            "SNI. Never re-resolve the hostname when connecting (a second lookup reintroduces "
            "rebinding). Re-run all three steps on every redirect hop."
        ),
        "validation_regex": r"^https?://[^\s/$.?#][^\s]*$",
        "sanitization": (
            "Normalize the scheme to http/https and strip embedded credentials (drop any "
            "user:pass@ userinfo). Carry the resolved-and-validated IP from validation step 2 into "
            "the connection: connect to the pinned IP, set Host header + TLS SNI to the original "
            "hostname. The regex above is only a coarse pre-filter — it does not make the URL safe to "
            "fetch; the three validation steps do."
        ),
        "specific_risks": ["Open redirect", "SSRF", "Protocol confusion", "DNS rebinding bypass"],
        "threat_explanation": (
            "If the server fetches this URL it is an SSRF vector: the attacker can reach loopback and "
            "internal-only services (admin panels, databases, host.docker.internal) and especially "
            "cloud metadata endpoints (169.254.169.254, GCP/Azure/AWS IMDS) to steal credentials. Two "
            "bypasses defeat the naive fix of 'block private IPs in the URL string': (a) the value is "
            "usually a HOSTNAME, not an IP, so a string blocklist never sees the private address it "
            "resolves to — this is exactly how host.docker.internal and internal DNS names get "
            "through; (b) DNS rebinding — a hostname can resolve to a public IP when you validate and "
            "to 127.0.0.1 when you fetch. The only robust defense is the three-step sequence in the "
            "Validation field: resolve first, validate every resolved IP (v4 and v6), then pin and "
            "connect to that exact IP with Host header + SNI set to the original host. Skipping the "
            "resolve-and-pin steps and only blocklisting the raw string is the common incomplete fix "
            "and is NOT acceptable here."
        ),
    },
    "REDIRECT_URL": {
        "validation": "MANDATORY allowlist of permitted domains",
        "validation_regex": r"^https?://[^\s/$.?#][^\s]*$",
        "sanitization": "Validate scheme (http/https only), block localhost/private ranges",
        "specific_risks": [
            "Open redirect",
            "Post-auth phishing",
            "OAuth redirect hijack",
        ],
        "threat_explanation": (
            "A user-controlled redirect target is an open-redirect / phishing primitive and, in OAuth, "
            "a token-theft primitive when the redirect_uri is not strictly matched. The regex cannot "
            "make this safe — only an exact allowlist of host (and ideally path prefix) can. Watch for "
            "bypasses: scheme-relative URLs (//evil.com), userinfo tricks (https://trusted@evil.com), "
            "backslashes and encoded characters that browsers normalize differently, and open "
            "redirectors on your own allowlisted domains. Compare against a parsed allowlist, not a "
            "substring match."
        ),
    },
    "FILE_PATH": {
        "validation": "os.path.realpath + allowed-prefix check",
        "validation_regex": r"^(?!.*\.\.)[A-Za-z0-9_\-./]+$",
        "sanitization": "Strip '../', null bytes, disallowed characters",
        "specific_risks": ["Path traversal", "Symlink following", "Zip slip"],
        "threat_explanation": (
            "A user-supplied path can escape the intended directory via ../ traversal, absolute paths, "
            "or symlinks, exposing or overwriting arbitrary files (/etc/passwd, app secrets). The regex "
            "blocks the obvious ../ but is fragile against encoded variants and is not sufficient alone. "
            "The robust control is to canonicalize with realpath AFTER joining, then assert the result "
            "still starts with the allowed base directory; also strip null bytes (truncation tricks) and "
            "be wary of symlink following and archive extraction (Zip Slip)."
        ),
    },
    "FILE_NAME": {
        "validation": "Extension allowlist, max length, no special characters",
        "validation_regex": r"^[A-Za-z0-9_][A-Za-z0-9_\-. ]{0,254}$",
        "sanitization": "Rename with UUID + validated extension, do not reuse the original name",
        "specific_risks": [
            "Double extension (.jpg.php)",
            "Null byte injection",
            "Path traversal",
        ],
        "threat_explanation": (
            "An uploaded file name can carry path separators (traversal), null bytes (extension "
            "truncation), or a double extension (shell.jpg.php) that some servers execute. Reserved "
            "names (CON, NUL on Windows) and leading dots/dashes cause further surprises. Do not trust "
            "or reuse the original name: validate the extension against an allowlist, store under a "
            "generated UUID name, and serve with an explicit, correct Content-Type so it cannot be "
            "interpreted as executable."
        ),
    },
    "SHELL_COMMAND": {
        "validation": "NEVER accept arbitrary commands from user input",
        "validation_regex": "",  # regex is the wrong control — see threat_explanation
        "sanitization": "Use subprocess with an args list (no shell=True), shlex escaping",
        "specific_risks": ["OS Command Injection", "Remote Code Execution"],
        "threat_explanation": (
            "There is no regex that safely allowlists a shell command — metacharacters (; | & $() `` "
            "newlines, globbing) and shell quoting make denylists trivially bypassable, so the field is "
            "left without a validation_regex on purpose. Never build a command string from user input "
            "and never use shell=True. Pass a fixed program plus an argument array (execve-style), or "
            "expose a small allowlist of named operations mapped to hard-coded commands; if a shell is "
            "truly required, shlex.quote every argument."
        ),
    },
    "SQL_QUERY": {
        "validation": "ALWAYS use parameterized queries / prepared statements",
        "validation_regex": "",  # regex is the wrong control — see threat_explanation
        "sanitization": "NEVER build queries via concatenation — ORM or bound parameters",
        "specific_risks": ["SQL Injection", "Blind SQLi", "Time-based SQLi"],
        "threat_explanation": (
            "Attempting to validate or escape SQL with a regex is a known anti-pattern (hence no "
            "validation_regex): comment styles, encodings, and stacked queries defeat denylists, and "
            "escaping by hand misses edge cases. The only robust defense is parameterized queries / "
            "prepared statements so user data is sent as data, never as SQL text. Identifiers (table/"
            "column names) cannot be parameterized — those must come from a server-side allowlist, not "
            "from the request."
        ),
    },
    "IP_ADDRESS": {
        "validation": "ipaddress.ip_address() (Python), block private ranges if needed",
        "validation_regex": r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$",
        "sanitization": "Normalize format, distinguish IPv4/IPv6",
        "specific_risks": [
            "IP spoofing via X-Forwarded-For",
            "SSRF via IP bypass",
        ],
        "threat_explanation": (
            "The regex covers IPv4 only; use a real parser (ipaddress) for IPv6 and to reject ambiguous "
            "forms. If the IP is used for access control, remember it is spoofable via X-Forwarded-For "
            "unless taken from a trusted proxy hop. If it is used as a connection target, it is an SSRF "
            "sink: block loopback, RFC1918, link-local and cloud-metadata ranges, and account for "
            "bypasses like decimal/octal/hex encodings (e.g. 2130706433), IPv4-mapped IPv6 "
            "(::ffff:127.0.0.1), and 0.0.0.0. Validate the canonical, parsed address — not the raw string."
        ),
    },
    "CREDIT_CARD_NUMBER": {
        "validation": "Luhn algorithm, NEVER persist in plaintext",
        "validation_regex": r"^\d{13,19}$",
        "sanitization": "Use PCI-DSS tokenization, mask in output (****1234)",
        "specific_risks": ["PCI DSS compliance", "Card skimming", "Data breach"],
        "threat_explanation": (
            "The regex only checks digit length; a real check also runs the Luhn checksum, but even a "
            "valid PAN must never be stored in plaintext — handling it brings the system into PCI DSS "
            "scope. Prefer never touching the raw PAN at all: use a payment provider/tokenization so "
            "only a token reaches your servers. If you must process it transiently, encrypt in transit "
            "and at rest, mask everywhere (show only last 4), and keep it out of logs and analytics."
        ),
    },
    "BANK_ACCOUNT": {
        "validation": "IBAN validation (ISO 7064 checksum)",
        "validation_regex": r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$",
        "sanitization": "Partially mask in output",
        "specific_risks": ["IBAN manipulation", "Financial fraud"],
        "threat_explanation": (
            "The regex checks the IBAN shape (country code + check digits + BBAN) but not the ISO 7064 "
            "mod-97 checksum, so always verify the checksum to catch typos and tampering. Beyond format, "
            "the real fraud risk is a silently substituted destination account (man-in-the-middle / "
            "business-email-compromise), so treat account changes as sensitive: confirm out-of-band, "
            "log changes, and mask the value in any output."
        ),
    },
    "TAX_CODE": {
        "validation": "Italian fiscal-code algorithm or local equivalent",
        "validation_regex": r"^[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]$",
        "sanitization": "Uppercase, strip spaces",
        "specific_risks": [
            "Identity theft",
            "GDPR — sensitive personal data",
        ],
        "threat_explanation": (
            "The regex matches the Italian codice fiscale structure but does not verify the final check "
            "character — validate that with the official algorithm, and substitute the correct national "
            "format/checksum for other countries. The code is directly identifying personal data under "
            "GDPR: minimize storage, restrict access, encrypt at rest, and never expose it in URLs, "
            "logs, or error messages where it could enable identity theft."
        ),
    },
    "DATE_OF_BIRTH": {
        "validation": "Reasonable range (1900 - today), ISO 8601 format",
        "validation_regex": r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$",
        "sanitization": "Normalize to YYYY-MM-DD",
        "specific_risks": [
            "GDPR — personal data",
            "Age verification bypass",
        ],
        "threat_explanation": (
            "The regex enforces YYYY-MM-DD shape but not semantics: also bound the range (e.g. 1900.."
            "today) and reject impossible dates, since a forged or future DOB bypasses age gates. As "
            "personal data it falls under GDPR, and combined with a name it is a strong identifier for "
            "profiling, so collect it only when necessary and protect it accordingly."
        ),
    },
    "COORDINATES": {
        "validation": "Range lat [-90,90], lon [-180,180]",
        "validation_regex": r"^-?(?:90(?:\.0+)?|[1-8]?\d(?:\.\d+)?),\s*-?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)$",
        "sanitization": "Limit precision when not needed (privacy)",
        "specific_risks": ["Location tracking", "GDPR — sensitive data"],
        "threat_explanation": (
            "The regex validates a 'lat,lon' pair within valid ranges. The main concern is privacy: "
            "high-precision coordinates can deanonymize and track an individual, so reduce precision to "
            "what the feature actually needs (a few decimals), avoid persisting raw history, and treat "
            "location as sensitive personal data under GDPR with explicit purpose and access control."
        ),
    },
    "SEARCH_QUERY": {
        "validation": "Max length, allowed characters",
        "validation_regex": r"^.{0,256}$",
        "sanitization": "Escape for the output context (HTML, SQL, LDAP)",
        "specific_risks": [
            "Reflected XSS",
            "LDAP injection",
            "Log injection",
        ],
        "threat_explanation": (
            "A search term is usually reflected back into a results page and forwarded into a backend "
            "query, so it is simultaneously a reflected-XSS sink and an injection sink (SQL, NoSQL, "
            "LDAP, or a search-engine DSL). The regex only caps length; the real defense is "
            "context-aware output encoding (HTML-escape on display, parameterize for the datastore) "
            "rather than trying to strip 'bad' characters from the input."
        ),
    },
    "FREE_TEXT": {
        "validation": "Max length, encoding check",
        "validation_regex": r"^[\s\S]{0,10000}$",
        "sanitization": "Escape for the output context, strip null bytes",
        "specific_risks": [
            "XSS",
            "Generic injection",
            "DoS via long input",
        ],
        "threat_explanation": (
            "Arbitrary text is the default sink for XSS and stored-injection: it is dangerous only when "
            "rendered or interpreted, so the fix is encoding at the point of output (HTML, attribute, "
            "JS, SQL contexts each differ), not input filtering. The regex caps length to blunt DoS via "
            "huge payloads; also reject null bytes and validate encoding so the value cannot smuggle "
            "control characters into downstream systems."
        ),
    },
    "JSON_PAYLOAD": {
        "validation": "Schema validation (jsonschema, pydantic, zod)",
        "validation_regex": "",  # structure must be validated with a schema, not a regex
        "sanitization": "Limit nesting depth, max size, field allowlist",
        "specific_risks": [
            "Mass assignment",
            "Prototype pollution (JS)",
            "Billion laughs DoS",
        ],
        "threat_explanation": (
            "A nested structure cannot be validated with a regex (hence none) — use a strict schema. "
            "The danger is binding unexpected fields: mass assignment lets a client set fields it "
            "should not (isAdmin, role), and in JS the keys __proto__/constructor/prototype enable "
            "prototype pollution. Validate against an explicit allowlist of fields and types, reject "
            "unknown keys, and cap size and nesting depth to prevent resource-exhaustion DoS."
        ),
    },
    "REGEX": {
        "validation": "Execution timeout, max complexity",
        "validation_regex": "",  # you cannot regex-validate a user-supplied regex safely
        "sanitization": "Do not use user regex in critical contexts",
        "specific_risks": [
            "ReDoS (catastrophic backtracking)",
            "Validation bypass",
        ],
        "threat_explanation": (
            "Letting a user supply a regular expression is dangerous: certain patterns cause "
            "catastrophic backtracking (ReDoS) that hangs the CPU on a crafted input, and you cannot "
            "vet an arbitrary regex with another regex. Prefer not to accept user regexes at all; if "
            "you must, run them on a linear-time engine (RE2) or under a strict timeout and "
            "length/complexity limit, isolated from the request thread."
        ),
    },
    "HEALTH_DATA": {
        "validation": "Expected type, clinically plausible range",
        "validation_regex": "",  # shape varies by measure — validate type/range, not a single regex
        "sanitization": "Mandatory encryption at rest",
        "specific_risks": [
            "HIPAA/GDPR — special sensitive data",
            "Data breach",
        ],
        "threat_explanation": (
            "Health information is a special category under GDPR Art.9 and is regulated by HIPAA, so a "
            "breach carries legal as well as reputational cost. A single regex does not fit (values "
            "range from numeric measurements to free-text notes) — validate the expected type and a "
            "clinically plausible range per field. Encrypt at rest, tightly scope access, and keep it "
            "out of logs and analytics pipelines."
        ),
    },
    "BIOMETRIC": {
        "validation": "Template matching, liveness detection",
        "validation_regex": "",  # raw biometric data is binary — not regex-validatable
        "sanitization": "NEVER persist raw data, only a template hash",
        "specific_risks": [
            "GDPR Art.9 — biometric data",
            "Irrevocable if breached",
        ],
        "threat_explanation": (
            "Biometrics are irrevocable: unlike a password, a leaked fingerprint or face template "
            "cannot be reset, so a breach is permanent. Raw biometric data is binary and not "
            "regex-validatable; never store the raw sample — store only a protected, non-reversible "
            "template, add liveness detection to resist spoofed/presented artifacts, and treat the "
            "data as GDPR Art.9 special category with strict consent and access controls."
        ),
    },
    "HTML_CONTENT": {
        "validation": "Treat as untrusted; never assume it is pre-sanitized HTML",
        "validation_regex": "",
        "sanitization": (
            "Rely on the framework's default autoescaping (Jinja2/Django templates escape by "
            "default) or run it through an allowlist HTML sanitizer (bleach, DOMPurify) before "
            "rendering it as raw HTML"
        ),
        "specific_risks": [
            "Stored/Reflected XSS",
            "Session hijacking via stolen cookies",
        ],
        "threat_explanation": (
            "Wrapping user input in Markup()/mark_safe() (Python) or assigning it to innerHTML/"
            "dangerouslySetInnerHTML (JS) tells the framework to skip escaping and render the "
            "value as literal HTML. If any part of that value is attacker-controlled, they can "
            "inject <script> tags or event handlers that execute in the victim's browser session, "
            "stealing cookies/tokens or performing actions as the victim. There is no regex that "
            "makes arbitrary HTML safe — the only sound approach is output-escaping (never marking "
            "it 'safe' in the first place) or running it through a dedicated allowlist sanitizer "
            "that strips scripts and dangerous attributes."
        ),
    },
    "TEMPLATE_STRING": {
        "validation": (
            "Never accept the template source itself from user input — only user-supplied "
            "variables that get interpolated into a fixed, developer-authored template"
        ),
        "validation_regex": "",
        "sanitization": (
            "Use a sandboxed template environment (Jinja2 SandboxedEnvironment) if a dynamic "
            "template is unavoidable, and never let it access filesystem/OS builtins"
        ),
        "specific_risks": [
            "Server-Side Template Injection",
            "Remote Code Execution",
        ],
        "threat_explanation": (
            "Template engines like Jinja2, Handlebars, and EJS compile their input into executable "
            "code paths (attribute/method access, filters, sometimes arbitrary expressions). If the "
            "template SOURCE — not just a variable rendered inside a safe, fixed template — comes "
            "from user input, an attacker can write template syntax that reaches the underlying "
            "interpreter and executes arbitrary code (e.g. Jinja2's "
            "{{ self.__init__.__globals__ }} gadget chain). This is a fundamentally different bug "
            "from XSS: it runs server-side. Never treat a template string as user data; only its "
            "variables should be."
        ),
    },
    "SERIALIZED_DATA": {
        "validation": (
            "Do not deserialize untrusted data with a format that supports arbitrary object "
            "reconstruction (pickle, marshal, unsafe YAML, Node's node-serialize)"
        ),
        "validation_regex": "",
        "sanitization": (
            "Use a data-only format (JSON) with a schema validator (pydantic, zod, jsonschema) "
            "instead of a language-native serializer"
        ),
        "specific_risks": [
            "Remote Code Execution on deserialization",
            "Denial of Service via crafted payloads",
        ],
        "threat_explanation": (
            "Formats like Python pickle/marshal and unsafe YAML loaders don't just decode data — "
            "they reconstruct arbitrary objects, which can trigger constructor- or "
            "__reduce__-style code execution the moment the payload is loaded, before your code "
            "even inspects it. The same class of bug exists in Node's node-serialize and Java's "
            "ObjectInputStream. There is no way to sanitize a serialized blob after the fact — the "
            "deserialization call itself is the vulnerability. Switch to a data-only format (JSON) "
            "validated against an explicit schema, or use the format's documented safe mode "
            "(yaml.safe_load) which only ever produces plain data types."
        ),
    },
    "NOSQL_FILTER": {
        "validation": (
            "Only accept known field names/operators from an explicit allowlist — never pass the "
            "raw request body as a query filter"
        ),
        "validation_regex": "",
        "sanitization": (
            "Build the filter object field-by-field from validated scalars; strip/reject any key "
            "starting with '$' (MongoDB operator syntax)"
        ),
        "specific_risks": [
            "NoSQL operator injection",
            "Authentication bypass",
        ],
        "threat_explanation": (
            "MongoDB (and similar document stores) interpret keys like $gt, $ne, $where inside a "
            "query object as operators, not literal values. If a request body is passed straight "
            "through as the filter — e.g. db.users.find(request.json) — an attacker can send "
            '{"password": {"$ne": null}} to match every document, bypassing an authentication '
            "check entirely. This is the NoSQL equivalent of SQL injection but involves no string "
            "concatenation, so it's easy to miss in review. Never pass a raw JSON body as a query "
            "filter; construct the filter from named, validated fields instead."
        ),
    },
    "XML_PAYLOAD": {
        "validation": "Disable external entity resolution before parsing any untrusted XML",
        "validation_regex": "",
        "sanitization": (
            "Use defusedxml (Python) or explicitly disable DTDs/external entities "
            "(lxml resolve_entities=False, libxmljs noent: false) instead of the library default"
        ),
        "specific_risks": [
            "Local file disclosure via external entity",
            "SSRF via external entity",
            "Denial of Service (entity expansion)",
        ],
        "threat_explanation": (
            "Many XML parsers resolve <!ENTITY> declarations by default, including external ones "
            "that read a local file or make an outbound request (file:///etc/passwd, "
            "http://internal-service/). A single crafted <!DOCTYPE> block in an otherwise normal-"
            "looking XML document can exfiltrate local files back into the parsed output or turn "
            "your parser into an SSRF proxy. A nested entity-expansion payload ('billion laughs') "
            "can also exhaust memory/CPU. Always parse untrusted XML with external entities and "
            "DTD processing disabled — don't rely on the library's default configuration."
        ),
    },
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


def get_guidance(technical_category: str, semantic_type: str) -> dict:
    """Combine technical + semantic guidance into a single rendered record."""
    tech = TECHNICAL_RISKS.get(
        technical_category,
        {"risks": ["Validate and sanitize the input"], "severity": "MEDIUM"},
    )
    sem = SEMANTIC_GUIDANCE.get(semantic_type, SEMANTIC_GUIDANCE["FREE_TEXT"])
    severity = tech["severity"]
    return {
        "severity": severity,
        "severity_emoji": SEVERITY_EMOJI[severity],
        "technical_risks": tech["risks"],
        "validation": sem["validation"],
        "validation_regex": sem["validation_regex"],
        "sanitization": sem["sanitization"],
        "specific_risks": sem["specific_risks"],
        "threat_explanation": sem["threat_explanation"],
    }
