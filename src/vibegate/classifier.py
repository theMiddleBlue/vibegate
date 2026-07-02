"""Deterministic, no-LLM classification of Semgrep findings.

Two-stage lookup:
  Stage A  rule_id            -> technical category (where the input goes)
  Stage B  variable/key name  -> semantic type      (what the data is)
  Stage C  fallback           -> FREE_TEXT
"""

from __future__ import annotations

import re

from .models import ClassifiedFinding

# --- Stage A: rule_id -> technical category ---------------------------------

RULE_TO_TECHNICAL = {
    # Python
    "python-cli-arg-sys": "CLI_ARG",
    "python-cli-arg-argparse": "CLI_ARG",
    "python-stdin-input": "STDIN",
    "python-stdin-raw": "STDIN",
    "python-http-body-flask": "HTTP_BODY",
    "python-http-body-fastapi": "HTTP_BODY",
    "python-http-body-django": "HTTP_BODY",
    "python-http-query": "HTTP_QUERY",
    "python-http-header": "HTTP_HEADER",
    "python-env-var": "ENV_VAR",
    "python-file-path-input": "FILE_PATH",
    "python-exec-input": "EXEC_INPUT",
    "python-db-query": "DB_QUERY",
    "python-ssrf": "URL_FETCH",
    "python-ssti": "TEMPLATE_INJECTION",
    "python-insecure-deserialization": "INSECURE_DESERIALIZATION",
    "python-nosql-query": "NOSQL_QUERY",
    "python-path-traversal": "PATH_TRAVERSAL",
    "python-xxe": "XXE",
    "python-xss": "XSS_SINK",
    "python-open-redirect": "OPEN_REDIRECT",
    "python-mass-assignment": "MASS_ASSIGNMENT",
    "python-file-upload": "FILE_UPLOAD",
    # JavaScript / TypeScript
    "js-cli-argv": "CLI_ARG",
    "js-cli-commander": "CLI_ARG",
    "js-stdin-readline": "STDIN",
    "js-http-body-express": "HTTP_BODY",
    "js-http-body-next": "HTTP_BODY",
    "js-http-query": "HTTP_QUERY",
    "js-http-header": "HTTP_HEADER",
    "js-env-var": "ENV_VAR",
    "js-exec-input": "EXEC_INPUT",
    "js-db-query": "DB_QUERY",
    "js-ssrf": "URL_FETCH",
    "js-ssti": "TEMPLATE_INJECTION",
    "js-insecure-deserialization": "INSECURE_DESERIALIZATION",
    "js-nosql-query": "NOSQL_QUERY",
    "js-path-traversal": "PATH_TRAVERSAL",
    "js-xxe": "XXE",
    "js-xss": "XSS_SINK",
    "js-open-redirect": "OPEN_REDIRECT",
    "js-mass-assignment": "MASS_ASSIGNMENT",
    "js-file-upload": "FILE_UPLOAD",
    # Go
    "go-cli-arg": "CLI_ARG",
    "go-stdin": "STDIN",
    "go-http-body": "HTTP_BODY",
    "go-http-query": "HTTP_QUERY",
    "go-http-header": "HTTP_HEADER",
    "go-env-var": "ENV_VAR",
    "go-file-path-input": "FILE_PATH",
    "go-exec-input": "EXEC_INPUT",
    "go-db-query": "DB_QUERY",
    "go-ssrf": "URL_FETCH",
    "go-ssti": "TEMPLATE_INJECTION",
    "go-path-traversal": "PATH_TRAVERSAL",
    "go-xss": "XSS_SINK",
    "go-open-redirect": "OPEN_REDIRECT",
    "go-file-upload": "FILE_UPLOAD",
    # Java
    "java-cli-arg": "CLI_ARG",
    "java-stdin": "STDIN",
    "java-http-body": "HTTP_BODY",
    "java-http-query": "HTTP_QUERY",
    "java-http-header": "HTTP_HEADER",
    "java-env-var": "ENV_VAR",
    "java-file-path-input": "FILE_PATH",
    "java-exec-input": "EXEC_INPUT",
    "java-db-query": "DB_QUERY",
    "java-ssrf": "URL_FETCH",
    "java-ssti": "TEMPLATE_INJECTION",
    "java-insecure-deserialization": "INSECURE_DESERIALIZATION",
    "java-path-traversal": "PATH_TRAVERSAL",
    "java-xxe": "XXE",
    "java-xss": "XSS_SINK",
    "java-open-redirect": "OPEN_REDIRECT",
    "java-file-upload": "FILE_UPLOAD",
    # PHP
    "php-cli-arg": "CLI_ARG",
    "php-stdin": "STDIN",
    "php-http-body": "HTTP_BODY",
    "php-http-query": "HTTP_QUERY",
    "php-http-header": "HTTP_HEADER",
    "php-env-var": "ENV_VAR",
    "php-file-path-input": "FILE_PATH",
    "php-exec-input": "EXEC_INPUT",
    "php-db-query": "DB_QUERY",
    "php-ssrf": "URL_FETCH",
    "php-ssti": "TEMPLATE_INJECTION",
    "php-insecure-deserialization": "INSECURE_DESERIALIZATION",
    "php-path-traversal": "PATH_TRAVERSAL",
    "php-xxe": "XXE",
    "php-xss": "XSS_SINK",
    "php-open-redirect": "OPEN_REDIRECT",
    "php-file-upload": "FILE_UPLOAD",
    # Ruby
    "ruby-cli-arg": "CLI_ARG",
    "ruby-stdin": "STDIN",
    "ruby-http-body": "HTTP_BODY",
    "ruby-http-query": "HTTP_QUERY",
    "ruby-http-header": "HTTP_HEADER",
    "ruby-env-var": "ENV_VAR",
    "ruby-file-path-input": "FILE_PATH",
    "ruby-exec-input": "EXEC_INPUT",
    "ruby-db-query": "DB_QUERY",
    "ruby-ssrf": "URL_FETCH",
    "ruby-ssti": "TEMPLATE_INJECTION",
    "ruby-insecure-deserialization": "INSECURE_DESERIALIZATION",
    "ruby-path-traversal": "PATH_TRAVERSAL",
    "ruby-xxe": "XXE",
    "ruby-xss": "XSS_SINK",
    "ruby-open-redirect": "OPEN_REDIRECT",
    "ruby-mass-assignment": "MASS_ASSIGNMENT",
    "ruby-file-upload": "FILE_UPLOAD",
    # CI/CD config hardening (not tied to a programming language)
    "unpinned-github-action": "UNPINNED_CI_ACTION",
    "github-actions-pull-request-target": "UNSAFE_PR_TRIGGER",
    # Credential logging
    "python-credential-log": "CREDENTIAL",
    "js-credential-log": "CREDENTIAL",
    "go-credential-log": "CREDENTIAL",
    "java-credential-log": "CREDENTIAL",
    "php-credential-log": "CREDENTIAL",
    "ruby-credential-log": "CREDENTIAL",
    # Hardcoded secrets
    "python-hardcoded-secret": "HARDCODED_SECRET",
    "js-hardcoded-secret": "HARDCODED_SECRET",
    "go-hardcoded-secret": "HARDCODED_SECRET",
    "java-hardcoded-secret": "HARDCODED_SECRET",
    "php-hardcoded-secret": "HARDCODED_SECRET",
    "ruby-hardcoded-secret": "HARDCODED_SECRET",
}

# Rules whose finding is intrinsically about a sink consuming a specific kind
# of payload (a URL, a template, a query filter, ...): force the semantic type
# so the guidance always shows the right threat model, regardless of the
# variable name (the name-based stage misses target/uri/endpoint/...).
RULE_FORCED_SEMANTIC = {
    "python-ssrf": "URL",
    "js-ssrf": "URL",
    "python-ssti": "TEMPLATE_STRING",
    "js-ssti": "TEMPLATE_STRING",
    "python-insecure-deserialization": "SERIALIZED_DATA",
    "js-insecure-deserialization": "SERIALIZED_DATA",
    "python-nosql-query": "NOSQL_FILTER",
    "js-nosql-query": "NOSQL_FILTER",
    "python-path-traversal": "FILE_PATH",
    "js-path-traversal": "FILE_PATH",
    "python-xxe": "XML_PAYLOAD",
    "js-xxe": "XML_PAYLOAD",
    "python-xss": "HTML_CONTENT",
    "js-xss": "HTML_CONTENT",
    "python-open-redirect": "REDIRECT_URL",
    "js-open-redirect": "REDIRECT_URL",
    "python-mass-assignment": "JSON_PAYLOAD",
    "js-mass-assignment": "JSON_PAYLOAD",
    "python-file-upload": "FILE_NAME",
    "js-file-upload": "FILE_NAME",
    "go-ssrf": "URL",
    "go-ssti": "TEMPLATE_STRING",
    "go-path-traversal": "FILE_PATH",
    "go-xss": "HTML_CONTENT",
    "go-open-redirect": "REDIRECT_URL",
    "go-file-upload": "FILE_NAME",
    "java-ssrf": "URL",
    "java-ssti": "TEMPLATE_STRING",
    "java-insecure-deserialization": "SERIALIZED_DATA",
    "java-path-traversal": "FILE_PATH",
    "java-xxe": "XML_PAYLOAD",
    "java-xss": "HTML_CONTENT",
    "java-open-redirect": "REDIRECT_URL",
    "java-file-upload": "FILE_NAME",
    "php-ssrf": "URL",
    "php-ssti": "TEMPLATE_STRING",
    "php-insecure-deserialization": "SERIALIZED_DATA",
    "php-path-traversal": "FILE_PATH",
    "php-xxe": "XML_PAYLOAD",
    "php-xss": "HTML_CONTENT",
    "php-open-redirect": "REDIRECT_URL",
    "php-file-upload": "FILE_NAME",
    "ruby-ssrf": "URL",
    "ruby-ssti": "TEMPLATE_STRING",
    "ruby-insecure-deserialization": "SERIALIZED_DATA",
    "ruby-path-traversal": "FILE_PATH",
    "ruby-xxe": "XML_PAYLOAD",
    "ruby-xss": "HTML_CONTENT",
    "ruby-open-redirect": "REDIRECT_URL",
    "ruby-mass-assignment": "JSON_PAYLOAD",
    "ruby-file-upload": "FILE_NAME",
    "unpinned-github-action": "UNPINNED_ACTION_REF",
    "github-actions-pull-request-target": "PULL_REQUEST_TARGET_TRIGGER",
}

# --- Stage B: keyword -> semantic type --------------------------------------

VARNAME_TO_SEMANTIC = {
    # Identity
    "name": "FULL_NAME",
    "full_name": "FULL_NAME",
    "fullname": "FULL_NAME",
    "first_name": "FIRST_NAME",
    "firstname": "FIRST_NAME",
    "last_name": "LAST_NAME",
    "lastname": "LAST_NAME",
    "surname": "LAST_NAME",
    "username": "USERNAME",
    "user_name": "USERNAME",
    "handle": "USERNAME",
    "nickname": "USERNAME",
    "age": "AGE",
    "dob": "DATE_OF_BIRTH",
    "birth": "DATE_OF_BIRTH",
    "birthdate": "DATE_OF_BIRTH",
    "birthday": "DATE_OF_BIRTH",
    "gender": "GENDER",
    "nationality": "NATIONALITY",
    "language": "LANGUAGE_CODE",
    "locale": "LANGUAGE_CODE",
    # Contacts
    "email": "EMAIL",
    "mail": "EMAIL",
    "e_mail": "EMAIL",
    "phone": "PHONE_NUMBER",
    "telephone": "PHONE_NUMBER",
    "tel": "PHONE_NUMBER",
    "mobile": "MOBILE_NUMBER",
    "cell": "MOBILE_NUMBER",
    "cellphone": "MOBILE_NUMBER",
    "fax": "FAX_NUMBER",
    "website": "WEBSITE_URL",
    # Authentication
    "password": "PASSWORD",
    "passwd": "PASSWORD",
    "pwd": "PASSWORD",
    "pass": "PASSWORD",
    "pin": "PIN",
    "otp": "OTP",
    "token": "JWT_TOKEN",
    "access_token": "OAUTH_TOKEN",
    "refresh_token": "OAUTH_TOKEN",
    "api_key": "API_KEY",
    "apikey": "API_KEY",
    "secret": "SECRET_KEY",
    "secret_key": "SECRET_KEY",
    "private_key": "PRIVATE_KEY",
    "passphrase": "PASSPHRASE",
    "session": "SESSION_ID",
    "session_id": "SESSION_ID",
    # Addresses
    "address": "STREET_ADDRESS",
    "street": "STREET_ADDRESS",
    "city": "CITY",
    "town": "CITY",
    "region": "REGION",
    "state": "REGION",
    "province": "REGION",
    "zip": "POSTAL_CODE",
    "zipcode": "POSTAL_CODE",
    "postal_code": "POSTAL_CODE",
    "cap": "POSTAL_CODE",
    "country": "COUNTRY",
    "nation": "COUNTRY",
    "coordinates": "COORDINATES",
    "lat": "COORDINATES",
    "lon": "COORDINATES",
    "latitude": "COORDINATES",
    "longitude": "COORDINATES",
    "timezone": "TIMEZONE",
    "ip": "IP_ADDRESS",
    "ip_address": "IP_ADDRESS",
    # Financial
    "credit_card": "CREDIT_CARD_NUMBER",
    "card_number": "CREDIT_CARD_NUMBER",
    "cvv": "CREDIT_CARD_CVV",
    "cvc": "CREDIT_CARD_CVV",
    "expiry": "CREDIT_CARD_EXPIRY",
    "iban": "BANK_ACCOUNT",
    "bank_account": "BANK_ACCOUNT",
    "swift": "SWIFT_BIC",
    "vat": "VAT_NUMBER",
    "tax_code": "TAX_CODE",
    "fiscal_code": "TAX_CODE",
    "price": "PRICE",
    "amount": "PRICE",
    "cost": "PRICE",
    "currency": "CURRENCY",
    "promo_code": "PROMO_CODE",
    "coupon": "PROMO_CODE",
    # Documents
    "passport": "PASSPORT_NUMBER",
    "ssn": "SSN",
    "driving_license": "DRIVING_LICENSE",
    "health_card": "HEALTH_ID",
    # Content
    "message": "MESSAGE",
    "msg": "MESSAGE",
    "comment": "COMMENT",
    "body": "LONG_TEXT",
    "text": "FREE_TEXT",
    "content": "FREE_TEXT",
    "description": "DESCRIPTION",
    "title": "TITLE",
    "subject": "TITLE",
    "query": "SEARCH_QUERY",
    "search": "SEARCH_QUERY",
    "tag": "TAG",
    "category": "CATEGORY",
    # Numbers
    "id": "NUMERIC_ID",
    "user_id": "NUMERIC_ID",
    "count": "COUNT",
    "quantity": "QUANTITY",
    "qty": "QUANTITY",
    "rating": "RATING",
    "score": "RATING",
    "percentage": "PERCENTAGE",
    # Date / Time
    "date": "DATE",
    "time": "TIME",
    "datetime": "DATETIME",
    "timestamp": "TIMESTAMP",
    "year": "YEAR",
    "month": "MONTH",
    "duration": "DURATION",
    # Web
    "url": "URL",
    "link": "URL",
    "href": "URL",
    "redirect": "REDIRECT_URL",
    "callback": "WEBHOOK_URL",
    "webhook": "WEBHOOK_URL",
    "domain": "DOMAIN",
    "hostname": "HOSTNAME",
    "port": "PORT",
    # Files
    "filename": "FILE_NAME",
    "file_name": "FILE_NAME",
    "path": "FILE_PATH",
    "file_path": "FILE_PATH",
    "filepath": "FILE_PATH",
    "extension": "FILE_EXTENSION",
    # Code / Commands
    "command": "SHELL_COMMAND",
    "cmd": "SHELL_COMMAND",
    "sql": "SQL_QUERY",
    "query_string": "SQL_QUERY",
    "payload": "JSON_PAYLOAD",
    "config": "CONFIG_VALUE",
    "regex": "REGEX",
    "pattern": "REGEX",
}

# Patterns tried in priority order: an explicit key (.get("k") / ["k"]) is the
# strongest semantic signal, then the argparse namespace attribute, then the
# assignment LHS, then a request attribute. (re.findall returns matches by
# position, not by alternation order, so the priority must be explicit.)
_PRIORITY_PATTERNS = (
    re.compile(r"""\.get\(\s*["'](\w+)["']""", re.IGNORECASE),  # .get("key")
    re.compile(r"""\[\s*["'](\w+)["']\s*\]"""),  # ["key"] / $_GET['key']
    re.compile(r"\[\s*:(\w+)\s*\]"),  # Ruby symbol key: params[:key]
    re.compile(
        r"""\.(?:FormValue|PostFormValue|getParameter|getHeader|getParameterValues)\(\s*["'](\w+)["']""",
    ),  # Go/Java accessor-style calls: r.FormValue("key"), request.getParameter("key")
    re.compile(r"parse_args\(\)\.(\w+)"),  # argparse namespace
    re.compile(r"[#$]?\{(\w+)\}"),  # interpolation: f"{x}", "#{x}" (Ruby), `${x}` (JS)
)
_ASSIGN_PATTERN = re.compile(
    r"(\w+)\s*=\s*(?:request|req|sys|os|process|input)\b", re.IGNORECASE
)
_ATTR_PATTERN = re.compile(r"(?:request|req)\.(\w+)", re.IGNORECASE)

# Request attributes that are carriers, not semantic field names.
_ATTR_SKIP = {
    "json",
    "form",
    "args",
    "get",
    "post",
    "headers",
    "params",
    "query",
    "getlist",
    "data",
}

_SKIP_WORDS = {
    "def",
    "get",
    "set",
    "req",
    "res",
    "request",
    "response",
    "return",
    "await",
    "async",
    "import",
    "from",
    "self",
    # Logging/print call names, so credential-log findings extract the
    # logged variable (e.g. "password") instead of the log call itself.
    "print",
    "puts",
    "logger",
    "logging",
    "console",
    "log",
    "info",
    "debug",
    "warn",
    "warning",
    "error",
    "err",
    "critical",
    "fmt",
    "println",
    "printf",
}


def extract_varname(snippet: str) -> str | None:
    """Extract the most likely variable/key name from a Semgrep snippet."""
    for pattern in _PRIORITY_PATTERNS:
        m = pattern.search(snippet)
        if m:
            return m.group(1).lower()

    m = _ASSIGN_PATTERN.search(snippet)
    if m:
        return m.group(1).lower()

    m = _ATTR_PATTERN.search(snippet)
    if m and m.group(1).lower() not in _ATTR_SKIP:
        return m.group(1).lower()

    # Fallback: first meaningful word.
    words = re.findall(r"\b[a-z_]{3,}\b", snippet.lower())
    for w in words:
        if w not in _SKIP_WORDS:
            return w
    return None


# Suppression marker, e.g. `# vibegate-ignore` or `// vibegate-ignore: DB_QUERY,SQL_QUERY`.
# Matched against the raw source line regardless of the language's comment
# syntax, so one regex covers every supported language.
_IGNORE_PATTERN = re.compile(r"vibegate-ignore(?:\s*:\s*([\w,\s]+))?", re.IGNORECASE)


def _is_suppressed(
    content_lines: list[str], line: int, technical: str, semantic: str
) -> bool:
    """A bare marker suppresses every finding on that line; a comma-separated
    category list only suppresses a match against the technical category or
    the semantic type (case-insensitive)."""
    if line < 1 or line > len(content_lines):
        return False
    match = _IGNORE_PATTERN.search(content_lines[line - 1])
    if not match:
        return False
    categories = match.group(1)
    if not categories:
        return True
    wanted = {c.strip().upper() for c in categories.split(",") if c.strip()}
    return technical.upper() in wanted or semantic.upper() in wanted


def _snippet_for(finding: dict, content_lines: list[str]) -> str:
    """Resolve the source snippet for a finding.

    Semgrep OSS often returns ``extra.lines == "requires login"`` instead of the
    matched source, so prefer reconstructing the snippet from the content we
    already hold (via start/end line numbers) and fall back to ``extra.lines``.
    """
    start = finding.get("start", {}).get("line", 0)
    end = finding.get("end", {}).get("line", start)
    if content_lines and start >= 1:
        snippet = "\n".join(content_lines[start - 1 : end]).strip()
        if snippet:
            return snippet
    extra = finding.get("extra", {}).get("lines", "").strip()
    return "" if extra == "requires login" else extra


def classify_findings(
    semgrep_findings: list[dict], file_content: str = ""
) -> list[ClassifiedFinding]:
    """Classify raw Semgrep findings into ``ClassifiedFinding`` objects.

    De-duplicates by ``(technical_category, semantic_type)`` so the same kind of
    input is reported only once.
    """
    classified: list[ClassifiedFinding] = []
    content_lines = file_content.splitlines() if file_content else []

    for finding in semgrep_findings:
        rule_id = finding.get("check_id", "").split(".")[-1]  # local id only
        line = finding.get("start", {}).get("line", 0)
        snippet = _snippet_for(finding, content_lines)

        # Stage A: technical category
        technical = RULE_TO_TECHNICAL.get(rule_id, "UNKNOWN")
        if technical == "UNKNOWN":
            continue

        # Stage B: semantic type from variable name
        varname = extract_varname(snippet)
        semantic: str | None = None
        confidence = "low"

        # A sink-based rule (e.g. SSRF) dictates the semantic type directly —
        # the URL being fetched is what matters, not the variable name.
        forced = RULE_FORCED_SEMANTIC.get(rule_id)
        if forced:
            semantic = forced
            confidence = "high"
        elif varname:
            semantic = VARNAME_TO_SEMANTIC.get(varname)
            if semantic:
                confidence = "high"
            else:
                # Partial match (e.g. "user_email" contains "email").
                for kw, sem in VARNAME_TO_SEMANTIC.items():
                    if kw in varname or varname in kw:
                        semantic = sem
                        confidence = "medium"
                        break

        # Stage C: fallback
        if not semantic:
            semantic = "FREE_TEXT"
            confidence = "low"

        if _is_suppressed(content_lines, line, technical, semantic):
            continue

        classified.append(
            ClassifiedFinding(
                technical_category=technical,
                semantic_type=semantic,
                line=line,
                snippet=snippet,
                confidence=confidence,
                var_name=varname,
            )
        )

    # De-duplicate by (category, semantic type).
    seen: set[tuple[str, str]] = set()
    unique: list[ClassifiedFinding] = []
    for item in classified:
        key = (item.technical_category, item.semantic_type)
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique
