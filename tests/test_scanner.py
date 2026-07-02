"""Tests for the CodeReviewScanner (Phase 1 rules)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from kasra.scanner import CodeReviewScanner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> CodeReviewScanner:
    """A scanner loaded with the Phase 1 P0 rules."""
    from kasra.utils.package import find_data_dir
    rules_path = find_data_dir("rules") / "_code-review-rules.json"
    sc = CodeReviewScanner(rules_path=rules_path)
    count = sc.load_rules()
    assert count > 0, "Failed to load code review rules"
    return sc


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Create a temporary directory simulating a code repository."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    return tmp_path


# ---------------------------------------------------------------------------
# Scanner basics
# ---------------------------------------------------------------------------

class TestScannerBasics:
    """Basic scanner functionality."""

    def test_load_rules(self, scanner):
        assert len(scanner.rules) >= 83
        rule_ids = [r["id"] for r in scanner.rules]
        assert "SEC-01" in rule_ids
        assert "SEC-42" in rule_ids
        assert "IAC-01" in rule_ids
        assert "IAC-17" in rule_ids

    def test_scan_empty_directory(self, scanner, tmp_repo):
        result = scanner.scan(tmp_repo)
        assert result.files_scanned == 0
        assert result.total_findings == 0
        assert result.error is None

    def test_scan_nonexistent_path(self, scanner):
        result = scanner.scan("/nonexistent/path")
        assert result.error is not None

    def test_scan_no_rules_loaded(self):
        sc = CodeReviewScanner(rules_path="nonexistent.json")
        with pytest.raises(FileNotFoundError):
            sc.load_rules()
        result = sc.scan("/tmp")
        assert result.error is not None
        assert "No rules loaded" in result.error


# ---------------------------------------------------------------------------
# SEC-01: Hardcoded Cloud Credentials
# ---------------------------------------------------------------------------

class TestSEC01HardcodedCredentials:
    """SEC-01: Hardcoded Cloud Credentials."""

    def test_aws_key(self, scanner, tmp_repo):
        f = tmp_repo / "config.py"
        f.write_text("aws_key = 'AKIAIOSFODNN7EXAMPLE'\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-01" for f in result.findings)

    def test_github_token(self, scanner, tmp_repo):
        f = tmp_repo / "config.py"
        f.write_text("github_token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd'\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-01" for f in result.findings)

    def test_private_key(self, scanner, tmp_repo):
        f = tmp_repo / "id_rsa"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-01" for f in result.findings)

    def test_openai_key(self, scanner, tmp_repo):
        f = tmp_repo / ".env"
        f.write_text("OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr678stu901vwx\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-01" for f in result.findings)

    def test_clean_file(self, scanner, tmp_repo):
        f = tmp_repo / "hello.py"
        f.write_text("print('hello world')\n")
        result = scanner.scan(tmp_repo)
        assert not any(f.rule_id == "SEC-01" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-02: Hardcoded Passwords / Connection Strings
# ---------------------------------------------------------------------------

class TestSEC02ConnectionStrings:
    """SEC-02: Hardcoded Passwords / Connection Strings."""

    def test_database_url(self, scanner, tmp_repo):
        f = tmp_repo / "settings.py"
        f.write_text("DATABASE_URL = 'postgresql://user:secret123@localhost:5432/db'\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-02" for f in result.findings)

    def test_redis_url(self, scanner, tmp_repo):
        f = tmp_repo / "cache.py"
        f.write_text("redis_url = 'redis://:password@localhost:6379/0'\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-02" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-05: SQL Injection
# ---------------------------------------------------------------------------

class TestSEC05SQLInjection:
    """SEC-05: SQL Injection."""

    def test_string_concat(self, scanner, tmp_repo):
        f = tmp_repo / "db_query.py"
        f.write_text("query = 'SELECT * FROM users WHERE id = ' + user_input\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-05" for f in result.findings)

    def test_f_string(self, scanner, tmp_repo):
        f = tmp_repo / "db_query.py"
        f.write_text("cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-05" for f in result.findings)

    def test_parameterized_safe(self, scanner, tmp_repo):
        f = tmp_repo / "db_query.py"
        f.write_text("cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n")
        result = scanner.scan(tmp_repo)
        assert not any(f.rule_id == "SEC-05" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-07: OS Command Injection
# ---------------------------------------------------------------------------

class TestSEC07CommandInjection:
    """SEC-07: OS Command Injection."""

    def test_subprocess_shell(self, scanner, tmp_repo):
        f = tmp_repo / "run.py"
        f.write_text("subprocess.call('ping ' + host, shell=True)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-07" for f in result.findings)

    def test_runtime_exec(self, scanner, tmp_repo):
        f = tmp_repo / "Execute.java"
        f.write_text("Runtime.getRuntime().exec(\"ping \" + host);\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-07" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-08: Unsafe Deserialization
# ---------------------------------------------------------------------------

class TestSEC08Deserialization:
    """SEC-08: Unsafe Deserialization."""

    def test_pickle(self, scanner, tmp_repo):
        f = tmp_repo / "load_data.py"
        f.write_text("data = pickle.loads(user_input)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-08" for f in result.findings)

    def test_yaml_load(self, scanner, tmp_repo):
        f = tmp_repo / "config.py"
        f.write_text("data = yaml.load(content, Loader=yaml.Loader)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-08" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-14: Code Injection (eval/exec)
# ---------------------------------------------------------------------------

class TestSEC14CodeInjection:
    """SEC-14: Code Injection."""

    def test_eval_input(self, scanner, tmp_repo):
        f = tmp_repo / "calc.py"
        f.write_text("result = eval(user_input)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-14" for f in result.findings)

    def test_exec_request(self, scanner, tmp_repo):
        f = tmp_repo / "exec_code.py"
        f.write_text("exec(request.body['code'])\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-14" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-15: XSS
# ---------------------------------------------------------------------------

class TestSEC15XSS:
    """SEC-15: XSS."""

    def test_inner_html(self, scanner, tmp_repo):
        f = tmp_repo / "app.js"
        f.write_text("element.innerHTML = userInput;\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-15" for f in result.findings)

    def test_dangerously_set_html(self, scanner, tmp_repo):
        f = tmp_repo / "Component.jsx"
        f.write_text('<div dangerouslySetInnerHTML={{__html: userContent}} />\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-15" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-19: SSRF
# ---------------------------------------------------------------------------

class TestSEC19SSRF:
    """SEC-19: SSRF."""

    def test_requests_user_url(self, scanner, tmp_repo):
        f = tmp_repo / "fetch.py"
        f.write_text("response = requests.get(user_url)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-19" for f in result.findings)

    def test_axios_user_url(self, scanner, tmp_repo):
        f = tmp_repo / "fetch.js"
        f.write_text("const res = await axios.get(userInput);\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-19" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-23: File Inclusion
# ---------------------------------------------------------------------------

class TestSEC23FileInclusion:
    """SEC-23: File Inclusion."""

    def test_include_get(self, scanner, tmp_repo):
        f = tmp_repo / "index.php"
        f.write_text("<?php include($_GET['page']); ?>")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-23" for f in result.findings)

    def test_fs_readfile(self, scanner, tmp_repo):
        f = tmp_repo / "read.js"
        f.write_text("fs.readFile(userInput, 'utf8', callback);\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-23" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-37: Debug Mode
# ---------------------------------------------------------------------------

class TestSEC37DebugMode:
    """SEC-37: Debug Mode."""

    def test_debug_true(self, scanner, tmp_repo):
        f = tmp_repo / "settings.py"
        f.write_text("DEBUG = True\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-37" for f in result.findings)

    def test_flask_debug(self, scanner, tmp_repo):
        f = tmp_repo / "app.py"
        f.write_text("app.run(debug=True)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-37" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-45: Path Traversal
# ---------------------------------------------------------------------------

class TestSEC45PathTraversal:
    """SEC-45: Path Traversal."""

    def test_os_path_join(self, scanner, tmp_repo):
        f = tmp_repo / "file_ops.py"
        f.write_text("path = os.path.join(base_dir, user_filename)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-45" for f in result.findings)

    def test_php_get(self, scanner, tmp_repo):
        f = tmp_repo / "download.php"
        f.write_text("$content = file_get_contents($_GET['file']);")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-45" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-51: Unsafe Command Execution
# ---------------------------------------------------------------------------

class TestSEC51CommandExecution:
    """SEC-51: Unsafe Command Execution."""

    def test_os_system(self, scanner, tmp_repo):
        f = tmp_repo / "utils.py"
        f.write_text("os.system('rm -rf /tmp/' + dir_name)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-51" for f in result.findings)

    def test_child_process(self, scanner, tmp_repo):
        f = tmp_repo / "exec.js"
        f.write_text("child_process.exec('ls -la', callback);\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-51" for f in result.findings)


# ---------------------------------------------------------------------------
# SEC-40: CVE Dependencies
# ---------------------------------------------------------------------------

class TestSEC40CVEDeps:
    """SEC-40: Known CVE Dependencies."""

    def test_vulnerable_lodash(self, scanner, tmp_repo):
        f = tmp_repo / "package.json"
        f.write_text('{"dependencies": {"lodash": "^4.17.15"}}\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-40" for f in result.findings)

    def test_safe_lodash(self, scanner, tmp_repo):
        # SEC-40 now does proper semver comparison via _check_cve Python checker.
        # 4.17.21 >= 4.17.21 (fixed) → should NOT trigger.
        f = tmp_repo / "package.json"
        f.write_text('{"dependencies": {"lodash": "^4.17.21"}}\n')
        result = scanner.scan(tmp_repo)
        assert not any(f.rule_id == "SEC-40" for f in result.findings)

    def test_vulnerable_log4j(self, scanner, tmp_repo):
        f = tmp_repo / "pom.xml"
        f.write_text('<dependency><groupId>org.apache.logging.log4j</groupId>'
                     '<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-40" for f in result.findings)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestScannerEdgeCases:
    """Edge cases for the scanner."""

    def test_binary_file_skipped(self, scanner, tmp_repo):
        f = tmp_repo / "image.png"
        f.write_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR')
        result = scanner.scan(tmp_repo)
        assert result.files_skipped > 0

    def test_git_directory_skipped(self, scanner, tmp_repo):
        (tmp_repo / ".git").mkdir()
        (tmp_repo / ".git" / "config").write_text("test")
        result = scanner.scan(tmp_repo)
        assert result.files_scanned == 0

    def test_multiple_findings_same_file(self, scanner, tmp_repo):
        f = tmp_repo / "creds.py"
        f.write_text(
            "aws = 'AKIAIOSFODNN7EXAMPLE'\n"
            "github = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd'\n"
        )
        result = scanner.scan(tmp_repo)
        sec01 = [ff for ff in result.findings if ff.rule_id == "SEC-01"]
        assert len(sec01) >= 2

    def test_no_false_positive_clean_file(self, scanner, tmp_repo):
        f = tmp_repo / "calculator.py"
        f.write_text(
            "def add(a, b):\n"
            "    return a + b\n"
            "def subtract(a, b):\n"
            "    return a - b\n"
            "print(add(10, 20))\n"
        )
        result = scanner.scan(tmp_repo)
        # Only check non-stub findings (stub = cross-file rules not yet implemented)
        real_findings = [ff for ff in result.findings if ff.confidence > 0.2]
        assert len(real_findings) == 0


# ---------------------------------------------------------------------------
# Phase 2: SEC-06 NoSQL Injection
# ---------------------------------------------------------------------------

class TestSEC06NoSQL:
    """SEC-06: NoSQL Injection."""

    def test_mongo_where(self, scanner, tmp_repo):
        f = tmp_repo / "query.py"
        f.write_text("db.collection.find({'$where': 'this.credits == ' + user_input})\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-06" for f in result.findings)

    def test_find_by_id_and_update(self, scanner, tmp_repo):
        f = tmp_repo / "query.js"
        f.write_text("User.findByIdAndUpdate(userInput, {role: 'admin'})\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-06" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-10 LDAP Injection
# ---------------------------------------------------------------------------

class TestSEC10LDAP:
    """SEC-10: LDAP Injection."""

    def test_ldap_concat(self, scanner, tmp_repo):
        f = tmp_repo / "auth.java"
        f.write_text('String filter = "uid=" + userInput;\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-10" for f in result.findings)

    def test_dir_context(self, scanner, tmp_repo):
        f = tmp_repo / "ldap.py"
        f.write_text("ctx.search('dc=example,dc=com', 'uid=' + username)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-10" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-11 SSTI
# ---------------------------------------------------------------------------

class TestSEC11SSTI:
    """SEC-11: SSTI."""

    def test_render_template_string(self, scanner, tmp_repo):
        f = tmp_repo / "app.py"
        f.write_text("return render_template_string(f'Hello {user_name}')\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-11" for f in result.findings)

    def test_handlebars_compile(self, scanner, tmp_repo):
        f = tmp_repo / "template.js"
        f.write_text("Handlebars.compile(userInput + 'template')\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-11" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-13 Prototype Pollution
# ---------------------------------------------------------------------------

class TestSEC13ProtoPollution:
    """SEC-13: Prototype Pollution."""

    def test_merge_body(self, scanner, tmp_repo):
        f = tmp_repo / "merge.js"
        f.write_text("_.merge(defaults, req.body)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-13" for f in result.findings)

    def test_proto_assign(self, scanner, tmp_repo):
        f = tmp_repo / "assign.js"
        f.write_text("target['__proto__'] = malicious\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-13" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-16 CORS
# ---------------------------------------------------------------------------

class TestSEC16CORS:
    """SEC-16: CORS Misconfiguration."""

    def test_django_cors(self, scanner, tmp_repo):
        f = tmp_repo / "settings.py"
        f.write_text("CORS_ALLOW_ALL_ORIGINS = True\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-16" for f in result.findings)

    def test_express_cors(self, scanner, tmp_repo):
        f = tmp_repo / "server.js"
        f.write_text("cors({origin: true, credentials: true})\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-16" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-20 Open Redirect
# ---------------------------------------------------------------------------

class TestSEC20Redirect:
    """SEC-20: Open Redirect."""

    def test_django_redirect(self, scanner, tmp_repo):
        f = tmp_repo / "views.py"
        f.write_text("return redirect(request.GET.get('next'))\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-20" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-24 Mass Assignment
# ---------------------------------------------------------------------------

class TestSEC24MassAssignment:
    """SEC-24: Mass Assignment."""

    def test_create_req_body(self, scanner, tmp_repo):
        f = tmp_repo / "users.js"
        f.write_text("User.create(req.body)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-24" for f in result.findings)

    def test_assign_attributes(self, scanner, tmp_repo):
        f = tmp_repo / "users.rb"
        f.write_text("User.create(params[:user])\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-24" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-25 JWT
# ---------------------------------------------------------------------------

class TestSEC25JWT:
    """SEC-25: JWT Security Defects."""

    def test_alg_none(self, scanner, tmp_repo):
        f = tmp_repo / "auth.py"
        f.write_text('jwt.encode(payload, key, algorithm="none")\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-25" for f in result.findings)

    def test_weak_secret(self, scanner, tmp_repo):
        f = tmp_repo / "config.py"
        f.write_text('JWT_SECRET = "secret"\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-25" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-32 Weak Crypto
# ---------------------------------------------------------------------------

class TestSEC32WeakCrypto:
    """SEC-32: Weak Cryptographic Algorithms."""

    def test_md5(self, scanner, tmp_repo):
        f = tmp_repo / "hash.py"
        f.write_text("hashlib.md5(data).hexdigest()\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-32" for f in result.findings)

    def test_sha1(self, scanner, tmp_repo):
        f = tmp_repo / "sign.java"
        f.write_text('MessageDigest.getInstance("SHA1")\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-32" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-33 Insecure Randomness
# ---------------------------------------------------------------------------

class TestSEC33Random:
    """SEC-33: Insecure Randomness."""

    def test_import_random(self, scanner, tmp_repo):
        f = tmp_repo / "token.py"
        f.write_text("import random\nsecret = random.randint(0, 999999)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-33" for f in result.findings)

    def test_math_random(self, scanner, tmp_repo):
        f = tmp_repo / "client.js"
        f.write_text("const id = Math.random().toString(36);\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-33" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-34 TLS Disabled
# ---------------------------------------------------------------------------

class TestSEC34TLS:
    """SEC-34: TLS/SSL Validation Disabled."""

    def test_verify_false(self, scanner, tmp_repo):
        f = tmp_repo / "client.py"
        f.write_text("requests.get(url, verify=False)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-34" for f in result.findings)

    def test_insecure_skip(self, scanner, tmp_repo):
        f = tmp_repo / "client.go"
        f.write_text("InsecureSkipVerify: true\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-34" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: SEC-38 Insecure Defaults
# ---------------------------------------------------------------------------

class TestSEC38Defaults:
    """SEC-38: Insecure Configuration Defaults."""

    def test_weak_secret_key(self, scanner, tmp_repo):
        f = tmp_repo / ".env"
        f.write_text('SECRET_KEY = "changeme"\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-38" for f in result.findings)

    def test_allowed_hosts_star(self, scanner, tmp_repo):
        f = tmp_repo / "settings.py"
        f.write_text("ALLOWED_HOSTS = ['*']\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-38" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: IAC-01 Docker Security
# ---------------------------------------------------------------------------

class TestIAC01Docker:
    """IAC-01: Dockerfile Security."""

    def test_latest_tag(self, scanner, tmp_repo):
        f = tmp_repo / "Dockerfile"
        f.write_text("FROM python:latest\nRUN pip install flask\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-01" for f in result.findings)

    def test_root_user(self, scanner, tmp_repo):
        f = tmp_repo / "Dockerfile"
        f.write_text("FROM python:3.11\nUSER root\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-01" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: IAC-04 K8s Security
# ---------------------------------------------------------------------------

class TestIAC04K8s:
    """IAC-04: K8s Workload Security."""

    def test_privileged(self, scanner, tmp_repo):
        f = tmp_repo / "deployment.yaml"
        f.write_text("spec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-04" for f in result.findings)

    def test_host_network(self, scanner, tmp_repo):
        f = tmp_repo / "pod.yaml"
        f.write_text("apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-04" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 2: IAC-08 Terraform Security
# ---------------------------------------------------------------------------

class TestIAC08Terraform:
    """IAC-08: Terraform Storage Security."""

    def test_public_acl(self, scanner, tmp_repo):
        f = tmp_repo / "s3.tf"
        f.write_text('resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-08" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-12 Header Injection
# ---------------------------------------------------------------------------

class TestSEC12HeaderInjection:
    def test_set_header(self, scanner, tmp_repo):
        f = tmp_repo / "app.py"
        f.write_text('response.setHeader("Location", user_input)\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-12" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-26 Security Response Headers
# ---------------------------------------------------------------------------

class TestSEC26SecurityHeaders:
    def test_no_csp(self, scanner, tmp_repo):
        f = tmp_repo / "config.py"
        f.write_text('Content-Security-Policy: default-src self\n')
        result = scanner.scan(tmp_repo)
        # Pattern matches presence of CSP header name
        findings = [ff for ff in result.findings if ff.rule_id == "SEC-26"]
        assert any("Content-Security-Policy" in ff.matched_text for ff in findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-27 Session Management
# ---------------------------------------------------------------------------

class TestSEC27Session:
    def test_session_id_from_user(self, scanner, tmp_repo):
        f = tmp_repo / "session.py"
        f.write_text('session.id = str(user_id)\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-27" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-29 WebSocket
# ---------------------------------------------------------------------------

class TestSEC29WebSocket:
    def test_ws_not_wss(self, scanner, tmp_repo):
        f = tmp_repo / "socket.js"
        f.write_text('const ws = new WebSocket("ws://example.com/socket")\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-29" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-30 gRPC
# ---------------------------------------------------------------------------

class TestSEC30gRPC:
    def test_grpc_insecure(self, scanner, tmp_repo):
        f = tmp_repo / "grpc.go"
        f.write_text('grpc.WithInsecure()\n')
        result = scanner.scan(tmp_repo)
        # Pattern matches insecure.NewCredentials()
        assert any(f.rule_id == "SEC-30" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-31 GraphQL
# ---------------------------------------------------------------------------

class TestSEC31GraphQL:
    def test_introspection_enabled(self, scanner, tmp_repo):
        f = tmp_repo / "graphql.py"
        f.write_text('introspection: True\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-31" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-49 Memory Safety
# ---------------------------------------------------------------------------

class TestSEC49MemorySafety:
    def test_gets(self, scanner, tmp_repo):
        f = tmp_repo / "vuln.c"
        f.write_text('gets(buffer);\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-49" for f in result.findings)

    def test_strcpy(self, scanner, tmp_repo):
        f = tmp_repo / "copy.c"
        f.write_text('strcpy(dest, src);\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-49" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-50 Error Handling Leak
# ---------------------------------------------------------------------------

class TestSEC50ErrorLeak:
    def test_traceback(self, scanner, tmp_repo):
        f = tmp_repo / "error.py"
        f.write_text('traceback.format_exc()\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-50" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: SEC-61 Insecure Local Storage
# ---------------------------------------------------------------------------

class TestSEC61MobileStorage:
    def test_shared_prefs_token(self, scanner, tmp_repo):
        f = tmp_repo / "storage.kt"
        f.write_text('SharedPreferences.putString("token", authToken)\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-61" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: IAC-02 Docker Compose
# ---------------------------------------------------------------------------

class TestIAC02Compose:
    def test_host_network(self, scanner, tmp_repo):
        f = tmp_repo / "docker-compose.yml"
        f.write_text('network_mode: host\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-02" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: IAC-06 K8s RBAC
# ---------------------------------------------------------------------------

class TestIAC06RBAC:
    def test_wildcard_verbs(self, scanner, tmp_repo):
        f = tmp_repo / "rbac.yaml"
        f.write_text('apiGroups: ["*"]\nresources: ["*"]\nverbs: ["*"]\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-06" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: IAC-09 Terraform Network
# ---------------------------------------------------------------------------

class TestIAC09TerraformNetwork:
    def test_open_sg(self, scanner, tmp_repo):
        f = tmp_repo / "sg.tf"
        f.write_text('cidr_blocks = ["0.0.0.0/0"]\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-09" for f in result.findings)


# ---------------------------------------------------------------------------
# Phase 3+4: IAC-12 Ansible
# ---------------------------------------------------------------------------

class TestIAC12Ansible:
    def test_ansible_password(self, scanner, tmp_repo):
        f = tmp_repo / "playbook.yml"
        f.write_text('ansible_become_password: "supersecret"\n')
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "IAC-12" for f in result.findings)


# ---------------------------------------------------------------------------
# New Python checkers: SEC-18, SEC-22, SEC-39, SEC-52~59
# ---------------------------------------------------------------------------

class TestAuthMissing:
    """SEC-18: Authentication Missing."""

    def test_django_route_no_auth(self, scanner, tmp_repo):
        f = tmp_repo / "views.py"
        f.write_text("@app.route('/api/users')\ndef get_users():\n    return User.query.all()\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-18" for f in result.findings)

    def test_flask_route_no_auth(self, scanner, tmp_repo):
        f = tmp_repo / "app.py"
        f.write_text("@app.get('/api/data')\ndef get_data():\n    return 'ok'\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-18" for f in result.findings)


class TestIntegerOverflow:
    """SEC-53: Integer Overflow."""

    def test_balance_sub_no_guard(self, scanner, tmp_repo):
        f = tmp_repo / "payment.py"
        f.write_text("def deduct(amount):\n    balance -= amount\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-53" for f in result.findings)


class TestPlaintextPassword:
    """SEC-55: Plaintext Password Storage."""

    def test_password_assign(self, scanner, tmp_repo):
        f = tmp_repo / "user.py"
        f.write_text("user.password = 'supersecret'\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-55" for f in result.findings)


class TestWeakPasswordPolicy:
    """SEC-56: Weak Password Policy."""

    def test_min_length_4(self, scanner, tmp_repo):
        f = tmp_repo / "register.py"
        f.write_text("min_length = 4\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-56" for f in result.findings)


class TestAuditLogMissing:
    """SEC-57: Audit Log Missing."""

    def test_delete_users_no_audit(self, scanner, tmp_repo):
        f = tmp_repo / "admin.sql"
        f.write_text("DELETE FROM users WHERE id = 1;\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-57" for f in result.findings)


class TestBruteForce:
    """SEC-58: Brute Force Protection Missing."""

    def test_login_no_rate_limit(self, scanner, tmp_repo):
        f = tmp_repo / "auth.py"
        f.write_text("def login(username, password):\n    user = authenticate(username, password)\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-58" for f in result.findings)


class TestInsecureDeletion:
    """SEC-59: Incomplete Data Deletion."""

    def test_soft_delete_no_cleanup(self, scanner, tmp_repo):
        f = tmp_repo / "cleanup.py"
        f.write_text("is_deleted = True\n")
        result = scanner.scan(tmp_repo)
        assert any(f.rule_id == "SEC-59" for f in result.findings)


# ---------------------------------------------------------------------------
# Incremental scanner tests
# ---------------------------------------------------------------------------

class TestIncrementalScanner:
    """IncrementalScanner: cache-based skip for unchanged files."""

    def test_first_scan_full(self, scanner, tmp_repo):
        from kasra.scanner.incremental import IncrementalScanner
        inc = IncrementalScanner(scanner, cache_dir=tmp_repo / ".kasra-cache")
        (tmp_repo / "secret.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        result = inc.scan(tmp_repo)
        assert result.files_scanned > 0
        assert result.total_findings > 0

    def test_second_scan_skips_unchanged(self, scanner, tmp_repo):
        from kasra.scanner.incremental import IncrementalScanner
        inc = IncrementalScanner(scanner, cache_dir=tmp_repo / ".kasra-cache")
        (tmp_repo / "secret.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        r1 = inc.scan(tmp_repo)
        assert r1.files_scanned > 0
        r2 = inc.scan(tmp_repo)
        assert r2.files_skipped >= r1.files_scanned

    def test_scan_finds_new_files(self, scanner, tmp_repo):
        from kasra.scanner.incremental import IncrementalScanner
        inc = IncrementalScanner(scanner, cache_dir=tmp_repo / ".kasra-cache")
        (tmp_repo / "secret.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        inc.scan(tmp_repo)
        (tmp_repo / "more_secret.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        r2 = inc.scan(tmp_repo)
        assert r2.files_scanned >= 1

    def test_scan_finds_modified_files(self, scanner, tmp_repo):
        from kasra.scanner.incremental import IncrementalScanner
        inc = IncrementalScanner(scanner, cache_dir=tmp_repo / ".kasra-cache")
        f = tmp_repo / "secret.py"
        f.write_text("x = 1\n")
        inc.scan(tmp_repo)
        f.write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        import time; time.sleep(0.01)
        r2 = inc.scan(tmp_repo)
        assert r2.files_scanned >= 1

    def test_clear_cache(self, scanner, tmp_repo):
        from kasra.scanner.incremental import IncrementalScanner
        inc = IncrementalScanner(scanner, cache_dir=tmp_repo / ".kasra-cache")
        (tmp_repo / "secret.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        inc.scan(tmp_repo)
        assert inc.clear_cache() > 0

    def test_no_false_positive_clean(self, scanner, tmp_repo):
        from kasra.scanner.incremental import IncrementalScanner
        inc = IncrementalScanner(scanner, cache_dir=tmp_repo / ".kasra-cache")
        f = tmp_repo / "calc.py"
        f.write_text("def add(a, b):\n    return a + b\n")
        result = inc.scan(tmp_repo)
        real = [ff for ff in result.findings if ff.confidence > 0.2]
        assert len(real) == 0
