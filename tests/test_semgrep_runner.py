import os
from pathlib import Path

from vibegate.core import RULES_DIR, analyze, resolve_language
from vibegate.models import InputEvent
from vibegate.semgrep_runner import _semgrep_env, resolve_semgrep_cmd

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_resolve_semgrep_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "semgrep"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("VIBEGATE_SEMGREP", str(fake))
    resolve_semgrep_cmd.cache_clear()
    try:
        assert resolve_semgrep_cmd() == [str(fake)]
    finally:
        resolve_semgrep_cmd.cache_clear()


def test_semgrep_env_prepends_binary_dir(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "semgrep"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", "/usr/bin")
    env = _semgrep_env([str(fake)])
    assert env["PATH"].split(os.pathsep)[0] == str(fake.parent)


def test_resolve_language():
    assert resolve_language("a.py") == "python"
    assert resolve_language("a.ts") == "typescript"
    assert resolve_language("a.unknown") is None


def test_analyze_unsupported_language_passes():
    event = InputEvent("Write", "notes.txt", "some content")
    result = analyze(event)
    assert not result.has_findings


def test_analyze_empty_content_passes():
    event = InputEvent("Write", "a.py", "")
    result = analyze(event)
    assert not result.has_findings


def test_analyze_http_fixture_detects_email():
    content = (FIXTURES / "test_http.py").read_text()
    event = InputEvent("Write", "test_http.py", content)
    result = analyze(event)
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    sems = {f.semantic_type for f in result.classified}
    assert "HTTP_BODY" in cats
    assert "EMAIL" in sems
    assert not result.should_block


def test_analyze_ssrf_sink_detected_regardless_of_varname():
    # The variable is named "target", not "url" — only the sink rule can catch it.
    content = (
        "from flask import request\n"
        "import requests\n"
        "def f():\n"
        "    target = request.args.get('target')\n"
        "    return requests.get(target).text\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert result.has_findings
    pairs = {(f.technical_category, f.semantic_type) for f in result.classified}
    assert ("URL_FETCH", "URL") in pairs


def test_analyze_constant_url_not_flagged_as_ssrf():
    content = "import requests\nrequests.get('https://api.example.com')\n"
    result = analyze(InputEvent("Write", "x.py", content))
    assert not any(f.technical_category == "URL_FETCH" for f in result.classified)


import pytest


@pytest.mark.parametrize(
    "snippet",
    [
        "import feedparser\nfeedparser.parse(feed.url)\n",
        "import urllib.request\nurllib.request.urlopen(u)\n",
        "import httpx\nhttpx.stream('GET', u)\n",
        "import aiohttp\naiohttp.ClientSession().get(u)\n",
        "import urllib3\nurllib3.request('GET', u)\n",
    ],
)
def test_analyze_python_ssrf_sinks(snippet):
    result = analyze(InputEvent("Write", "x.py", snippet))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


@pytest.mark.parametrize(
    "snippet",
    [
        "const r = await fetch(u);\n",
        "const r = await axios.get(u);\n",
        "const r = await got.post(u);\n",
        "http.get(u);\n",
    ],
)
def test_analyze_js_ssrf_sinks(snippet):
    result = analyze(InputEvent("Write", "x.ts", snippet))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


def test_analyze_exec_fixture_blocks():
    content = (FIXTURES / "test_exec.py").read_text()
    event = InputEvent("Write", "test_exec.py", content)
    result = analyze(event)
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    assert cats & {"EXEC_INPUT", "DB_QUERY"}
    assert result.should_block
    assert result.block_reason


# --- New vulnerability categories: Python ---


def test_analyze_python_ssti_detected():
    content = (
        "from flask import request, render_template_string\n"
        "tpl = request.form.get('tpl')\n"
        "render_template_string(tpl)\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "TEMPLATE_INJECTION" for f in result.classified)
    assert result.should_block


def test_analyze_python_insecure_deserialization_blocks():
    content = (
        "from flask import request\nimport pickle\n"
        "data = request.get_json()\n"
        "obj = pickle.loads(data)\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(
        f.technical_category == "INSECURE_DESERIALIZATION" for f in result.classified
    )
    assert result.should_block


def test_analyze_python_nosql_query_blocks():
    content = "from flask import request\nusers.find(request.json)\n"
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "NOSQL_QUERY" for f in result.classified)
    assert result.should_block


def test_analyze_python_path_traversal_blocks():
    content = (
        "from flask import request\n"
        "path = request.args.get('path')\n"
        "open(path)\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "PATH_TRAVERSAL" for f in result.classified)
    assert result.should_block


def test_analyze_python_xxe_blocks():
    content = "from flask import request\nimport lxml.etree\nlxml.etree.fromstring(request.data)\n"
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "XXE" for f in result.classified)
    assert result.should_block


def test_analyze_python_xss_blocks():
    content = (
        "from flask import request\nfrom markupsafe import Markup\n"
        "Markup(request.args.get('name'))\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "XSS_SINK" for f in result.classified)
    assert result.should_block


def test_analyze_python_open_redirect_detected_not_blocking():
    content = (
        "from flask import request, redirect\n"
        "target = request.args.get('next')\n"
        "redirect(target)\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "OPEN_REDIRECT" for f in result.classified)
    assert not result.should_block


def test_analyze_python_mass_assignment_detected_not_blocking():
    content = "from flask import request\nUser(**request.json)\n"
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "MASS_ASSIGNMENT" for f in result.classified)
    assert not result.should_block


# --- New vulnerability categories: JavaScript/TypeScript ---


def test_analyze_js_ssti_detected():
    content = "ejs.render(req.body.template);\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "TEMPLATE_INJECTION" for f in result.classified)
    assert result.should_block


def test_analyze_js_insecure_deserialization_blocks():
    content = "serialize.unserialize(req.body.blob);\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(
        f.technical_category == "INSECURE_DESERIALIZATION" for f in result.classified
    )
    assert result.should_block


def test_analyze_js_nosql_query_blocks():
    content = "User.find(req.body);\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "NOSQL_QUERY" for f in result.classified)
    assert result.should_block


def test_analyze_js_path_traversal_blocks():
    content = "fs.readFile(req.body.path, () => {});\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "PATH_TRAVERSAL" for f in result.classified)
    assert result.should_block


def test_analyze_js_xxe_blocks():
    content = "xml2js.parseString(req.body.xml, () => {});\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "XXE" for f in result.classified)
    assert result.should_block


def test_analyze_js_xss_blocks():
    content = "el.innerHTML = req.body.html;\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "XSS_SINK" for f in result.classified)
    assert result.should_block


def test_analyze_js_open_redirect_detected_not_blocking():
    content = "res.redirect(req.query.next);\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "OPEN_REDIRECT" for f in result.classified)
    assert not result.should_block


def test_analyze_js_mass_assignment_detected_not_blocking():
    content = "new User(req.body);\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "MASS_ASSIGNMENT" for f in result.classified)
    assert not result.should_block


# --- New language: Go ---


def test_analyze_go_fixture_blocks():
    content = (FIXTURES / "test_go.go").read_text()
    result = analyze(InputEvent("Write", "test_go.go", content))
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    assert "HTTP_QUERY" in cats
    assert "EXEC_INPUT" in cats
    assert result.should_block


def test_analyze_go_db_query_blocks():
    content = 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE name=\'%s\'", r.FormValue("name")))\n'
    result = analyze(InputEvent("Write", "x.go", content))
    assert any(f.technical_category == "DB_QUERY" for f in result.classified)
    assert result.should_block


def test_analyze_go_ssrf_detected():
    content = 'http.Get(r.URL.Query().Get("url"))\n'
    result = analyze(InputEvent("Write", "x.go", content))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


def test_analyze_go_ssti_detected():
    content = 'template.Must(template.New("x").Parse(r.FormValue("tpl")))\n'
    result = analyze(InputEvent("Write", "x.go", content))
    assert any(f.technical_category == "TEMPLATE_INJECTION" for f in result.classified)
    assert result.should_block


def test_analyze_go_path_traversal_blocks():
    content = 'os.Open(r.FormValue("path"))\n'
    result = analyze(InputEvent("Write", "x.go", content))
    assert any(f.technical_category == "PATH_TRAVERSAL" for f in result.classified)
    assert result.should_block


def test_analyze_go_xss_blocks():
    content = 'safe := template.HTML(r.FormValue("html"))\n'
    result = analyze(InputEvent("Write", "x.go", content))
    assert any(f.technical_category == "XSS_SINK" for f in result.classified)
    assert result.should_block


def test_analyze_go_open_redirect_detected_not_blocking():
    content = 'http.Redirect(w, r, r.URL.Query().Get("next"), 302)\n'
    result = analyze(InputEvent("Write", "x.go", content))
    assert any(f.technical_category == "OPEN_REDIRECT" for f in result.classified)
    assert not result.should_block


# --- New language: Java ---


def test_analyze_java_fixture_blocks():
    content = (FIXTURES / "test_java.java").read_text()
    result = analyze(InputEvent("Write", "test_java.java", content))
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    assert "HTTP_QUERY" in cats
    assert "EXEC_INPUT" in cats
    assert result.should_block


def test_analyze_java_db_query_blocks():
    content = (
        "Statement stmt = conn.createStatement();\n"
        'stmt.executeQuery("SELECT * FROM users WHERE name=\'" + request.getParameter("name") + "\'");\n'
    )
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "DB_QUERY" for f in result.classified)
    assert result.should_block


def test_analyze_java_ssrf_detected():
    content = 'URL u = new URL(request.getParameter("url"));\n'
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


def test_analyze_java_ssti_detected():
    content = "velocityEngine.evaluate(context, request.getParameter(\"tpl\"));\n"
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "TEMPLATE_INJECTION" for f in result.classified)
    assert result.should_block


def test_analyze_java_insecure_deserialization_blocks():
    content = "ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\n"
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(
        f.technical_category == "INSECURE_DESERIALIZATION" for f in result.classified
    )
    assert result.should_block


def test_analyze_java_path_traversal_blocks():
    content = 'File f = new File(request.getParameter("path"));\n'
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "PATH_TRAVERSAL" for f in result.classified)
    assert result.should_block


def test_analyze_java_xxe_blocks():
    content = "builder.parse(request.getInputStream());\n"
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "XXE" for f in result.classified)
    assert result.should_block


def test_analyze_java_xss_blocks():
    content = 'out.println(request.getParameter("html"));\n'
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "XSS_SINK" for f in result.classified)
    assert result.should_block


def test_analyze_java_open_redirect_detected_not_blocking():
    content = 'response.sendRedirect(request.getParameter("next"));\n'
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "OPEN_REDIRECT" for f in result.classified)
    assert not result.should_block


# --- New language: PHP ---


def test_analyze_php_fixture_blocks():
    content = (FIXTURES / "test_php.php").read_text()
    result = analyze(InputEvent("Write", "test_php.php", content))
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    assert "HTTP_QUERY" in cats
    assert "EXEC_INPUT" in cats
    assert result.should_block


def test_analyze_php_db_query_blocks():
    content = "<?php\nmysqli_query($conn, \"SELECT * FROM users WHERE name='\" . $_GET['name'] . \"'\");\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "DB_QUERY" for f in result.classified)
    assert result.should_block


def test_analyze_php_ssrf_detected():
    content = "<?php\nfile_get_contents($_GET['url']);\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


def test_analyze_php_ssti_detected():
    content = '<?php\neval("?>" . $_GET[\'tpl\']);\n'
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "TEMPLATE_INJECTION" for f in result.classified)
    assert result.should_block


def test_analyze_php_insecure_deserialization_blocks():
    content = "<?php\n$data = unserialize($_POST['blob']);\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(
        f.technical_category == "INSECURE_DESERIALIZATION" for f in result.classified
    )
    assert result.should_block


def test_analyze_php_path_traversal_blocks():
    content = "<?php\ninclude($_GET['path']);\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "PATH_TRAVERSAL" for f in result.classified)
    assert result.should_block


def test_analyze_php_xxe_blocks():
    content = "<?php\n$doc->loadXML($_POST['xml']);\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "XXE" for f in result.classified)
    assert result.should_block


def test_analyze_php_xss_blocks():
    content = "<?php\necho $_GET['html'];\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "XSS_SINK" for f in result.classified)
    assert result.should_block


def test_analyze_php_open_redirect_detected_not_blocking():
    content = "<?php\nheader(\"Location: \" . $_GET['next']);\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "OPEN_REDIRECT" for f in result.classified)
    assert not result.should_block


# --- New language: Ruby ---


def test_analyze_ruby_fixture_blocks():
    content = (FIXTURES / "test_ruby.rb").read_text()
    result = analyze(InputEvent("Write", "test_ruby.rb", content))
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    assert "HTTP_BODY" in cats
    assert "EXEC_INPUT" in cats
    assert result.should_block


def test_analyze_ruby_db_query_blocks():
    content = "User.where(params[:filter])\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "DB_QUERY" for f in result.classified)
    assert result.should_block


def test_analyze_ruby_ssrf_detected():
    content = "Net::HTTP.get(params[:url])\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


def test_analyze_ruby_ssti_detected():
    content = "render inline: params[:tpl]\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "TEMPLATE_INJECTION" for f in result.classified)
    assert result.should_block


def test_analyze_ruby_insecure_deserialization_blocks():
    content = "data = Marshal.load(params[:blob])\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(
        f.technical_category == "INSECURE_DESERIALIZATION" for f in result.classified
    )
    assert result.should_block


def test_analyze_ruby_path_traversal_blocks():
    content = "File.open(params[:path])\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "PATH_TRAVERSAL" for f in result.classified)
    assert result.should_block


def test_analyze_ruby_xxe_blocks():
    content = "Nokogiri::XML(params[:xml], nil, nil, Nokogiri::XML::ParseOptions::NOENT)\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "XXE" for f in result.classified)
    assert result.should_block


def test_analyze_ruby_xss_blocks():
    content = "html = params[:html].html_safe\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "XSS_SINK" for f in result.classified)
    assert result.should_block


def test_analyze_ruby_open_redirect_detected_not_blocking():
    content = "redirect_to params[:next]\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "OPEN_REDIRECT" for f in result.classified)
    assert not result.should_block


def test_analyze_ruby_mass_assignment_detected_not_blocking():
    content = "User.new(params)\n"
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "MASS_ASSIGNMENT" for f in result.classified)
    assert not result.should_block


# --- New category: FILE_UPLOAD (unrestricted file upload) ---


def test_analyze_python_file_upload_blocks_split_statement():
    # The classic Flask idiom: filename used two statements after the upload
    # object is fetched — exercises taint propagation through the variable.
    content = (
        "from flask import request\nimport os\n"
        "f = request.files['upload']\n"
        "f.save(os.path.join('/uploads', f.filename))\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert any(f.technical_category == "FILE_UPLOAD" for f in result.classified)
    assert result.should_block


def test_analyze_js_file_upload_blocks():
    content = "const dest = './uploads/' + req.file.originalname;\nfs.writeFile(dest, req.file.buffer, () => {});\n"
    result = analyze(InputEvent("Write", "x.js", content))
    assert any(f.technical_category == "FILE_UPLOAD" for f in result.classified)
    assert result.should_block


def test_analyze_go_file_upload_blocks():
    content = (
        "package main\nimport \"os\"\n"
        "func handler() {\n"
        '\t_, header, _ := r.FormFile("upload")\n'
        '\tos.Create("/uploads/" + header.Filename)\n'
        "}\n"
    )
    result = analyze(InputEvent("Write", "x.go", content))
    assert any(f.technical_category == "FILE_UPLOAD" for f in result.classified)
    assert result.should_block


def test_analyze_java_file_upload_blocks():
    content = (
        "public class T {\n"
        "    void handle(MultipartFile file) throws Exception {\n"
        '        file.transferTo(new File("/uploads/" + file.getOriginalFilename()));\n'
        "    }\n"
        "}\n"
    )
    result = analyze(InputEvent("Write", "x.java", content))
    assert any(f.technical_category == "FILE_UPLOAD" for f in result.classified)
    assert result.should_block


def test_analyze_php_file_upload_blocks():
    content = "<?php\nmove_uploaded_file($_FILES['upload']['tmp_name'], '/uploads/' . $_FILES['upload']['name']);\n"
    result = analyze(InputEvent("Write", "x.php", content))
    assert any(f.technical_category == "FILE_UPLOAD" for f in result.classified)
    assert result.should_block


def test_analyze_ruby_file_upload_blocks():
    content = (
        "file = params[:upload]\n"
        'FileUtils.mv(file.tempfile.path, "/uploads/#{file.original_filename}")\n'
    )
    result = analyze(InputEvent("Write", "x.rb", content))
    assert any(f.technical_category == "FILE_UPLOAD" for f in result.classified)
    assert result.should_block
