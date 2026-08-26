import subprocess

from app.services.sast_git import collect_git_context, git_history_secret_findings
from app.services.sast_scanner import scan_source_tree


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def test_history_secret_scan_excludes_identifier_mentions_and_docs(tmp_path):
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "test")
    (tmp_path / "README.md").write_text("Set password and api_key in the environment.\n", encoding="utf-8")
    (tmp_path / "config.js").write_text('api_key = "A8f2K9mQ4xT7vN3pL6sR0cY5"\n', encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "fixture")

    context = collect_git_context(str(tmp_path), include_history_secrets=True)
    findings = git_history_secret_findings(context)

    assert context["history_secret_files"] == ["config.js"]
    assert len(findings) == 1
    assert findings[0].file_path == "config.js"
    assert "A8f2K9" not in findings[0].evidence


def test_javascript_direct_sources_reach_redirect_xss_and_xxe_sinks(tmp_path):
    (tmp_path / "handler.js").write_text(
        "res.redirect(req.query.url);\n"
        "element.innerHTML = req.body.content;\n"
        "parseXmlString(req.body.xml, { noent: true });\n",
        encoding="utf-8",
    )
    (tmp_path / "view.ejs").write_text("<%- user.bio %>\n", encoding="utf-8")

    findings = scan_source_tree(str(tmp_path)).findings
    rules = {item.rule_id for item in findings}

    assert "SAST.TAINT.JAVASCRIPT.REDIRECT" in rules
    assert "SAST.TAINT.JAVASCRIPT.XSS" in rules
    assert "SAST.TAINT.JAVASCRIPT.XXE" in rules
    assert "SAST.XSS.EJS_UNESCAPED_OUTPUT" in rules
    assert "SAST.XML.EXTERNAL_ENTITY_ENABLED" in rules


def test_express_project_checks_find_auth_access_csrf_exposure_and_logging(tmp_path):
    (tmp_path / "routes.js").write_text(
        "router.get('/admin/usersapi', authHandler.isAuthenticated, appHandler.listUsersAPI);\n"
        "router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit);\n"
        "router.post('/login', passport.authenticate('login'));\n",
        encoding="utf-8",
    )
    (tmp_path / "handler.js").write_text(
        "module.exports.userEditSubmit = function(req, res) {\n"
        "  db.User.find({where: {'id': req.body.id}}).then(user => user.save());\n"
        "};\n"
        "module.exports.listUsersAPI = function(req, res) {\n"
        "  db.User.findAll({}).then(users => res.json({users: users}));\n"
        "};\n"
        "module.exports.reset = function(req, res) {\n"
        "  if (req.query.token == md5(req.query.login)) res.send('ok');\n"
        "};\n",
        encoding="utf-8",
    )
    (tmp_path / "view.ejs").write_text("<script>row.innerHTML = user.name;</script>\n", encoding="utf-8")

    findings = scan_source_tree(str(tmp_path)).findings
    rules = {item.rule_id for item in findings}

    assert "SAST.ACCESS.ADMIN_ROUTE_ROLE_MISSING" in rules
    assert "SAST.ACCESS.USER_ID_FROM_BODY" in rules
    assert "SAST.CSRF.STATE_CHANGE_WITHOUT_TOKEN" in rules
    assert "SAST.DATA.FULL_USER_OBJECT_RESPONSE" in rules
    assert "SAST.AUTH.PREDICTABLE_RESET_TOKEN" in rules
    assert "SAST.XSS.DOM_INNERHTML" in rules
    assert "SAST.LOGGING.AUTH_EVENTS_NOT_AUDITED" in rules
