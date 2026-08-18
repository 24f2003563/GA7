from flask import Flask, jsonify, request
import re

app = Flask(__name__)

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


@app.post("/release-gate")
def release_gate():
    data = request.get_json(silent=True) or {}
    violations = []

    workflow = data.get("workflow", {}) or {}
    image = data.get("image", {}) or {}

    # ---------------------------------------------------------
    # 1. Permissions must be EXACTLY:
    #    contents: read, packages: write, id-token: none
    #    (no extra scopes allowed)
    # ---------------------------------------------------------
    permissions = workflow.get("permissions", {}) or {}
    if permissions != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. pull_request_target must NEVER be used, regardless of
    #    what the top-level "event" field says. This is checked
    #    unconditionally because pull_request_target is the
    #    actual security hazard (it exposes secrets to forked-PR
    #    code) -- gating this check behind event=="pull_request"
    #    would let a mislabeled event slip through.
    # ---------------------------------------------------------
    if workflow.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # Tests must pass, matrix must be complete, failFast must be false.
    tests_ok = (
        workflow.get("testsPassed") is True
        and workflow.get("matrixComplete") is True
        and workflow.get("failFast") is False
    )
    if not tests_ok:
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 3. Action pinning.
    #    actions/* may use a version tag (e.g. v4).
    #    Every other owner must pin to a full 40-char lowercase
    #    hex commit SHA.
    # ---------------------------------------------------------
    for action in workflow.get("actions", []) or []:
        owner = action.get("owner")
        ref = action.get("ref", "") or ""
        if owner != "actions" and not FULL_SHA.fullmatch(ref):
            violations.append("MUTABLE_ACTION")
            break

    # ---------------------------------------------------------
    # 4. Docker image hardening
    # ---------------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 5. Production-only extra requirements
    # ---------------------------------------------------------
    if data.get("target") == "production":
        if data.get("event") != "push" or data.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"

    return jsonify({
        "decision": decision,
        "violations": violations
    })


@app.get("/")
def health():
    # simple health check so you can confirm the tunnel/host is alive
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)