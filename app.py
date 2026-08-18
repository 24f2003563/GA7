from flask import Flask, jsonify, request
import re

app = Flask(__name__)

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


@app.post("/release-gate")
def release_gate():
    data = request.get_json()
    violations = []

    workflow = data.get("workflow", {})
    image = data.get("image", {})

    # ---------------------------------------------------------
    # 1. Permissions must be EXACTLY:
    # contents: read
    # packages: write
    # id-token: none
    # ---------------------------------------------------------
    permissions = workflow.get("permissions", {})

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. Pull requests must use pull_request, not
    # pull_request_target.
    #
    # Tests must pass, matrix must be complete, and
    # failFast must be false.
    # ---------------------------------------------------------
    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    if workflow.get("testsPassed") is not True:
        violations.append("TESTS_INCOMPLETE")

    if workflow.get("matrixComplete") is not True:
        violations.append("TESTS_INCOMPLETE")

    if workflow.get("failFast") is not False:
        violations.append("TESTS_INCOMPLETE")

    # Avoid returning TESTS_INCOMPLETE three times.
    # The assignment asks for applicable violation codes,
    # not duplicate copies of the same code.
    violations = list(dict.fromkeys(violations))

    # ---------------------------------------------------------
    # 3. Check GitHub Actions references.
    #
    # actions/* may use a version tag.
    # Everything else must use a 40-character lowercase SHA.
    # ---------------------------------------------------------
    for action in workflow.get("actions", []):
        owner = action.get("owner")
        ref = action.get("ref", "")

        if owner != "actions" and not FULL_SHA.fullmatch(ref):
            violations.append("MUTABLE_ACTION")
            break

    # ---------------------------------------------------------
    # 4. Docker image checks
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
    # 5. Production requirements
    #
    # Production must be:
    # push -> refs/heads/main
    # and have environmentApproval == true
    # ---------------------------------------------------------
    if data.get("target") == "production":
        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while preserving order.
    violations = list(dict.fromkeys(violations))

    decision = "promote" if not violations else "block"

    return jsonify({
        "decision": decision,
        "violations": violations
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
