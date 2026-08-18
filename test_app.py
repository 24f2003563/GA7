from app import app


def client():
    app.config["TESTING"] = True
    return app.test_client()


def safe_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/test",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none"
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {
                    "owner": "thirdparty",
                    "name": "example",
                    "ref": "0123456789abcdef0123456789abcdef01234567"
                }
            ]
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True
        }
    }


def test_safe_request_promotes():
    response = client().post("/release-gate", json=safe_payload())
    assert response.status_code == 200
    assert response.get_json() == {"decision": "promote", "violations": []}


def test_multiple_failures():
    data = safe_payload()
    data["workflow"]["permissions"]["issues"] = "bad"
    data["workflow"]["testsPassed"] = False
    data["workflow"]["failFast"] = True
    data["image"]["runsAsRoot"] = True
    data["image"]["criticalVulnerabilities"] = 2
    data["image"]["digestPinned"] = False
    data["image"]["secretMode"] = "copy"

    response = client().post("/release-gate", json=data)
    result = response.get_json()

    assert result["decision"] == "block"
    for code in [
        "EXCESS_PERMISSION", "TESTS_INCOMPLETE", "ROOT_RUNTIME",
        "CRITICAL_CVE", "UNPINNED_IMAGE", "SECRET_IN_LAYER"
    ]:
        assert code in result["violations"]


def test_pull_request_target_flagged_regardless_of_event():
    data = safe_payload()
    data["event"] = "push"
    data["workflow"]["trigger"] = "pull_request_target"
    response = client().post("/release-gate", json=data)
    assert "UNSAFE_PR_TRIGGER" in response.get_json()["violations"]


def test_mutable_action_flagged():
    data = safe_payload()
    data["workflow"]["actions"][1]["ref"] = "v1"
    response = client().post("/release-gate", json=data)
    assert "MUTABLE_ACTION" in response.get_json()["violations"]


def test_production_requires_push_main_and_approval():
    data = safe_payload()
    data["target"] = "production"
    data["event"] = "push"
    data["ref"] = "refs/heads/main"
    data["workflow"]["trigger"] = "push"
    response = client().post("/release-gate", json=data)
    result = response.get_json()
    assert "APPROVAL_REQUIRED" in result["violations"]

    data["workflow"]["environmentApproval"] = True
    response = client().post("/release-gate", json=data)
    result = response.get_json()
    assert "APPROVAL_REQUIRED" not in result["violations"]
    assert "INVALID_PRODUCTION_REF" not in result["violations"]