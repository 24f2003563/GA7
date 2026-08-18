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
                {
                    "owner": "actions",
                    "name": "checkout",
                    "ref": "v4"
                },
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
    assert response.get_json() == {
        "decision": "promote",
        "violations": []
    }


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
    assert "EXCESS_PERMISSION" in result["violations"]
    assert "TESTS_INCOMPLETE" in result["violations"]
    assert "ROOT_RUNTIME" in result["violations"]
    assert "CRITICAL_CVE" in result["violations"]
    assert "UNPINNED_IMAGE" in result["violations"]
    assert "SECRET_IN_LAYER" in result["violations"]
