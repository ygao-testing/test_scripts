import pytest


@pytest.fixture
def severity_list(request):
    """Severity list fixture"""
    return request.param


@pytest.fixture
def severity_payload(severity_list):
    """Fixture to generate severity payload inside Filters for query card execution"""
    payload = []
    for severity in severity_list:
        payload.append({
            "value": severity,
            "filterGroup": "eq"
        })
    return payload


@pytest.fixture
def cve_status_list(request):
    """CVE status list fixture"""
    return request.param


@pytest.fixture
def cve_status_payload(cve_status_list):
    """Fixture to generate cve status payload inside Filters for query card execution"""
    payload = []
    for cve_status in cve_status_list:
        payload.append({
            "value": cve_status,
            "filterGroup": "include"
        })
    return payload


@pytest.fixture
def fixability_list(request):
    """Fixability list fixture"""
    return request.param


@pytest.fixture
def fixability_payload(fixability_list):
    """Fixture to generate fixability payload inside Filters for query card execution"""
    payload = []
    for fixability in fixability_list:
        payload.append({
            "value": fixability,
            "filterGroup": "include"
        })
    return payload


@pytest.fixture
def privileged_list(request):
    """Fixability list fixture"""
    return request.param


@pytest.fixture
def privileged_payload(privileged_list):
    """Fixture to generate privileged payload inside Filters for query card execution"""
    payload = []
    for privileged in privileged_list:
        payload.append({
            "value": privileged[0],
            "filterGroup": "eq" if privileged[1] else 'gt'
        })
    return payload


@pytest.fixture
def eval_status_list(request):
    """Eval status list fixture"""
    return request.param


@pytest.fixture
def eval_status_payload(eval_status_list):
    """Fixture to generate eval status payload inside Filters for query card execution"""
    payload = []
    for eval_status in eval_status_list:
        payload.append({
            "value": eval_status,
            "filterGroup": "include"
        })
    return payload


@pytest.fixture
def host_type_list(request):
    """Host type list fixture"""
    return request.param


@pytest.fixture
def host_type_payload(host_type_list):
    """Fixture to generate host type payload inside Filters for query card execution"""
    payload = []
    for host_type in host_type_list:
        payload.append({
            "value": host_type,
            "filterGroup": "eq"
        })
    payload.append({
        "value": "Launched",
        "filterGroup": "eq"
    })
    return payload


@pytest.fixture
def coverage_type_list(request):
    """Coverage type list fixture"""
    return request.param


@pytest.fixture
def coverage_type_payload(coverage_type_list):
    """Fixture to generate coverage type payload inside Filters for query card execution"""
    payload = []
    for coverage_type in coverage_type_list:
        payload.append({
            "value": coverage_type,
            "filterGroup": "include"
        })
    return payload


@pytest.fixture
def policy_status_list(request):
    """Policy Status list fixture"""
    return request.param


@pytest.fixture
def policy_status_payload(policy_status_list):
    """Fixture to generate policy status payload inside Filters for query card execution"""
    payload = []
    for status in policy_status_list:
        payload.append({
            "value": status,
            "filterGroup": "include"
        })
    return payload


@pytest.fixture
def internet_exposure_list(request):
    """Internet exposure list fixture"""
    return request.param


@pytest.fixture
def internet_exposure_payload(internet_exposure_list):
    """Fixture to generate internet exposure payload inside Filters for query card execution"""
    payload = []
    for exposure in internet_exposure_list:
        payload.append({
            "value": exposure,
            "filterGroup": "include"
        })
    return payload
