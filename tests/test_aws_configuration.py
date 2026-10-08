"""AWS environment configuration across all authentication paths."""

from unittest.mock import MagicMock

import pytest

from app.exporter import MetricExporter


@pytest.fixture(autouse=True)
def aws_environment(monkeypatch):
    for variable in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PARTITION"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr("app.exporter.Gauge", MagicMock)


def make_exporter(auth):
    return MetricExporter(
        polling_interval_seconds=3600,
        metric_name="test_aws_configuration",
        aws_access_key="key" if auth in ("static", "role_static") else "",
        aws_access_secret="secret" if auth in ("static", "role_static") else "",
        aws_assumed_role_name="path/CostExporter" if auth.startswith("role") else "",
        group_by={"enabled": False},
        targets=[{"Publisher": "123456789012"}],
        metric_type="UnblendedCost",
    )


@pytest.mark.parametrize("auth", ["default", "static", "role_default", "role_static"])
@pytest.mark.parametrize(
    "environment, region, partition",
    [
        ({}, "us-east-1", "aws"),
        ({"AWS_DEFAULT_REGION": "cn-northwest-1", "AWS_PARTITION": "aws-cn"}, "cn-northwest-1", "aws-cn"),
        (
            {"AWS_REGION": "us-gov-west-1", "AWS_DEFAULT_REGION": "us-east-1", "AWS_PARTITION": "aws-us-gov"},
            "us-gov-west-1",
            "aws-us-gov",
        ),
        ({"AWS_REGION": "", "AWS_DEFAULT_REGION": "eu-west-1"}, "eu-west-1", "aws"),
        ({"AWS_REGION": "", "AWS_DEFAULT_REGION": "", "AWS_PARTITION": ""}, "us-east-1", "aws"),
    ],
)
def test_clients_and_role_arn_use_environment(monkeypatch, auth, environment, region, partition):
    for variable, value in environment.items():
        monkeypatch.setenv(variable, value)

    sts = MagicMock()
    ce = MagicMock()
    credentials = {"AccessKeyId": "assumed-key", "SecretAccessKey": "assumed-secret", "SessionToken": "token"}
    sts.assume_role.return_value = {"Credentials": credentials}
    client = MagicMock(side_effect=lambda service, **kwargs: {"sts": sts, "ce": ce}[service])
    monkeypatch.setattr("app.exporter.boto3.client", client)

    exporter = make_exporter(auth)
    assert exporter._get_aws_client({"Publisher": "123456789012"}) is ce

    ce_kwargs = {"region_name": region}
    if auth.startswith("role"):
        ce_kwargs.update(
            aws_access_key_id="assumed-key", aws_secret_access_key="assumed-secret", aws_session_token="token"
        )
        sts_kwargs = {"region_name": region}
        if auth == "role_static":
            sts_kwargs.update(aws_access_key_id="key", aws_secret_access_key="secret")
        assert client.call_args_list[0].args == ("sts",)
        assert client.call_args_list[0].kwargs == sts_kwargs
        sts.assume_role.assert_called_once_with(
            RoleArn=f"arn:{partition}:iam::123456789012:role/path/CostExporter",
            RoleSessionName="AssumeRoleSession1",
        )
        assert client.call_count == 2
    else:
        if auth == "static":
            ce_kwargs.update(aws_access_key_id="key", aws_secret_access_key="secret")
        assert client.call_count == 1
        sts.assume_role.assert_not_called()

    assert client.call_args.args == ("ce",)
    assert client.call_args.kwargs == ce_kwargs
