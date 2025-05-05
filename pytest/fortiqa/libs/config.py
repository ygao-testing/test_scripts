import yaml
from dataclasses import dataclass, field, fields, is_dataclass

from fortiqa.libs.yaml_helpers import merge_configs, get_loader


@dataclass
class NestedDataclass:
    def __post_init__(self):
        for fld in fields(self):
            field_value = getattr(self, fld.name)
            if is_dataclass(fld.type) and isinstance(field_value, dict):
                setattr(self, fld.name, fld.type(**field_value))


@dataclass
class AzureAccountSettings:
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)
    subscription_id: str

    @property
    def credentials(self) -> dict:
        """Returns AZURE credentials"""
        return {'tenant_id': self.tenant_id, 'client_id': self.client_id, 'client_secret': self.client_secret}


@dataclass
class AwsAccountSettings:
    aws_account_id: str
    aws_access_key_id: str
    aws_secret_access_key: str = field(repr=False)
    aws_terraform_s3_backend: str
    aws_terrafrom_s3_backend_region: str

    @property
    def credentials(self) -> dict:
        """Returns AWS credentials"""
        return {'aws_access_key_id': self.aws_access_key_id, 'aws_secret_access_key': self.aws_secret_access_key}


@dataclass
class GcpServiceAccountSettings:
    type: str
    project_id: str
    org_id: str
    private_key_id: str
    private_key: str
    client_email: str
    client_id: str
    auth_uri: str
    token_uri: str
    auth_provider_x509_cert_url: str
    client_x509_cert_url: str
    universe_domain: str


@dataclass
class TerraformRemoteBackend:
    s3_bucket: str
    s3_bucket_region: str


@dataclass
class UiSettings:
    default_implicit_wait: int


@dataclass
class AppSettings(NestedDataclass):
    workspace_id: str
    customer: dict
    aws_account: AwsAccountSettings
    azure_account: AzureAccountSettings
    gcp_service_account: GcpServiceAccountSettings
    terrafrom_remote_backend: TerraformRemoteBackend


@dataclass
class Settings(NestedDataclass):
    app: AppSettings
    ui: UiSettings


def load_settings(configs: list) -> Settings:
    """Create Settings by merging given config files' contents"""
    full_config: dict = {}
    for config in configs:
        with open(config) as config_file:
            config_content = yaml.load(config_file, Loader=get_loader())
            if config_content:
                full_config = merge_configs(full_config, config_content)
    return Settings(**full_config)
