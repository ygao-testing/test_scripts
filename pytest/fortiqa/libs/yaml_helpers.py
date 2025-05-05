import os
import yaml


def join_constructor(loader, node):
    """Custom YAML constructor to join two strings"""
    seq = loader.construct_sequence(node)
    return ''.join([str(i) for i in seq])


def env_constructor(loader, node):
    """Custom YAML constructor to inject environment variables"""
    tag_value = loader.construct_scalar(node)
    assert tag_value in os.environ, f"No environment variable {tag_value}"
    return os.environ[tag_value]


def get_loader():
    """Return SafeLoader with custom constructors"""
    loader = yaml.SafeLoader
    loader.add_constructor("!join", join_constructor)
    loader.add_constructor("!env", env_constructor)
    return loader


def merge_configs(default, user):
    """Merge two dictionaries"""
    if isinstance(user, dict) and isinstance(default, dict):
        for key in user:
            if key in default:
                default[key] = merge_configs(default[key], user[key])
            else:
                default[key] = user[key]
    else:
        default = user
    return default
