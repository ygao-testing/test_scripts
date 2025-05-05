import os

from fortiqa.libs.config import load_settings

default_config = os.path.join(os.path.dirname(__file__), "config.yaml")
user_config = os.path.join(os.path.dirname(__file__), "user_config.yaml")
settings = load_settings([default_config, user_config])
