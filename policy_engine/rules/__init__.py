"""
Policy rules package.

Each module in this package implements one or more PolicyRule subclasses.
"""

from policy_engine.rules.base import PolicyRule
from policy_engine.rules.public_storage import PublicStorageRule
from policy_engine.rules.required_tags import RequiredTagsRule
from policy_engine.rules.nsg_ssh_open import NsgSshOpenRule
from policy_engine.rules.naming_convention import NamingConventionRule
from policy_engine.rules.disk_encryption import DiskEncryptionRule

# Master list used by the engine — order does not matter.
ALL_RULES: list[PolicyRule] = [
    PublicStorageRule(),
    RequiredTagsRule(),
    NsgSshOpenRule(),
    NamingConventionRule(),
    DiskEncryptionRule(),
]

__all__ = [
    "PolicyRule",
    "PublicStorageRule",
    "RequiredTagsRule",
    "NsgSshOpenRule",
    "NamingConventionRule",
    "DiskEncryptionRule",
    "ALL_RULES",
]
