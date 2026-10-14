"""The shipped managed-settings floor recipe, parsed into its semantic model.

`claude plugin test` cannot read a JSON file and `claude plugin validate` treats a
settings file as a plugin manifest, so the recipe file itself is checked here. Each check
is a function of the parsed document, so the negative cases drive the same code on a
mutated copy.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / "packaging" / "managed-settings.example.json"

MOD = "barmkin-mod"
SEC_DEFAULT_ID = "cc-plugin-sec-default@builtin"


def floor_problems(doc: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    sandbox = doc.get("sandbox") or {}
    network = sandbox.get("network") or {}
    if sandbox.get("enabled") is not True:
        problems.append("sandbox.enabled")
    if sandbox.get("failIfUnavailable") is not True:
        problems.append("sandbox.failIfUnavailable")
    if sandbox.get("allowUnsandboxedCommands") is not False:
        problems.append("sandbox.allowUnsandboxedCommands")
    if network.get("allowManagedDomainsOnly") is not True:
        problems.append("network.allowManagedDomainsOnly")
    if network.get("allowAllUnixSockets") is True:
        problems.append("network.allowAllUnixSockets")

    allowed = set(network.get("allowedDomains") or [])
    credentials = sandbox.get("credentials") or {}
    masks = [
        entry
        for kind in ("files", "envVars")
        for entry in credentials.get(kind) or []
        if isinstance(entry, dict) and entry.get("mode") == "mask"
    ]
    if not masks:
        problems.append("sandbox.credentials mask entry")
    for entry in masks:
        if not set(entry.get("injectHosts") or []) <= allowed:
            problems.append("injectHosts outside allowedDomains")

    if doc.get("disableSkillShellExecution") is not True:
        problems.append("disableSkillShellExecution")
    if doc.get("allowManagedMcpServersOnly") is not True:
        problems.append("allowManagedMcpServersOnly")
    if not isinstance(doc.get("allowedMcpServers"), list):
        problems.append("allowedMcpServers")

    names = [plugin.split("@")[0] for plugin in doc.get("prependPlugins") or []]
    if MOD not in names or SEC_DEFAULT_ID not in (doc.get("prependPlugins") or []):
        problems.append("prependPlugins seating")
    elif names.index(MOD) > names.index(SEC_DEFAULT_ID.split("@")[0]):
        problems.append("prependPlugins order")
    return problems


def load_recipe() -> dict[str, Any]:
    return json.loads(RECIPE.read_text())


def test_shipped_recipe_meets_the_floor() -> None:
    assert floor_problems(load_recipe()) == []


def test_each_floor_key_is_enforced() -> None:
    mutations = {
        "sandbox.enabled": lambda d: d["sandbox"].__setitem__("enabled", False),
        "sandbox.failIfUnavailable": lambda d: d["sandbox"].pop("failIfUnavailable"),
        "sandbox.allowUnsandboxedCommands": lambda d: d["sandbox"].__setitem__("allowUnsandboxedCommands", True),
        "network.allowManagedDomainsOnly": lambda d: d["sandbox"]["network"].pop("allowManagedDomainsOnly"),
        "network.allowAllUnixSockets": lambda d: d["sandbox"]["network"].__setitem__("allowAllUnixSockets", True),
        "sandbox.credentials mask entry": lambda d: d["sandbox"].pop("credentials"),
        "injectHosts outside allowedDomains": lambda d: d["sandbox"]["network"].__setitem__("allowedDomains", []),
        "disableSkillShellExecution": lambda d: d.pop("disableSkillShellExecution"),
        "allowManagedMcpServersOnly": lambda d: d.pop("allowManagedMcpServersOnly"),
        "allowedMcpServers": lambda d: d.pop("allowedMcpServers"),
        "prependPlugins seating": lambda d: d.__setitem__("prependPlugins", [MOD + "@x"]),
        "prependPlugins order": lambda d: d["prependPlugins"].reverse(),
    }
    for problem, mutate in mutations.items():
        doc = copy.deepcopy(load_recipe())
        mutate(doc)
        assert problem in floor_problems(doc), problem
