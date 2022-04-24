from __future__ import annotations

import json
from typing import Any
from typing import Sequence

import attrs
import diskcache
import yaml
from github import Github
from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape
from rich.console import Console
from rich.traceback import install as install_rich_traceback

console = Console(width=240)
github_api = Github()
# TODO make the github action cache the cache this directory for its future runs
# note: cache is used solely to avoid github api rate limits
cache = diskcache.Cache(".ansible_roles_diskcache")


# TODO seperate the fetched variables into an own object (without any logic)
#      and cache that one
#      caching entire class is no good
@attrs.define
class AnsibleRole:
    repo_name: str
    repo_pull_url: str
    requirements_yml: dict[str, Any] = {}

    computed_dependencies: list[str] = []  # list of galaxy_role_name's

    @property
    def role_name(self) -> str:
        return self.repo_name.replace("ansible-role-", "")

    @property
    def galaxy_role_name(self) -> str:
        return "jonaspammer." + self.role_name

    def get_dependency_layer_color(self) -> str:
        layer_colors = {
            0: "green",
            1: "yellow",
            2: "orange",
            3: "red",
            4: "purple",
            5: "blue",
        }
        return layer_colors[len(self.computed_dependencies)]


def main(argv: Sequence[str] | None = None) -> int:
    retv = 0
    install_rich_traceback(show_locals=True)
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(),
    )

    with open("all-repos-in.json") as f:
        all_repos_in = json.load(f)

    # initialize all_roles
    all_roles: list[AnsibleRole] = []
    for key in all_repos_in:
        role = AnsibleRole(repo_name=key, repo_pull_url=all_repos_in[key])
        if not role.repo_name.startswith("ansible-role"):
            console.log(f"{role.repo_name} is not an ansible role, skipping...")
            continue
        if cache.get(role.repo_name) is not None:
            console.log(f"{role.repo_name} exists in cache, skipping...")
            all_roles.append(cache.get(role.repo_name))
            continue

        console.log(
            f"querying additional information of {role.repo_name} using github api..."
        )
        repo = github_api.get_repo(f"JonasPammer/{role.repo_name}")
        role.requirements_yml = yaml.safe_load(
            repo.get_contents("requirements.yml").decoded_content
        )

        cache.set(key=role.repo_name, value=role, expire=60 * 60)
        all_roles.append(role)

    # compute values
    for role in all_roles:
        if "roles" not in role.requirements_yml:
            continue  # no dependencies
        for role_req in role.requirements_yml["roles"]:
            role.computed_dependencies.append(role_req["name"])
        console.log(
            f"computed dependencies of {role.galaxy_role_name}: "
            f"{role.computed_dependencies}"
        )
        console.log(role.requirements_yml)

    with open("README.adoc", "w") as f:
        f.write(env.get_template("README.adoc.jinja2").render(all_roles=all_roles))
    with open("graphs/dependencies_ALL.dot", "w") as f:
        f.write(
            env.get_template("dependencies_ALL.dot.jinja2").render(all_roles=all_roles)
        )

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
