from __future__ import annotations

import json
import os
from typing import Any

import attrs
import diskcache
import yaml
from github import BadCredentialsException
from github import Github
from github import GithubException
from rich.console import Console


console = Console(width=240)
github_api = Github()
"""See :func:`utils.init_github_api`"""

all_roles: dict[str, AnsibleRole] = {}
"""
A dictionary of all ansible roles found in `all-repos-in.json`
in which the key is the `galaxy_role_name`.

See :func:`utils.init_all_roles`
"""
__all_roles_cache = diskcache.Cache(".ansible_roles_diskcache")


@attrs.define
class AnsibleRole:
    repo_name: str
    """ repository name as denoted in all-repos-in.json """
    repo_pull_url: str
    """ repository pull URI as denoted in all-repos-in.json """
    galaxy_owner: str = "jonaspammer"
    requirements_yml: dict[str, Any] = {}
    """ decoded content of this role's `requirements.yml` file """
    meta_yml: dict[str, Any] = {}
    """ decoded content of this role's `meta/meta.yml` file """

    computed_dependencies: list[str] = attrs.field(default=attrs.Factory(list))
    """ list of `galaxy_role_name`'s """

    @property
    def role_name(self) -> str:
        """Utility function to get the actual name of the role.

        :return: `repo_name` with removed slug/repository-prefix (e.g. `ansible-role-`)
        """
        return self.repo_name.replace("ansible-role-", "")

    @property
    def galaxy_role_name(self) -> str:
        """Utility function to retun this role's fully qualified name.

        :return: This role's fully qualified name in format `galaxy_owner.role_name`.
        """
        return self.galaxy_owner + "." + self.role_name

    def get_dependency_color(self) -> str:
        """
        :return: Named color understood by Graphviz.
        """
        layer_colors = {
            0: "green",
            1: "yellow",
            2: "orange",
            3: "red",
            4: "purple",
            5: "blue",
        }
        return layer_colors[len(self.computed_dependencies)]


def init_github_api() -> None:
    """Tries to search for either the GITHUB_TOKEN environment variable or an
    `all-repos.json` file and implant the found token in the global module
    variable `github_api`."""
    global github_api

    if "GITHUB_TOKEN" in os.environ:
        console.log("Using API key found `GITHUB_TOKEN` environment variable!")
        github_api = Github(os.environ["GITHUB_TOKEN"])
        try:
            github_api.get_user().name
        except BadCredentialsException:
            console.log(
                "API key found in `GITHUB_TOKEN` environment variable is invalid. "
                "Reverting to use Github API without token or login!"
            )
            github_api = Github()
        return

    console.log(
        "No `GITHUB_TOKEN` environemnt variable found."
        "Trying to look for `all-repos.json`..."
    )

    if not os.path.exists("all-repos.json"):
        console.log(
            "No `all-repos.json` file found. Using Github API without token or login!"
        )
        return

    with open("all-repos.json") as f:
        all_repos = json.load(f)
    try:
        github_api = Github(all_repos["push_settings"]["api_key"])
        console.log("Using API key found in `all-repos.json`!")
    except (FileNotFoundError, KeyError):
        console.log(
            "No API key found in `all-repos.json`."
            "Using Github API without token or login!"
        )
        return

    try:
        github_api.get_user().name
    except BadCredentialsException:
        console.log(
            "API key found in `all-repos.json` is invalid. "
            "Reverting to use Github API without token or login!"
        )
        github_api = Github()


def init_all_roles() -> None:
    """Initializes the global module variable `all_roles`."""
    with open("all-repos-in.json") as f:
        all_repos_in = json.load(f)

    # initialize
    for key in all_repos_in:
        role = AnsibleRole(repo_name=key, repo_pull_url=all_repos_in[key])
        if not role.repo_name.startswith("ansible-role"):
            console.log(f"{role.repo_name} is not an ansible role, skipping...")
            continue
        if __all_roles_cache.get(role.galaxy_role_name) is not None:
            console.log(f"{role.galaxy_role_name} exists in cache, skipping...")
            all_roles[role.galaxy_role_name] = __all_roles_cache.get(
                role.galaxy_role_name
            )
            continue

        console.log(
            f"querying additional information of {role.galaxy_role_name} "
            f"using github api..."
        )
        repo = github_api.get_repo(f"JonasPammer/{role.repo_name}")

        try:
            role.requirements_yml = yaml.safe_load(
                repo.get_contents("requirements.yml").decoded_content
            )
            role.meta_yml = yaml.safe_load(
                repo.get_contents("meta/main.yml").decoded_content
            )
        # allow for yet-just-created / WIP ansible roles of mine
        except GithubException as ex:
            if "empty" not in str(ex):
                raise ex

        __all_roles_cache.set(key=role.galaxy_role_name, value=role, expire=60 * 30)
        all_roles[role.galaxy_role_name] = role

    # compute values
    for galaxy_role_name, role in all_roles.items():
        if "roles" not in role.requirements_yml:
            continue  # no dependencies
        for role_req in role.requirements_yml["roles"]:
            if "__not_mandatory_to_role_itself" not in role_req:
                role.computed_dependencies.append(role_req["name"])
            # role.dependencies_not_mandatory_to_role_itself.append(role_req["name"])


def init() -> None:
    """Initialize all Variables global to this module."""
    init_github_api()
    init_all_roles()


def recurse_add_dependencies(
    role: AnsibleRole, __tmp_dict: dict[str, AnsibleRole] | None = None
) -> dict[str, AnsibleRole]:
    """
    :param role: AnsibleRole which to dig through it's `computed_dependencies`.
    :return:
        A list of all computed soft role dependencies
        in form of a dict in which the key represent the role's `galaxy_role_name`.

        Note that a entry in this role may not be a fully qualified AnsibleRole
        and only contain marginal information if said role is not found
        in the global module variable `all_roles`
    """
    if __tmp_dict is None:
        __tmp_dict = {}
    __tmp_dict[role.galaxy_role_name] = role

    for galaxy_dependency in role.computed_dependencies:
        if galaxy_dependency in all_roles:
            role_for_galaxy_dependency = all_roles[galaxy_dependency]
        else:
            role_for_galaxy_dependency = AnsibleRole(
                repo_name=galaxy_dependency.split(".")[1],
                repo_pull_url="",
                galaxy_owner=galaxy_dependency.split(".")[0],
            )
        recurse_add_dependencies(role_for_galaxy_dependency, __tmp_dict)
    return __tmp_dict
