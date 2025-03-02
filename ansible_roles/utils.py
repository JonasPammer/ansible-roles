from __future__ import annotations

import json
import logging
import os
from typing import Any
from typing import Callable
from typing import Literal

import attrs
import click
import diskcache
import requests
import verboselogs
import yaml
from dotenv import load_dotenv
from github import BadCredentialsException
from github import Github
from github import GithubException
from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install as install_rich_traceback

console = Console(width=240)
logger = verboselogs.VerboseLogger("ansible-roles")
github_api: Github = None
"""Critical Note!

Use this variable using `utils.github_api`, not `github_api`.
"""
github_api_used_token: Literal["all-repos", "env", "None"] = "None"
"""See :func:`utils.init_github_api`"""

all_roles: dict[str, AnsibleRole] = {}
"""A dictionary of all ansible roles found in `all-repos-in.json` in which the
key is the `galaxy_role_name`.

See :func:`utils.init_all_roles`
"""
__all_roles_cache = diskcache.Cache(".ansible_roles_diskcache")


@attrs.define
class AnsibleRole:
    repo_name: str
    """Repository name as denoted in all-repos-in.json."""
    repo_pull_url: str
    """Repository pull URI as denoted in all-repos-in.json."""
    galaxy_owner: str = "jonaspammer"
    requirements_yml: dict[str, Any] = {}
    """Decoded content of this role's `requirements.yml` file."""
    meta_yml: dict[str, Any] = {}
    """Decoded content of this role's `meta/meta.yml` file."""
    ansible_roles_yml: dict[str, Any] = {}
    """Decoded content of this role's `meta/ansible-roles.yml` file added in
    https://github.com/JonasPammer/cookiecutter-ansible-role/pull/52."""

    id: int = 0
    """Fetched ansible id of this role."""

    computed_dependencies: list[str] = attrs.field(default=attrs.Factory(list))
    """List of `galaxy_role_name`'s."""

    @property
    def role_name(self) -> str:
        """Utility property which returns the actual name of the role.

        :return: `repo_name` with removed slug/repository-prefix (e.g. `ansible-role-`)
        """
        return self.repo_name.replace("ansible-role-", "")

    @property
    def galaxy_role_name(self) -> str:
        """Utility property which returns this role's fully qualified name.

        :return: This role's fully qualified name in format `galaxy_owner.role_name`.
        """
        return self.galaxy_owner + "." + self.role_name

    @property
    def description(self) -> str | None:
        """Utility property to return
        `self.meta_yml["galaxy_info"]["description"]` if exists or None
        otherwise."""
        if (
            "galaxy_info" in self.meta_yml
            and "description" in self.meta_yml["galaxy_info"]
        ):
            return self.meta_yml["galaxy_info"]["description"]
        return None

    def get_dependency_color(self) -> str:
        """
        :return: Named color understood by Graphviz.
        """
        layer_colors = {
            0: "darkgreen",
            1: "forestgreen",
            2: "limegreen",
            3: "greenyellow",
            4: "yellow",
            5: "gold",
            6: "orange",
            7: "darkorange",
            8: "orangered",
            9: "red",
            10: "firebrick",
            11: "darkred",
            12: "mediumvioletred",
            13: "purple",
            14: "darkorchid",
            15: "blueviolet",
            16: "royalblue",
            17: "blue",
            18: "dodgerblue",
            19: "deepskyblue",
            20: "turquoise",
            21: "mediumturquoise",
            22: "lightseagreen",
            23: "seagreen",
        }
        return layer_colors[len(self.computed_dependencies)]


def get_click_silent_option() -> Callable[[click.FC], click.FC]:
    return click.option(
        "-s",
        "--silent",
        "-q",
        "--quiet",
        "silent",
        default=False,
        is_flag=True,
        help="Disable LOGGING to console (print's will still be made).",
    )


def get_click_verbosity_option() -> Callable[[click.FC], click.FC]:
    return click.option(
        "-v",
        "--verbose",
        "verbosity",
        count=True,
        help="""
        Can be used up to 3 times (i.e., '-vvv') to
        incrementally increase verbosity of log output (VERBOSE -> DEBUG -> SPAM).
        File Log Output (if existant) is always DEBUG except when verbosity is over 3,
        in which scenario it also shows SPAM logs.
        """,
    )


def get_log_levels_from_verbosity_or_silent_cli_argument(
    verbosity: int = 0, silent: bool = False
) -> tuple[int, int]:
    """
    :param verbosity:
      0:
        INFO    | VERBOSE
      1:
        VERBOSE | DEBUG
      2:
        DEBUG   | DEBUG
      3 and above:
        SPAM    | SPAM
    :param silent:
        Sets the returned console_log_level to be NOTSET
        (no-matter what `verbosity` level was given).
    :return:
        A tuple containing
        1) the determined console log level and
        2) the determined rotating log level.
    """

    console_log_level = logging.INFO
    rotate_log_level = verboselogs.VERBOSE
    if verbosity == 1:
        # Detailed information that should be understandable to experienced users
        # to provide insight in the software’s behavior;
        # a sort of high level debugging information.
        console_log_level = verboselogs.VERBOSE
        rotate_log_level = logging.DEBUG
    elif verbosity == 2:
        # Detailed information, typically of interest only when diagnosing problems.
        console_log_level = logging.DEBUG
        console_log_level = logging.DEBUG
    elif verbosity >= 3:
        # Way too verbose for regular debugging,
        # but nice to have when someone is getting desperate
        # in a late night debugging session and decides
        # that they want as much instrumentation as possible! :-)
        console_log_level = verboselogs.SPAM
        rotate_log_level = verboselogs.SPAM

    if silent:
        console_log_level = logging.NOTSET

    return console_log_level, rotate_log_level


def init_logger(verbosity: int = 0, silent: bool = False) -> None:
    (
        console_log_level,
        rotate_log_level,
    ) = get_log_levels_from_verbosity_or_silent_cli_argument(verbosity, silent)
    logger.addHandler(
        RichHandler(level=logging.getLevelName(console_log_level), markup=True)
    )
    logger.setLevel(console_log_level)
    install_rich_traceback(show_locals=True)


def init_github_api() -> None:
    """Tries to search for either the GITHUB_TOKEN environment variable or an
    `all-repos.json` file and implant the found token in the global module
    variable `github_api`."""
    global github_api
    global github_api_used_token

    if "GITHUB_TOKEN" in os.environ:
        github_api = Github(os.environ["GITHUB_TOKEN"])
        try:
            # github_api.get_user().name
            logger.success("Using API key from `GITHUB_TOKEN` environment variable!")
            github_api_used_token = "env"
        except BadCredentialsException:
            logger.warning(
                "API key found in `GITHUB_TOKEN` environment variable is invalid. "
                "Reverting to use Github API without token or login!"
            )
            github_api = Github()
        return

    logger.notice(
        "No `GITHUB_TOKEN` environment variable found. "
        "Trying to look for `all-repos.json`..."
    )

    if not os.path.exists("all-repos.json"):
        logger.notice(
            "No `all-repos.json` file found. Using Github API without token or login!"
        )
        github_api = Github()
        return

    with open("all-repos.json") as f:
        all_repos = json.load(f)
    try:
        github_api = Github(all_repos["push_settings"]["api_key"])
    except (FileNotFoundError, KeyError):
        logger.notice(
            "No API key found in `all-repos.json`. "
            "Using Github API without token or login!"
        )
        github_api = Github()
        return

    try:
        github_api.get_user().name
        logger.success("Using API key found in `all-repos.json`!")
        github_api_used_token = "all-repos"
        return
    except BadCredentialsException:
        logger.warning(
            "API key found in `all-repos.json` is invalid. "
            "Reverting to use Github API without token or login!"
        )
        github_api = Github()
        return


def get_role_id(role: AnsibleRole) -> int | None:
    url = (
        "https://galaxy.ansible.com/api/v1/roles/"
        f"?owner__username={role.galaxy_owner}&name={role.role_name}"
    )
    response = requests.get(url)
    data = json.loads(response.text)
    if "count" not in data:
        return None
    if data["count"] > 1:
        # shouldn't and hasn't happened, but just making sure consumer notices
        logger.warn("galaxy.ansible.com has multiple results?!")
    if data["count"] <= 0:
        return None
    role_id = data["results"][0]["id"]
    return int(role_id)


def init_all_roles() -> None:
    """Initializes the global module variable `all_roles`."""
    with open("all-repos-in.json") as f:
        all_repos_in = json.load(f)

    # initialize
    for key in all_repos_in:
        role = AnsibleRole(repo_name=key, repo_pull_url=all_repos_in[key])
        if not role.repo_name.startswith("ansible-role"):
            logger.debug(f"{role.repo_name} is not an ansible role, skipping...")
            continue
        if __all_roles_cache.get(role.galaxy_role_name) is not None:
            logger.verbose(f"{role.galaxy_role_name} exists in cache, skipping...")
            logger.spam(role)
            all_roles[role.galaxy_role_name] = __all_roles_cache.get(
                role.galaxy_role_name
            )
            continue

        logger.verbose(
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
            role.ansible_roles_yml = yaml.safe_load(
                repo.get_contents("meta/ansible-roles.yml").decoded_content
            )
        # allow for yet-just-created / WIP ansible roles of mine
        except GithubException as ex:
            if "empty" not in str(ex):
                raise ex

        try:
            logger.debug(
                "Querying https://galaxy.ansible.com/api/v1 "
                f"to get {role.galaxy_role_name}'s id"
            )
            queried_role_id = get_role_id(role)
            if queried_role_id is not None:
                logger.verbose(f"Role ID: {queried_role_id}")
                role.id = queried_role_id
            else:
                logger.verbose("Couldn't query role ID.")
        except Exception as ex:
            logger.warning(
                f"Could not fetch {role.galaxy_role_name}'s id " f"because of {ex}."
            )

        __all_roles_cache.set(key=role.galaxy_role_name, value=role, expire=60 * 30)
        all_roles[role.galaxy_role_name] = role
        logger.success(f"Sucessfully fetched {role.galaxy_role_name}!")

    # compute relationship-dependant values
    for galaxy_role_name, role in all_roles.items():
        if "roles" not in role.requirements_yml:
            continue  # no dependencies
        for role_req in role.requirements_yml["roles"]:
            if (
                role_req["name"]
                not in role.ansible_roles_yml[
                    "requirements_not_mandatory_to_role_itself"
                ]
            ):
                role.computed_dependencies.append(role_req["name"])
            # role.dependencies_not_mandatory_to_role_itself.append(role_req["name"])

    logger.success(
        f"Successfully fetched {len(all_roles)} roles from 'all-repos-in.json'!"
    )


def init(verbosity: int = 0, silent: bool = False) -> None:
    """Initialize all Variables global to this module."""
    load_dotenv(override=True)
    init_logger(verbosity, silent)
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
