from __future__ import annotations

import getpass
import os
import pathlib
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Sequence

from ansible_roles.utils import logger

COMMIT_MSG = f"""
Co-Authored-by: https://github.com/JonasPammer/ansible-roles python script
on {platform.node()} by {getpass.getuser()}
"""


def execute(
    args: Sequence[str | os.PathLike[Any]],
    path: pathlib.Path,
    is_real_error: Callable[[subprocess.CalledProcessError], bool] | None = None,
) -> str:
    cmd_str = " ".join([str(_) for _ in args])
    logger.verbose(f"Executing '{cmd_str}'...")

    result = None
    try:
        result = subprocess.check_output(args, cwd=path.absolute())
        logger.verbose(result.decode())
        return result.decode()
    except subprocess.CalledProcessError as ex:
        if is_real_error is not None and not is_real_error(ex):
            logger.verbose(ex.stdout.decode())
            return ex.stdout.decode()
        logger.error(f"stdout: \n {ex.stdout.decode()}")
        logger.error(
            f"'{cmd_str}' for '{path}' returned non-zero exit status {ex.returncode}! "
            f"See above for more information."
        )
        raise ex


def check_conflict_files(path: Path) -> bool:
    """Check if `path` has git conflicts and log-inform about them.

    :param path: Path to execute the relevant commands in.
    :return: False if no merge conflicts exist
    """
    result = execute(["git", "ls-files", "-u"], path)
    if len(result) > 0:
        logger.error(
            f"'{path}' contains git merge conflicts." f"Please resolve by hand."
        )
        return True
    return False


def check_tools_ok(tools_in: list[str]) -> bool:
    """Check if given tools exist and log-inform about all tools that don't.

    :param tools_in: A list of commands to check for.
    :return: False if any of the tools do not exist on PATH
    """
    tools_ok = True

    def __check_tool(name: str) -> bool:
        if shutil.which(name) is None:
            logger.critical(f"Could not find program '{name}'.")
            return False
        return True

    for tool in tools_in:
        if not __check_tool(tool):
            tools_ok = False
    if not tools_ok:
        logger.critical("Not all environment requirements are met! See above.")
        return False
    return True


def get_all_cloned_github_repositories() -> list[Path]:
    """Recurse the 'all-repos' directory and return each directory that has
    github info.

    :return: A list of directories of which origin/master points to github
    """

    def __is_upstream_github(path: pathlib.Path) -> bool:
        if not path.is_dir():
            return False

        # without this, the following git commands
        # will use any parent git fount (i.e., "ansible-roles")
        dotgit = path.joinpath(".git")
        if not dotgit.exists():
            return False

        result = execute(["git", "remote", "--verbose"], path)
        return "github.com" in result and "/ansible-roles" not in result

    all_repos = [
        repo
        for repo in pathlib.Path("all-repos").iterdir()
        if __is_upstream_github(repo)
    ]
    return all_repos


def get_all_cloned_ansible_repositories() -> list[Path]:
    """Recurse the 'all-repos' directory and return each directory that has
    cookiecutter info.

    :return: A list of directories found to be valid ansible roles
             (i.e. cruft'ed from my cookiecutter).
    """

    def __is_ansible_role(path: pathlib.Path) -> bool:
        if not path.is_dir():
            return False
        cruft = path.joinpath(".cruft.json")
        return cruft.exists() and "cookiecutter-ansible-role.git" in cruft.read_text()

    all_repos = [
        repo for repo in pathlib.Path("all-repos").iterdir() if __is_ansible_role(repo)
    ]
    return all_repos
