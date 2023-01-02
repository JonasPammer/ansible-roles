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

import attrs
from github.Repository import Repository

from ansible_roles import utils
from ansible_roles.utils import AnsibleRole
from ansible_roles.utils import logger

SCRIPT_CO_AUTHOR_COMMIT_MSG = f"""
Co-Authored-by: https://github.com/JonasPammer/ansible-roles python script
on {platform.node()} by {getpass.getuser()}
"""


class ProcedureResultBase:
    all_ok: bool | str | None = None
    """Only directly modify this to False!

    Use `set_ok_if_none` for setting it to True.
    """
    changed: bool = False

    def set_ok_if_none(self) -> None:
        if self.all_ok is None:
            self.all_ok = True

    def is_all_ok(self) -> bool:
        return self.all_ok is True


@attrs.define()
class ProcedureResultRole(ProcedureResultBase):
    role_in: AnsibleRole

    @property
    def role(self) -> AnsibleRole:
        return self.role_in

    @property
    def repo(self) -> Repository:
        return utils.github_api.get_repo(f"JonasPammer/{ self.role_in.repo_name }")

    @property
    def path(self) -> Path:
        """May exist (have been cloned), may not."""
        return Path("all-repos").joinpath(self.repo.name)


@attrs.define()
class ProcedureResultGenericRepo(ProcedureResultBase):
    repo_name_in: str

    @property
    def repo(self) -> Repository:
        return utils.github_api.get_repo(f"JonasPammer/{ self.repo_name_in }")

    @property
    def path(self) -> Path:
        """May exist (have been cloned), may not."""
        return Path("all-repos").joinpath(self.repo.name)

    @property
    def role(self) -> AnsibleRole:
        """
        :raises StopIteration: If this repository does not exist in `utils.all_roles`.
        """
        return next(
            filter(
                lambda role: role.repo_name == self.repo.name, utils.all_roles.values()
            )
        )


def is_upstream_of_path_github(path: pathlib.Path) -> bool:
    if not path.is_dir():
        return False

    # without this, the following git commands
    # will use any parent git fount (i.e., "ansible-roles"),
    # resulting in false-positive
    dotgit = path.joinpath(".git")
    if not dotgit.exists():
        return False

    result = execute(["git", "remote", "--verbose"], path)
    return "github.com" in result and "/ansible-roles" not in result


def is_path_ansible_role(path: pathlib.Path) -> bool:
    if not path.is_dir():
        return False
    cruft = path.joinpath(".cruft.json")
    return (
        cruft.exists() and "JonasPammer/cookiecutter-ansible-role" in cruft.read_text()
    )


def execute(
    args: Sequence[str | os.PathLike[Any]],
    path: pathlib.Path,
    is_real_error: Callable[[subprocess.CalledProcessError], bool] | None = None,
) -> str:
    """Execute given command in the given directory with appropiate of logs,
    returing the output if all went ok.

    :param args:
        The actual command to execute.
    :param path:
        The `cwd` to execute the subproccess in.
    :param is_real_error:
        If the exit code was non-zero, this function is used to determine
        whether to throw and report about the thrown CalledProcessError
        or wheter to just log and return the output like normal.
        None is interpreted as "always True".
        None by default.
    :raises subproccess.CalledProcesssError:
        If the exit code was non-zero and `is_real_error`
        is either None or returns True,
        this function raises a CalledProcessError.
        The CalledProcessError object will have  the return code in the
        returncode attribute and output in the output attribute.
    :return: decoded output of command
    """
    cmd_str = " ".join([str(_) for _ in args])
    logger.verbose(f"Executing '{cmd_str}'...")

    result = None
    try:
        result = subprocess.check_output(
            args, cwd=path.absolute(), stderr=subprocess.PIPE
        )
        logger.verbose(result.decode())
        return result.decode()
    except subprocess.CalledProcessError as ex:
        if is_real_error is not None and not is_real_error(ex):
            logger.verbose(ex.output.decode())
            return ex.output.decode()
        logger.error(
            f"stdout: \n {ex.stdout.decode()} \n"
            f"stderr: \n {ex.stderr.decode(errors='ignore')}"
        )
        logger.error(
            f"'{cmd_str}' for '{path}' returned non-zero exit status {ex.returncode}! "
            f"See above for more information."
        )
        raise ex


def check_conflict_files(path: Path) -> bool:
    """Check if `path` has any unresolved git conflicts and log-inform about
    them.

    If merge conflicts (ls-files) exist but have already been resolved
    in the unstaged environment this function returns False too.

    :param path: Path to execute the relevant commands in.
    :return: False if no merge conflicts exist
    """
    unmerged_files_result = execute(["git", "ls-files", "--unmerged"], path)
    # --check: Warn if changes introduce conflict markers or whitespace errors.
    conflict_check_result = execute(["git", "diff", "--check"], path)
    if len(unmerged_files_result) > 0:
        # potentially add 'or "conflict" not in conflict_check_result'
        # to not trigger on whitespace errors which --check also warns about
        if len(conflict_check_result) == 0:
            logger.verbose(
                f"'{path}' contains git merge conflicts "
                f"which have already been resolved but not yet staged. \n"
                f"{unmerged_files_result}"
            )
            return False
        logger.error(
            f"'{path}' contains git merge conflicts. "
            f"Please resolve by hand. \n"
            f"{conflict_check_result} \n"
            f"{unmerged_files_result}"
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

    all_repos = [
        repo
        for repo in pathlib.Path("all-repos").iterdir()
        if is_upstream_of_path_github(repo)
    ]
    return all_repos


def get_all_cloned_ansible_repositories() -> list[Path]:
    """Recurse the 'all-repos' directory and return each directory that has
    cookiecutter info.

    :return: A list of directories found to be valid ansible roles
             (i.e. cruft'ed from my cookiecutter).
    """

    all_repos = [
        repo
        for repo in pathlib.Path("all-repos").iterdir()
        if is_path_ansible_role(repo)
    ]
    return all_repos
