from __future__ import annotations

import os
import pathlib
import platform
import shutil
import subprocess
from typing import Any
from typing import Callable
from typing import Sequence

import click

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger


COMMIT_MSG = f"""
Commit Authored by https://github.com/JonasPammer/ansible-roles python script
on {platform.node()} by {os.getlogin()}
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


def check_rejected_files(path: pathlib.Path) -> bool:
    cruft_rejected_files = [f for f in path.glob("**/*") if ".rej" in f.name]
    if len(cruft_rejected_files) > 0:
        logger.error(
            f"'{path.name}' contains rejected cookiecutter update alterations."
            f"Please review and incoorperate by hand: \n* "
            + "\n* ".join(
                [
                    str(p.absolute()).replace(str(path.absolute()), "")
                    for p in cruft_rejected_files
                ]
            )
        )
        return True
    return False


def check_conflict_files(path: pathlib.Path) -> bool:
    result = execute(["git", "ls-files", "-u"], path)
    if len(result) > 0:
        logger.error(
            f"'{path}' contains git merge conflicts." f"Please resolve by hand."
        )
        return True
    return False


def cruft_update(path: pathlib.Path) -> bool:
    def _is_real_commit_error(ex: subprocess.CalledProcessError) -> bool:
        return "nothing to commit" not in ex.stdout.decode()

    console.rule(f"{path}")
    logger.info(f"Start procedure for '{path}'")

    if check_rejected_files(path) or check_conflict_files(path):
        return False

    execute(["git", "add", "."], path)
    execute(
        ["git", "commit", "-m", "chore: cruft update fix", "-m", COMMIT_MSG],
        path,
        is_real_error=_is_real_commit_error,
    )

    execute(["git", "pull", "--rebase"], path)

    execute(["cruft", "update", "-y"], path)
    if check_rejected_files(path) or check_conflict_files(path):
        return False
    execute(["git", "add", "."], path)
    execute(
        ["git", "commit", "-m", "chore: cruft update", "-m", COMMIT_MSG],
        path,
        is_real_error=_is_real_commit_error,
    )

    execute(["pre-commit", "run", "--all-files"], path)
    execute(["git", "add", "."], path)
    execute(
        ["git", "commit", "-m", "chore: pre-commit", "-m", COMMIT_MSG],
        path,
        is_real_error=_is_real_commit_error,
    )

    execute(["git", "push"], path)

    logger.info(f"Successfully ended procedure for '{path}'")
    return True


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@utils.get_click_silent_option()
@utils.get_click_verbosity_option()
def main(
    silent: bool,
    verbosity: int,
) -> int:
    utils.init(verbosity=verbosity, silent=silent)
    retv = 0

    tools_ok = True

    def _check_tool_exists(name: str) -> bool:
        if shutil.which(name) is None:
            logger.critical(f"Could not find program '{name}'.")
            return False
        return True

    for tool in ["git", "pre-commit", "cruft"]:
        ret = _check_tool_exists(tool)
        if not ret:
            tools_ok = False
    if not tools_ok:
        logger.critical("Not all environment requirements are met! See above.")
        return 127

    all_ok = True

    def _is_ansible_role(path: pathlib.Path) -> bool:
        if not path.is_dir():
            return False
        cruft = path.joinpath(".cruft.json")
        return cruft.exists() and "cookiecutter-ansible-role.git" in cruft.read_text()

    all_repos = [
        repo for repo in pathlib.Path("all-repos").iterdir() if _is_ansible_role(repo)
    ]
    for repo in all_repos:
        try:
            ok = cruft_update(repo)
            if not ok:
                all_ok = False
        except subprocess.CalledProcessError:
            # initially catched by function,
            # thrown again to abort that function
            all_ok = False
            retv = 1
            pass
    if all_ok:
        logger.success("Sucessfully run procedure on all repositories!")
    else:
        logger.error("Some Repositories error'd. Please see above!")

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
