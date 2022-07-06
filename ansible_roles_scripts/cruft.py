from __future__ import annotations

import subprocess
from pathlib import Path

import click

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger
from ansible_roles_scripts import script_utils
from ansible_roles_scripts.script_utils import check_conflict_files
from ansible_roles_scripts.script_utils import COMMIT_MSG
from ansible_roles_scripts.script_utils import execute


def check_rejected_files(path: Path) -> bool:
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


def cruft_update(path: Path, push: bool) -> bool:
    def _is_real_commit_error(ex: subprocess.CalledProcessError) -> bool:
        return not any(
            match in ex.stdout.decode() for match in ["nichts zu", "nothing to"]
        )

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

    stdout = execute(["git", "status"], path)
    # """
    # Ihr Branch ist 1 Commit vor 'origin/master'.
    # (benutzen Sie "git push", um lokale Commits zu publizieren)
    # """
    if "git push" not in stdout:
        if push:
            execute(["git", "push"], path)
            logger.success("Successfully pushed the results.")
        else:
            logger.notice("Not pushing the results.")
    else:
        logger.info("Nothing to push.")

    logger.info(f"Successfully ended procedure for '{path}'")
    return True


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@click.option("-P", "--push/--no-push", "push", default=False, help="Default: False")
@utils.get_click_silent_option()
@utils.get_click_verbosity_option()
def main(push: bool, silent: bool, verbosity: int) -> int:
    utils.init(verbosity=verbosity, silent=silent)
    retv = 1

    if not script_utils.check_tools_ok(["git", "cruft", "pre-commit"]):
        return 127

    all_repos: list[Path] = script_utils.get_all_cloned_ansible_repositories()
    not_ok = set()
    for repo in all_repos:
        try:
            ok = cruft_update(repo, push)
            if not ok:
                not_ok.add(repo)
        except subprocess.CalledProcessError:
            # initially catched by function,
            # thrown again to abort that function
            not_ok.add(repo)
            retv = 1
            pass
    if len(not_ok) == 0:
        logger.success("Sucessfully run procedure on all repositories!")
    else:
        logger.error(
            f"The following repos did not succeed: "
            f"{', '.join([repo.name for repo in not_ok])}"
        )

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
