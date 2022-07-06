from __future__ import annotations

import subprocess
from pathlib import Path

import attrs
import click

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger
from ansible_roles_scripts import script_utils
from ansible_roles_scripts.script_utils import check_conflict_files
from ansible_roles_scripts.script_utils import COMMIT_MSG
from ansible_roles_scripts.script_utils import execute


@attrs.define
class CruftUpdateResult:
    path: Path
    all_ok: bool = False
    is_something_to_push: bool = False


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


def cruft_update(path: Path, push: bool) -> CruftUpdateResult:
    retv: CruftUpdateResult = CruftUpdateResult(path=path)

    def _is_real_commit_error(ex: subprocess.CalledProcessError) -> bool:
        return not any(
            match in ex.stdout.decode() for match in ["nichts zu", "nothing to"]
        )

    console.rule(f"{path}")
    logger.info(f"Start procedure for '{path}'")

    if check_rejected_files(path) or check_conflict_files(path):
        return retv

    execute(["git", "add", "."], path)
    execute(
        ["git", "commit", "-m", "chore: cruft update fix", "-m", COMMIT_MSG],
        path,
        is_real_error=_is_real_commit_error,
    )

    execute(["git", "pull", "--rebase"], path)

    execute(["cruft", "update", "-y"], path)
    if check_rejected_files(path) or check_conflict_files(path):
        return retv
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
            retv.is_something_to_push = True
            logger.notice("Not pushing the results.")
    else:
        logger.info("Nothing to push.")

    retv.all_ok = True
    logger.info(f"Successfully ended procedure for '{path}'")
    return retv


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
    results = {
        repo_path.name: CruftUpdateResult(path=repo_path) for repo_path in all_repos
    }
    for repo_path in all_repos:
        try:
            results[repo_path.name] = cruft_update(repo_path, push)
        except subprocess.CalledProcessError:
            # initially catched by function,
            # thrown again to abort that function
            retv = 1
            pass

    not_ok_results: list[CruftUpdateResult] = [
        result for result in results.values() if not result.all_ok
    ]
    if len(not_ok_results) == 0:
        logger.success("Sucessfully run procedure on all repositories!")
    else:
        logger.error(
            f"The following {len(not_ok_results)} repositories "
            "did not finish the procedure as expected: \n* "
            + "\n* ".join([repo.path.name for repo in not_ok_results])
            + "\n"
            + "Please see the respective sections and their logs for more information."
        )

    pushable_results: list[CruftUpdateResult] = [
        result for result in results.values() if result.is_something_to_push
    ]
    if len(pushable_results) != 0:
        logger.notice(
            f"The following {len(pushable_results)} repositories "
            "contain unpushed commits: \n* "
            + "\n* ".join([repo.path.name for repo in pushable_results])
            + "\n"
            "Invoke the command again with '--push' to push them!"
        )

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
