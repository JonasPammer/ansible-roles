from __future__ import annotations

from pathlib import Path
from subprocess import CalledProcessError

import attrs
import click

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger
from ansible_roles_scripts.script_utils import check_conflict_files
from ansible_roles_scripts.script_utils import check_tools_ok
from ansible_roles_scripts.script_utils import execute
from ansible_roles_scripts.script_utils import get_all_cloned_ansible_repositories
from ansible_roles_scripts.script_utils import ProcedureResultGenericRepo
from ansible_roles_scripts.script_utils import SCRIPT_CO_AUTHOR_COMMIT_MSG


@attrs.define
class CruftProcedureResult(ProcedureResultGenericRepo):
    is_something_to_push: bool = False


def is_real_commit_error(ex: CalledProcessError) -> bool:
    return not any(match in ex.stdout.decode() for match in ["nichts zu", "nothing to"])


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


def run_procedure_for(retv: CruftProcedureResult, push: bool) -> CruftProcedureResult:
    console.rule(f"{retv.role.repo_name}")
    logger.info(f"Start procedure for '{retv.role.repo_name}'")

    if check_rejected_files(retv.path) or check_conflict_files(retv.path):
        return retv

    execute(["git", "add", "."], retv.path)
    execute(
        [
            "git",
            "commit",
            "-m",
            "chore: cruft update fix",
            "-m",
            SCRIPT_CO_AUTHOR_COMMIT_MSG,
        ],
        retv.path,
        is_real_error=is_real_commit_error,
    )

    execute(["git", "pull", "--rebase"], retv.path)

    execute(["cruft", "update", "-y"], retv.path)
    if check_rejected_files(retv.path) or check_conflict_files(retv.path):
        return retv
    execute(["git", "add", "."], retv.path)
    execute(
        [
            "git",
            "commit",
            "-m",
            "chore: cruft update",
            "-m",
            SCRIPT_CO_AUTHOR_COMMIT_MSG,
        ],
        retv.path,
        is_real_error=is_real_commit_error,
    )

    execute(
        ["pre-commit", "run", "--all-files"], retv.path, is_real_error=lambda _: False
    )
    execute(["pre-commit", "run", "--all-files"], retv.path)
    execute(["git", "add", "."], retv.path)
    execute(
        ["git", "commit", "-m", "chore: pre-commit", "-m", SCRIPT_CO_AUTHOR_COMMIT_MSG],
        retv.path,
        is_real_error=is_real_commit_error,
    )

    stdout = execute(["git", "status"], retv.path)
    # """
    # Ihr Branch ist 1 Commit vor 'origin/master'.
    # (benutzen Sie "git push", um lokale Commits zu publizieren)
    # """
    if "git push" in stdout:
        if push:
            execute(["git", "push"], retv.path)
            logger.success("Successfully pushed the results.")
        else:
            retv.is_something_to_push = True
            logger.notice("Not pushing the results.")
    else:
        logger.info("Nothing to push.")

    retv.all_ok = True
    logger.info(f"Successfully ended procedure for '{retv.path}'")
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
    """Script to loop through all ANSIBLE repositories (`all-repos-in.json`),
    execute `cruft update ...` / `pre-commit run ...` and commit the results.

    This script relies on the machine executing this script
    to have the appropiate command lines tools installed
    and accessible from the within current PATH.

    To actually push the results you need to add the option `-P`
    for safety reason.

    This script recognizes cruft- and git-conflicts,
    aborting the operation for a given repository
    if any were found and notifies of the required
    manual intervention needed.
    """
    utils.init(verbosity=verbosity, silent=silent)
    retv = 1

    if not check_tools_ok(["git", "cruft", "pre-commit"]):
        return 127

    results = {
        repo_path.name: CruftProcedureResult(repo_name_in=repo_path.name)
        for repo_path in get_all_cloned_ansible_repositories()
    }
    for result in results.values():
        try:
            results[result.path.name] = run_procedure_for(result, push)
        except CalledProcessError:
            # initially catched by function,
            # thrown again to abort that function
            retv = 1
            pass

    not_ok_results: list[CruftProcedureResult] = [
        result for result in results.values() if not result.is_all_ok()
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

    pushable_results: list[CruftProcedureResult] = [
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
