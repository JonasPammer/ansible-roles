from __future__ import annotations

from pathlib import Path
from subprocess import CalledProcessError

import attrs
import click
from github import GithubException

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger
from ansible_roles_scripts import script_utils


@attrs.define
class SyncProcedureResult:
    path: Path
    all_ok: bool = False
    changed: bool = False


def run_procedure_for(path: Path) -> SyncProcedureResult:
    console.rule(f"{path}")
    logger.verbose(f"Start procedure for '{path}'")
    retv = SyncProcedureResult(path=path)

    # TODO procedure

    retv.all_ok = True
    return retv


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@utils.get_click_silent_option()
@utils.get_click_verbosity_option()
def main(silent: bool, verbosity: int) -> int:
    utils.init(verbosity=verbosity, silent=silent)
    retv = 1

    # TODO pre-req test

    all_repos: list[Path] = script_utils.get_all_cloned_ansible_repositories()
    results = {
        repo_path.name: SyncProcedureResult(path=repo_path) for repo_path in all_repos
    }
    for repo_path in all_repos:
        try:
            results[repo_path.name] = run_procedure_for(repo_path)
        except CalledProcessError:
            retv = 1
            results[repo_path.name].all_ok = False
            # error information logging handled by `script_utils.execute`:
            pass
        except GithubException:
            retv = 1
            results[repo_path.name].all_ok = False
            # exc_info will printStackTrace the current exception
            logger.error(
                f"GithubException occured for procedure of {repo_path}.", exc_info=True
            )
            pass

    not_ok_results: list[SyncProcedureResult] = [
        result for result in results.values() if not result.all_ok
    ]
    changed_results: int = sum(map(lambda result: result.changed, results.values()))
    if len(not_ok_results) == 0:
        logger.success(
            f"Sucessfully run procedure on all repositories "
            f"with changes made to {changed_results} of them!"
        )
    else:
        logger.error(
            f"The following {len(not_ok_results)} repositories "
            "did not finish the procedure as expected: \n* "
            + "\n* ".join([repo.path.name for repo in not_ok_results])
            + "\n"
            + "Please see the respective sections and their logs for more information."
        )

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
