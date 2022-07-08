from __future__ import annotations

from pathlib import Path
from subprocess import CalledProcessError

import attrs
import click
from github import GithubException
from github.Repository import Repository

from ansible_roles import utils
from ansible_roles.utils import AnsibleRole
from ansible_roles.utils import console
from ansible_roles.utils import logger


@attrs.define
class SyncProcedureResult:
    role: AnsibleRole
    path: Path | None = None
    all_ok: bool | None = None
    changed: bool = False

    @property
    def repo(self) -> Repository:
        return utils.github_api.get_repo(f"JonasPammer/{ self.role.repo_name }")

    def set_ok_if_none(self) -> None:
        if self.all_ok is None:
            self.all_ok = True

    def is_all_ok(self) -> bool:
        return self.all_ok is True


def run_procedure_for(role: AnsibleRole) -> SyncProcedureResult:
    console.rule(f"{role.repo_name}")
    logger.verbose(f"Start procedure for '{role.repo_name}'")
    retv = SyncProcedureResult(role)
    repo = retv.repo

    if (
        repo.allow_squash_merge is False
        or repo.allow_merge_commit is True
        or repo.allow_rebase_merge is False
    ):
        logger.verbose(f"Updating allowed merge types of {repo}.")
        repo.edit(
            allow_squash_merge=True, allow_merge_commit=False, allow_rebase_merge=True
        )
        retv.set_ok_if_none()
        retv.changed = True
        logger.success(f"Sucessfully updated allowed merge types of {repo}.")
    else:
        retv.set_ok_if_none()
        logger.verbose(
            f"{repo}'s allowed merge types are up to date "
            "with script's definition, doing nothing."
        )

    if (
        "galaxy_info" in retv.role.meta_yml
        and "description" in retv.role.meta_yml["galaxy_info"]
    ):
        meta_yml_description = retv.role.meta_yml["galaxy_info"]["description"]

        if meta_yml_description != repo.description:
            logger.verbose(
                f"Updating description of {repo} from '{repo.description}'"
                "to '{meta_yml_description}'."
            )
            repo.edit(description=meta_yml_description)
            retv.set_ok_if_none()
            retv.changed = True
            logger.success(
                f"Sucessfully updated description of {repo}"
                "using contents of 'meta/main.yml'."
            )
        else:
            retv.set_ok_if_none()
            logger.verbose(
                f"{repo}'s description is up to date "
                "with 'meta/main.yml', doing nothing."
            )
    else:
        retv.all_ok = False
        logger.notice(
            f"{repo}'s meta.yml does not contain required 'meta/main.yml' information."
        )

    return retv


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@utils.get_click_silent_option()
@utils.get_click_verbosity_option()
def main(silent: bool, verbosity: int) -> int:
    """Edit GitHub Repository Settings of all ansible roles."""
    utils.init(verbosity=verbosity, silent=silent)
    retv = 1

    if utils.github_api_used_token == "None":
        logger.critical(
            "This script requires a github token "
            "(for merging and doing things to the PRs). Aborting!"
        )
        return retv

    results = {
        role.galaxy_role_name: SyncProcedureResult(role)
        for role in utils.all_roles.values()
    }
    for role in utils.all_roles.values():
        try:
            results[role.galaxy_role_name] = run_procedure_for(role)
        except CalledProcessError:
            retv = 1
            results[role.galaxy_role_name].all_ok = False
            # error information logging handled by `script_utils.execute`:
            pass
        except GithubException:
            retv = 1
            results[role.galaxy_role_name].all_ok = False
            # exc_info will printStackTrace the current exception
            logger.error(
                f"GithubException occured for procedure of {role}.", exc_info=True
            )
            pass

    not_ok_results: list[SyncProcedureResult] = [
        result for result in results.values() if not result.is_all_ok()
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
            + "\n* ".join([result.repo.name for result in not_ok_results])
            + "\n"
            + "Please see the respective sections and their logs for more information."
        )

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
