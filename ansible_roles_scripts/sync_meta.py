from __future__ import annotations

from subprocess import CalledProcessError
from typing import Any

import attrs
import click
import github
from github import Branch
from github import Consts
from github import GithubException
from pydantic import SecretStr

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger
from ansible_roles_scripts.script_utils import ProcedureResultRole


@attrs.define
class SyncProcedureResult(ProcedureResultRole):
    pass


def is_galaxy_api_key_valid(galaxy_api_key: SecretStr) -> bool:
    # TODO figure out real auth test
    return len(galaxy_api_key.get_secret_value()) == 40


def run_procedure_for(
    retv: SyncProcedureResult, galaxy_api_key: SecretStr
) -> SyncProcedureResult:
    console.rule(f"{retv.role.repo_name}")
    logger.verbose(f"Start procedure for '{retv.role.repo_name}'")
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

    master_branch = repo.get_branch("master")
    if master_branch.protected is True:
        logger.verbose(f"Updating master branch protection settings of {repo}.")
        master_branch.remove_protection()
    else:
        retv.set_ok_if_none()
        logger.verbose(
            f"{repo}'s master basic branch protection settings "
            "align with script's definition, doing nothing."
        )

    if is_galaxy_api_key_valid(galaxy_api_key):
        # `create_secret` also updates existing
        repo.create_secret(
            secret_name="GALAXY_API_KEY",  # pragma: allowlist secret
            unencrypted_value=galaxy_api_key.get_secret_value(),
        )
        logger.success(f"Successfully updated 'GALAXY_API_KEY' of {repo}...")
        retv.set_ok_if_none()
        retv.changed = True
    return retv


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@click.option(
    "--set-galaxy-api-key",
    "--galaxy",
    "set_galaxy_api_key",
    default=False,
    is_flag=True,
    help="""
    If this option is given this script will prompt the user
    for an appropiate key and update the Github Action Secret
    `GALAXY_API_KEY` of every repository to the given value.
    """,
)
@utils.get_click_silent_option()
@utils.get_click_verbosity_option()
def main(set_galaxy_api_key: bool, silent: bool, verbosity: int) -> int:
    """Script to loop through all ANSIBLE repositories (`all-repos-in.json`)
    and edit GitHub Repository Settings. This includes.

    * setting allowed merge types

    * setting github project description to `meta/main.yml`'s description

    * setting branch protection controls for `master` (e.g. `required_linear_history`)

    * optionally setting GALAXY_API_KEY action secret if supplied

    This script solely relies on the use of the GitHub API.
    See DEVELOPMENT.adoc for instructions on how to
    make your token accessible to the script.
    """
    utils.init(verbosity=verbosity, silent=silent)
    retv = 1

    if utils.github_api_used_token == "None":
        logger.critical(
            "This script requires a github token "
            "(for merging and doing things to the PRs). Aborting!"
        )
        return retv

    galaxy_api_key: SecretStr = SecretStr("")
    if set_galaxy_api_key:
        galaxy_api_key = SecretStr(
            click.prompt("GALAXY_API_KEY", hide_input=True, confirmation_prompt=True)
        )
        if not is_galaxy_api_key_valid(galaxy_api_key):
            raise click.BadParameter("Given GALAXY_API_KEY is invalid!")

    results = {
        role.galaxy_role_name: SyncProcedureResult(role_in=role)
        for role in utils.all_roles.values()
    }
    for result in results.values():
        try:
            results[result.role.galaxy_role_name] = run_procedure_for(
                result, galaxy_api_key
            )
        except CalledProcessError:
            retv = 1
            results[result.role.galaxy_role_name].all_ok = False
            # error information logging handled by `script_utils.execute`:
            pass
        except GithubException:
            retv = 1
            results[result.role.galaxy_role_name].all_ok = False
            # exc_info will printStackTrace the current exception
            logger.error(
                f"GithubException occured for procedure of {result.role}.",
                exc_info=True,
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
