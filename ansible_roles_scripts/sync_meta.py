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


def get_required_linear_history(branch: Branch) -> bool:
    """
    FIXME: remove when https://github.com/PyGithub/PyGithub/issues/2239 is resolved
           i.e. if `Branch` has this functionality built in
    """
    headers, data = branch._requester.requestJsonAndCheck(
        "GET",
        branch.protection_url,
        headers={"Accept": Consts.mediaTypeRequireMultipleApprovingReviews},
    )
    return data["required_linear_history"]["enabled"]


def edit_protection(
    branch: Branch,
    strict: bool = github.GithubObject.NotSet,
    contexts: list[str] = github.GithubObject.NotSet,
    enforce_admins: bool = github.GithubObject.NotSet,
    dismissal_users: list[str] = github.GithubObject.NotSet,
    dismissal_teams: list[str] = github.GithubObject.NotSet,
    dismiss_stale_reviews: bool = github.GithubObject.NotSet,
    require_code_owner_reviews: bool = github.GithubObject.NotSet,
    required_approving_review_count: int = github.GithubObject.NotSet,
    user_push_restrictions: list[str] = github.GithubObject.NotSet,
    team_push_restrictions: list[str] = github.GithubObject.NotSet,
    required_linear_history: bool = github.GithubObject.NotSet,
) -> None:
    """Copy of the source code from `Branch.edit_protection` as per
    PyGithub/PyGithub v1.55 with additions made in
    https://github.com/PyGithub/PyGithub/pull/2211 as per 2022/07.

    FIXME: remove when above PR aka.
           https://github.com/PyGithub/PyGithub/issues/2239
           is resolved / i.e. if `Branch.edit_protection`
           has this functionality built-in

    :calls:
        `PUT /repos/{owner}/{repo}/branches/{branch}/protection`
        https://docs.github.com/en/rest/reference/repos#branches

    NOTE: The GitHub API groups strict and contexts together, both must
    be submitted. Take care to pass both as arguments even if only one is
    changing. Use edit_required_status_checks() to avoid this.
    """
    assert strict is github.GithubObject.NotSet or isinstance(strict, bool), strict
    assert contexts is github.GithubObject.NotSet or all(
        isinstance(element, str) for element in contexts
    ), contexts
    assert enforce_admins is github.GithubObject.NotSet or isinstance(
        enforce_admins, bool
    ), enforce_admins
    assert dismissal_users is github.GithubObject.NotSet or all(
        isinstance(element, str) for element in dismissal_users
    ), dismissal_users
    assert dismissal_teams is github.GithubObject.NotSet or all(
        isinstance(element, str) for element in dismissal_teams
    ), dismissal_teams
    assert dismiss_stale_reviews is github.GithubObject.NotSet or isinstance(
        dismiss_stale_reviews, bool
    ), dismiss_stale_reviews
    assert require_code_owner_reviews is github.GithubObject.NotSet or isinstance(
        require_code_owner_reviews, bool
    ), require_code_owner_reviews
    assert required_approving_review_count is github.GithubObject.NotSet or isinstance(
        required_approving_review_count, int
    ), required_approving_review_count
    assert required_linear_history is github.GithubObject.NotSet or isinstance(
        required_linear_history, bool
    ), required_linear_history

    post_parameters: dict[str, Any] = {}
    if (
        strict is not github.GithubObject.NotSet
        or contexts is not github.GithubObject.NotSet
    ):
        if strict is github.GithubObject.NotSet:
            strict = False
        if contexts is github.GithubObject.NotSet:
            contexts = []
        post_parameters["required_status_checks"] = {
            "strict": strict,
            "contexts": contexts,
        }
    else:
        post_parameters["required_status_checks"] = None

    if enforce_admins is not github.GithubObject.NotSet:
        post_parameters["enforce_admins"] = enforce_admins
    else:
        post_parameters["enforce_admins"] = None

    if (
        dismissal_users is not github.GithubObject.NotSet
        or dismissal_teams is not github.GithubObject.NotSet
        or dismiss_stale_reviews is not github.GithubObject.NotSet
        or require_code_owner_reviews is not github.GithubObject.NotSet
        or required_approving_review_count is not github.GithubObject.NotSet
    ):
        post_parameters["required_pull_request_reviews"] = {}
        if dismiss_stale_reviews is not github.GithubObject.NotSet:
            post_parameters["required_pull_request_reviews"][
                "dismiss_stale_reviews"
            ] = dismiss_stale_reviews
        if require_code_owner_reviews is not github.GithubObject.NotSet:
            post_parameters["required_pull_request_reviews"][
                "require_code_owner_reviews"
            ] = require_code_owner_reviews
        if required_approving_review_count is not github.GithubObject.NotSet:
            post_parameters["required_pull_request_reviews"][
                "required_approving_review_count"
            ] = required_approving_review_count
        if dismissal_users is not github.GithubObject.NotSet:
            post_parameters["required_pull_request_reviews"][
                "dismissal_restrictions"
            ] = {"users": dismissal_users}
        if dismissal_teams is not github.GithubObject.NotSet:
            if (
                "dismissal_restrictions"
                not in post_parameters["required_pull_request_reviews"]
            ):
                post_parameters["required_pull_request_reviews"][
                    "dismissal_restrictions"
                ] = {}
            post_parameters["required_pull_request_reviews"]["dismissal_restrictions"][
                "teams"
            ] = dismissal_teams
    else:
        post_parameters["required_pull_request_reviews"] = None
    if (
        user_push_restrictions is not github.GithubObject.NotSet
        or team_push_restrictions is not github.GithubObject.NotSet
    ):
        if user_push_restrictions is github.GithubObject.NotSet:
            user_push_restrictions = []
        if team_push_restrictions is github.GithubObject.NotSet:
            team_push_restrictions = []
        post_parameters["restrictions"] = {
            "users": user_push_restrictions,
            "teams": team_push_restrictions,
        }
    else:
        post_parameters["restrictions"] = None

    if required_linear_history is not github.GithubObject.NotSet:
        post_parameters["required_linear_history"] = required_linear_history

    headers, data = branch._requester.requestJsonAndCheck(
        "PUT",
        branch.protection_url,
        headers={"Accept": Consts.mediaTypeRequireMultipleApprovingReviews},
        input=post_parameters,
    )


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
    if (
        master_branch.protected is False
        or master_branch.get_admin_enforcement() is True
        or master_branch.get_required_pull_request_reviews().require_code_owner_reviews
        is True
        or master_branch.get_required_pull_request_reviews().required_approving_review_count != 0
        or get_required_linear_history(master_branch) is False
    ):
        logger.verbose(f"Updating master branch protection settings of {repo}.")
        edit_protection(
            master_branch,
            enforce_admins=False,
            require_code_owner_reviews=False,
            required_approving_review_count=0,
            required_linear_history=True,
        )
        retv.set_ok_if_none()
        retv.changed = True
        logger.success(
            f"Sucessfully updated master branch protection settings of {repo}."
        )
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
