from __future__ import annotations

from subprocess import CalledProcessError

import attrs
import click
import yaml
from github import GithubException
from github.Commit import Commit
from github.NamedUser import NamedUser
from github.PullRequest import PullRequest
from github.PullRequestMergeStatus import PullRequestMergeStatus
from github.Repository import Repository

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger
from ansible_roles_scripts.script_utils import get_all_cloned_github_repositories
from ansible_roles_scripts.script_utils import ProcedureResultGenericRepo
from ansible_roles_scripts.script_utils import SCRIPT_CO_AUTHOR_COMMIT_MSG


@attrs.define
class MergeProcedureResult(ProcedureResultGenericRepo):
    pass


def is_user_precommit_bot(user: NamedUser) -> bool:
    return (
        user.type == "Bot"
        and user.id == 66853113
        and user.suspended_at is None
        and user.login == "pre-commit-ci[bot]"
        and user.subscriptions_url is not None
    )


def is_user_dependabot_bot(user: NamedUser) -> bool:
    return (
        user.type == "Bot"
        and user.id == 49699333
        and user.suspended_at is None
        and user.login == "dependabot[bot]"
        and user.subscriptions_url is not None
    )


def is_user_renovate_bot(user: NamedUser) -> bool:
    return (
        user.type == "Bot"
        and user.id == 29139614
        and user.suspended_at is None
        and user.login == "renovate[bot]"
        and user.subscriptions_url is not None
    )


def close_fake_pull_request(repo: Repository, pr: PullRequest, name: str) -> None:
    # never happened but you never know how sleepy or "ok next" you may one time be
    logger.warn(f"Closing fake pre-commit.ci pull request {pr}.")
    pr.create_comment(
        f"""
        Closing this '{name}' pull request as it was deemed fake!
        Nice try.

        {SCRIPT_CO_AUTHOR_COMMIT_MSG}
        """
    )
    pr.edit(status="closed")


def _squash_merge(repo: Repository, pr: PullRequest, commit_title: str) -> bool:
    logger.verbose("Attempting to squash-merge PR...")
    try:
        result: PullRequestMergeStatus = pr.merge(
            commit_title=commit_title, merge_method="squash"
        )
    except GithubException as ex:
        if (
            ex.status == 405
            and "message" in ex.data
            and "not mergeable" in ex.data["message"]
        ):
            logger.error(f"{pr.html_url} is not mergeable (possible conflicts).")
            return False
        raise ex

    if not result.merged:
        logger.error(f"{pr} reported that it did not merge! Message: {result.message}")
        return False
    logger.success(f"Successfully merged {pr}.")
    return True


def merge_renovate_request(repo: Repository, pr: PullRequest) -> bool:
    commit_title = pr.title
    commit_title += f" (#{pr.number})\n {SCRIPT_CO_AUTHOR_COMMIT_MSG}"
    return _squash_merge(repo, pr, commit_title)


def merge_dependabot_request(repo: Repository, pr: PullRequest) -> bool:
    commit_title = pr.title
    if not commit_title.startswith("chore(deps)"):
        commit_title = "chore(deps): " + commit_title
    commit_title += f" (#{pr.number})\n {SCRIPT_CO_AUTHOR_COMMIT_MSG}"

    return _squash_merge(repo, pr, commit_title)


def merge_precommit_ci_request(repo: Repository, pr: PullRequest) -> bool:
    precommit_yml = yaml.safe_load(
        repo.get_contents(".pre-commit-config.yaml").decoded_content
    )
    autoupdate_commit_msg: str = "chore(pre-commit): autoupdate :arrow_up:"

    if "ci" in precommit_yml and "autoupdate_commit_msg" in precommit_yml["ci"]:
        # `.split("\n")[0]` to fix duplicate message body as seen in
        # https://github.com/JonasPammer/ansible-role-shellcheck/commit/75764d4d14f9759f466339308706ab4192bb3530
        # which happens as a result of squash merging a single commit
        autoupdate_commit_msg = precommit_yml["ci"]["autoupdate_commit_msg"].split(
            "\n"
        )[0]
    autoupdate_commit_msg += f" (#{pr.number})\n {SCRIPT_CO_AUTHOR_COMMIT_MSG}"

    return _squash_merge(repo, pr, commit_title=autoupdate_commit_msg)


def run_procedure_for(
    retv: MergeProcedureResult, dry_run: bool = True, pr_title_filter: str | None = None
) -> MergeProcedureResult:
    console.rule(f"{retv}")
    logger.verbose(f"Start procedure for '{retv}'")
    repo = retv.repo

    pull_requests = repo.get_pulls()
    if pull_requests.totalCount == 0:
        retv.set_ok_if_none()
        logger.info(f"{repo} has no pull requests.")
        return retv

    for pr in pull_requests:
        logger.info(f"Checking {pr.html_url} ...")

        if pr_title_filter is not None and pr_title_filter not in pr.title:
            logger.verbose(f"{pr.title} does not match title filter, skipping.")
            continue

        last_commit: Commit = pr.get_commits().reversed[0]
        last_commit_status = last_commit.get_check_runs()
        good: int = 0
        for check in last_commit_status:
            if check.status == "completed" and check.conclusion == "success":
                good += 1
        if good != last_commit_status.totalCount:
            logger.info(
                f"Only {good}/{last_commit_status.totalCount} CI checks ok, skipping."
            )
            continue
        logger.verbose(f"All {last_commit_status.totalCount} CI checks ok, continuing.")

        if "<!--pre-commit.ci start-->" in pr.body and pr.changed_files == 1:
            if not is_user_precommit_bot(pr.user):
                close_fake_pull_request(repo, pr, "pre-commit.ci")
                continue
            logger.verbose("Authentic pre-commit.ci request!")
            if dry_run:
                continue
            merge_result = merge_precommit_ci_request(repo, pr)
            if merge_result:
                retv.set_ok_if_none()
                retv.changed = True
        elif (
            "You can trigger Dependabot actions by commenting on this PR" in pr.body
            or is_user_dependabot_bot(pr.user)
        ):
            if not is_user_dependabot_bot(pr.user):
                close_fake_pull_request(repo, pr, "dependabot")
                continue
            logger.verbose("Authentic dependabot request!")
            if dry_run:
                continue
            merge_result = merge_dependabot_request(repo, pr)
            if merge_result:
                retv.set_ok_if_none()
                retv.changed = True
        elif (
            "This PR has been generated by Mend Renovate." in pr.body
            or is_user_renovate_bot(pr.user)
        ):
            if not is_user_renovate_bot(pr.user):
                close_fake_pull_request(repo, pr, "renovate")
                continue
            logger.verbose("Authentic renovate request!")
            if dry_run:
                continue
            merge_result = merge_renovate_request(repo, pr)
            if merge_result:
                retv.set_ok_if_none()
                retv.changed = True
        else:  # no match (normal PR)
            logger.info(f'Normal PR, skipping ("{pr.title}" by {pr.user.name})')
            continue

    logger.info(f"Could not find a matching Bot Pull Request in {repo}.")
    retv.set_ok_if_none()
    return retv


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@click.option(
    "--dry/--dry-run",
    "dry_run",
    default=False,
    help="Don't Actually Merge. Default: False",
)
@click.option(
    "--only",
    "repo_name_filter",
    default=None,
    help="Only run on the given repository name.",
)
@click.option(
    "--only-title",
    "pr_title_filter",
    default=None,
    help="Filter to only PRs with this title (does not bypass other PR checks)",
)
@utils.get_click_silent_option()
@utils.get_click_verbosity_option()
def main(
    dry_run: bool,
    repo_name_filter: str,
    pr_title_filter: str,
    silent: bool,
    verbosity: int,
) -> int:
    """Script to loop through all GITHUB repositories (`all-repos-in.json`) and
    squash-merge authentic pre-commit.ci / dependabot / renovate bot pull
    requests.

    This script solely relies on the use of the GitHub API. See
    DEVELOPMENT.adoc for instructions on how to make your token
    accessible to the script.
    """
    utils.init(verbosity=verbosity, silent=silent)
    retv = 1

    if utils.github_api_used_token == "None":
        logger.critical(
            "This script requires a github token "
            "(for merging and doing things to the PRs). Aborting!"
        )
        return retv

    def repo_name_filter_fn(repo_name_in: str) -> bool:
        if repo_name_filter is None:
            return True
        return repo_name_in == repo_name_filter

    results = {
        repo_path.name: MergeProcedureResult(repo_name_in=repo_path.name)
        for repo_path in get_all_cloned_github_repositories()
        if repo_name_filter_fn(repo_path.name)
    }
    for result in results.values():
        try:
            results[result.path.name] = run_procedure_for(
                result, dry_run, pr_title_filter
            )
        except CalledProcessError:
            retv = 1
            results[result.path.name].all_ok = False
            # error information logging handled by `script_utils.execute`:
            pass
        except GithubException:
            retv = 1
            results[result.path.name].all_ok = False
            # exc_info will printStackTrace the current exception
            logger.error(
                f"GithubException occured for procedure of {result.path.name}.",
                exc_info=True,
            )
            pass

    not_ok_results: list[MergeProcedureResult] = [
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
