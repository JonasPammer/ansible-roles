from __future__ import annotations

from pathlib import Path
from subprocess import CalledProcessError

import attrs
import click
import github
import yaml
from github import GithubException
from github.NamedUser import NamedUser
from github.PullRequest import PullRequest
from github.PullRequestMergeStatus import PullRequestMergeStatus
from github.Repository import Repository

from ansible_roles import utils
from ansible_roles.utils import console
from ansible_roles.utils import logger
from ansible_roles_scripts import script_utils


@attrs.define
class MergeProcedureResult:
    path: Path
    repo: github.Repository | None = None
    all_ok: bool = False
    changed: bool = False


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


def close_fake_precommit_ci_request(repo: Repository, pr: PullRequest) -> None:
    # never happened but you never know how sleepy or "ok next" you may one time be
    logger.warn(f"Closing fake pre-commit.ci pull request {pr} found in {repo} LOL.")
    pr.create_comment(
        f"""
        Closing this 'pre-commit.ci' pull request as it was deemed fake!
        Nice try.

        {script_utils.COMMIT_MSG}
        """
    )
    pr.edit(status="closed")


def merge_dependabot_request(repo: Repository, pr: PullRequest) -> bool:
    commit_title = pr.title
    if not commit_title.startswith("chore(deps)"):
        commit_title = "chore(deps): " + commit_title
    commit_title += f" (#{pr.number})"
    commit_title += f"\n {script_utils.COMMIT_MSG}"

    logger.verbose(f"Attempting to squash-merge {pr} of {repo}...")
    result: PullRequestMergeStatus = pr.merge(
        commit_title=commit_title, merge_method="squash"
    )
    if not result.merged:
        logger.error(f"{pr} reported that it did not merge! Message: {result.message}")
        return False
    logger.success(f"Successfully merged {pr} for {repo}.")
    return True


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
    autoupdate_commit_msg += f" (#{pr.number})"
    autoupdate_commit_msg += f"\n {script_utils.COMMIT_MSG}"

    logger.verbose(f"Attempting to squash-merge {pr} of {repo}...")
    result: PullRequestMergeStatus = pr.merge(
        commit_title=autoupdate_commit_msg, merge_method="squash"
    )
    if not result.merged:
        logger.error(f"{pr} reported that it did not merge! Message: {result.message}")
        return False
    logger.success(f"Successfully merged {pr} for {repo}.")
    return True


def run_procedure_for(path: Path) -> MergeProcedureResult:
    console.rule(f"{path}")
    logger.verbose(f"Start procedure for '{path}'")
    retv = MergeProcedureResult(path=path)
    repo = retv.repo = utils.github_api.get_repo(f"JonasPammer/{ path.name }")

    pull_requests = repo.get_pulls()
    if pull_requests.totalCount == 0:
        retv.all_ok = True
        logger.info(f"{repo} has no pull requests.")
        return retv

    # TODO add check to only merge if all CI checks are ok
    # PullRequest has no adhoc thing to check for this the way githubs UI warns/does

    for pr in pull_requests:
        logger.verbose(f"Checking pull request {pr} of {repo}...")
        if "<!--pre-commit.ci start-->" in pr.body and pr.changed_files == 1:
            if not is_user_precommit_bot(pr.user):
                close_fake_precommit_ci_request(repo, pr)
                continue
            logger.verbose(
                f"Recognized {pr} of {repo} as an authentic pre-commit.ci request!"
            )
            retv.all_ok = merge_precommit_ci_request(repo, pr)
            if retv.all_ok:
                retv.changed = retv.all_ok
            continue
        if is_user_dependabot_bot(pr.user):
            logger.verbose(
                f"Recognized {pr} of {repo} as an authentic dependabot request!"
            )
            retv.all_ok = merge_dependabot_request(repo, pr)
            if retv.all_ok:
                retv.changed = retv.all_ok
            continue

    logger.info(f"Could not find a matching Bot Pull Request in {repo}.")
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

    if utils.github_api_used_token == "None":
        logger.critical(
            "This script requires a github token "
            "(for merging and doing things to the PRs). Aborting!"
        )
        return retv

    all_repos: list[Path] = script_utils.get_all_cloned_github_repositories()
    results = {
        repo_path.name: MergeProcedureResult(path=repo_path) for repo_path in all_repos
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
