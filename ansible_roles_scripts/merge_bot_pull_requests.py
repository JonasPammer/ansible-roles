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


def close_fake_precommit_ci_request(pr: PullRequest) -> None:
    pr.create_comment(
        f"""
                      Closing this 'pre-commit.ci' pull request as it was deemed fake!
                      Nice try.

                      {script_utils.COMMIT_MSG}
                      """
    )
    pr.edit(status="closed")


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

    for pr in pull_requests:
        logger.verbose(f"Checking pull request {pr}...")
        if not ("<!--pre-commit.ci start-->" in pr.body and pr.changed_files == 1):
            continue
        if not is_user_precommit_bot(pr.user):
            logger.warning(
                "Recognized {pr} as an fake pre-commit.ci request. Closing it!"
            )
            close_fake_precommit_ci_request(pr)
            continue
        logger.verbose(f"Recognized {pr} as an authentic pre-commit.ci request!")
        retv.all_ok = merge_precommit_ci_request(repo, pr)
        retv.changed = True
        # return as I and this procedure assume that
        # only one PR from pre-commit.ci may exist
        return retv

    logger.info(f"Could not find a pre-commit.ci Pull Request in {repo}.")
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
