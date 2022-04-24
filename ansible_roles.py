from __future__ import annotations

import json
from typing import Sequence

import attrs
from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape
from rich.console import Console
from rich.traceback import install as install_rich_traceback


console = Console()


@attrs.define
class AnsibleRole:
    repo_name: str
    repo_pull_url: str


def main(argv: Sequence[str] | None = None) -> int:
    retv = 0
    install_rich_traceback(show_locals=True)
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(),
    )
    template = env.get_template("README.adoc.jinja2")

    with open("all-repos-in.json") as f:
        all_repos_in = json.load(f)

    all_roles: list[AnsibleRole] = []

    for key in all_repos_in:
        role = AnsibleRole(repo_name=key, repo_pull_url=all_repos_in[key])
        if not role.repo_name.startswith("ansible-role"):
            continue
        # TODO request github api info and turn relevant things into vars of role
        # TODO cache results from above requests for future runs
        #      (invalidated after xyz time passed of course)
        #      (also, make the github action cache the cache file for its future runs)
        all_roles.append(role)

    with open("README.adoc", "w") as f:
        f.write(template.render(all_roles=all_roles))

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
