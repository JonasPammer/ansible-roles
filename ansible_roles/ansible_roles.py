from __future__ import annotations

from typing import Sequence

from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape

from ansible_roles import utils


def main(argv: Sequence[str] | None = None) -> int:
    retv = 0
    utils.init()
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(),
    )

    with open("README.adoc", "w", encoding="utf-8") as f:
        f.write(
            env.get_template("README.adoc.jinja2").render(all_roles=utils.all_roles)
        )
    with open("graphs/dependencies_ALL.dot", "w", encoding="utf-8") as f:
        f.write(
            env.get_template("dependencies_ALL.dot.jinja2").render(
                all_roles=utils.all_roles
            )
        )

    template_dependencies_single = env.get_template("dependencies_single.dot.jinja2")
    for input_galaxy_role_name, input_role in utils.all_roles.items():
        filtered_roles = utils.recurse_add_dependencies(input_role)

        with open(f"graphs/dependencies_{input_role.role_name}.dot", "w") as f:
            f.write(
                template_dependencies_single.render(
                    all_roles=filtered_roles, input_role=input_role
                )
            )

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
