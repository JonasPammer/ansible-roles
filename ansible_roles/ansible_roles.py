from __future__ import annotations

import click
from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape

from ansible_roles import utils
from ansible_roles.utils import logger


@click.command(
    context_settings=dict(
        max_content_width=120, help_option_names=["--help", "--usage"]
    )
)
@utils.get_click_silent_option()
@utils.get_click_verbosity_option()
def main(
    silent: bool,
    verbosity: int,
) -> int:
    """Fetch information about all ansible roles (`all-repos-in.json`) using
    the Github API, compute additional things (dependencies), and render all
    Jinja2 templates.

    Note that this does not execute any command - not even to generate
    the graphs' png/svg. But don't worry, CI does not only run this
    script but takes care of that and everything else (as a good boy CI
    should ;).
    """
    utils.init(verbosity=verbosity, silent=silent)
    retv = 0
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(),
    )

    with open("README.adoc", "w", encoding="utf-8") as f:
        f.write(
            env.get_template("README.adoc.jinja2").render(all_roles=utils.all_roles)
        )
        logger.success(f"Successfully generated '{f.name}'.")
    with open("graphs/dependencies_ALL.dot", "w", encoding="utf-8") as f:
        f.write(
            env.get_template("dependencies_ALL.dot.jinja2").render(
                all_roles=utils.all_roles
            )
        )
        logger.success(f"Successfully generated '{f.name}'.")

    template_dependencies_single = env.get_template("dependencies_single.dot.jinja2")
    for input_galaxy_role_name, input_role in utils.all_roles.items():
        filtered_roles = utils.recurse_add_dependencies(input_role)

        with open(f"graphs/dependencies_{input_role.role_name}.dot", "w") as f:
            logger.verbose(f"Generating '{f.name}'...")
            f.write(
                template_dependencies_single.render(
                    all_roles=filtered_roles, input_role=input_role
                )
            )
            logger.success(f"Successfully generated '{f.name}'.")

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
