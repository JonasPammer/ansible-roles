#!/bin/bash


function echo_err() {
    echo -e "\e[41m ${*} \e[49m"
}
function echo_meh() {
    echo -e "\e[103m ${*} \e[49m"
}
pwd=$(pwd)

for d in ./all-repos/ansible-role-*; do
    cd "$pwd"
    cd "$d"
    git pull --rebase
    pre-commit install
    if [[ $? -ne 0 ]]; then
        echo_err "$d: pre-commit install exited with error status? aborting"
        exit 1
    fi
    cruft update -y
    if [[ $? -ne 0 ]]; then
        echo_err "$d: cruft exited with error status. aborting"
        exit 1
    fi

    rej=$(find "$d" -name "*.rej")
    if [[ -n "$rej" ]]; then
        echo_err "$d contains rejected cookiecutter update alteration informations. skipping"
        echo_err "$rej"
        continue
    fi

    conf=$(git diff --diff-filter=U)
    if [[ -n "$rej" ]]; then
        echo_err "$d contains git merge conflicts. skipping"
        echo_err "$conf"
        continue
    fi

    # no *.rej or merge conflicts
    git add .
    git commit -m "chore: cruft update"
    git add . # pre-commit auto fixes
    git commit -m "chore: cruft update"

    if [[ $? -ne 0 ]]; then
        echo_meh "$d contains pre-commit errors or has nothing to commit. not pushing"
    fi

    git push
done