@echo off
set FILTER_BRANCH_SQUELCH_WARNING=1
git filter-branch -f --env-filter "if [ \"$GIT_AUTHOR_NAME\" = \"Ainembabazi Lucia Rachel\" ]; then export GIT_AUTHOR_NAME=\"Lucy-dev1999\"; export GIT_COMMITTER_NAME=\"Lucy-dev1999\"; fi" -- --all
