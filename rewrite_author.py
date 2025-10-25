def commit_callback(commit):
    if commit.author_email.decode("utf-8") == "ainembabaziluciarachel02@gmail.com":
        commit.author_name = "Lucy-dev1999".encode("utf-8")
        commit.author_email = "ainembabaziluciarachel02@gmail.com".encode("utf-8")
    if commit.committer_email.decode("utf-8") == "ainembabaziluciarachel02@gmail.com":
        commit.committer_name = "Lucy-dev1999".encode("utf-8")
        commit.committer_email = "ainembabaziluciarachel02@gmail.com".encode("utf-8")
