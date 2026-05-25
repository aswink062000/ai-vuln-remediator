from pathlib import Path


def patch_file(repo_path, relative_path, new_content):
    full_path = Path(repo_path) / relative_path

    full_path.write_text(new_content)