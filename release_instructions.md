# Release Process

If you haven't released Atheris before, do the "Getting Set Up" section first.

## Release Process

### Run copybara to copy to git-on-borg

Atheris uses go/copybara to modify its code before pushing to public repos.
Config: http://google3/third_party/py/atheris/copy.bara.sky

NOTE Copybara modifies the code during this process.

First, create a CL to associate with the release, but do not submit it. Then,
run the following command to create a GoB PR.

```bash
copybara third_party/py/atheris/copy.bara.sky postsubmit_piper_to_gob
```

### Fetch from git-on-borg to my machine.

```bash
git clone sso://partner-code/_direct/atheris
```

NOTE the rpc://partner-code/atheris version should be avoided because it will
prevent you from pushing later.

### (Optional) Run OSS tests.

NOTE These tests are run automatically as part of the deploy_pypi.sh script
below, so this step is not strictly necessary.

NOTE this run after copybara modifies the code, so it's not 1:1 w/ the google3
tests.

Run the `./run_tests.sh` script in the root dir of the Atheris git repo.

### Build and Release.

This step assumes you have docker installed, as well as the python packages venv
and pip. Make sure you have everything from the "Getting Set Up" section
installed before proceeding.

NOTE This step takes a while.

From within a clean git repo, run the following command to build the code to be
released and pushes it to testpypi. It then downloads Atheris from testpypi and
runs the unit tests. If they pass, it also uploads to pypi.

```bash
./deployments/deploy_pypi.sh
```

## Getting Set Up

You should only ever have to run these once on any single machine.

### Git

Make sure you install the following command for the git cli to support GoB:

```bash
sudo apt install git-remote-google
```

### Docker

Make sure you have Docker installed. See go/installdocker.

### Copybara

Install the ISE hashbang profile to get access to the common tools used in this
document:

```bash
sudo apt install hashbang-ise
```
