# Releasing the local proxy

The process for cutting a local proxy release. Use previous releases as
examples. CI builds the binaries; tagging and publishing are manual.

## Versioning

The `version` file at the repo root is the single source of truth, and tags are
`vX.Y.Z` to match. By default the short commit is appended as SemVer build
metadata (`v3.3.1+abc1234`); `-DLOCALPROXY_RELEASE=ON` reports the bare release
version instead, and every job that uploads a publishable binary sets it. See
[BUILD.md](BUILD.md) for the flag tables.

## Process

### 1. Prepare

- CI is green on `main`.
- Local `main` is up to date.

### 2. Open the release PR

From a `dev/<short-kebab-name>` branch, updating just the release notes and the
version. Title it "Release vX.Y.Z"; the body can be blank.

- Add a new section at the top of `CHANGELOG.md`, headed with the release date,
  listing the features and fixes customers should know about under `### Added`,
  `### Changed` and `### Fixed`. Describe each entry in terms of the feature it
  affects; skip commits with no customer impact.
- Bump the `version` file to `X.Y.Z`.
- Merge the PR once it is green.

### 3. Tag the release commit

- Tag with `git tag -a vX.Y.Z` — annotated, not lightweight.
- Title the tag message "Release vX.Y.Z" and use the new `CHANGELOG.md` section
  as the description, with the markdown markup removed and wrapped at 79 columns
  to match git conventions.
- Verify the tag is annotated, then push it.

### 4. Collect the artifacts

From the workflow runs of the release commit on `vX.Y.Z`.

- From `uat-and-release.yml`:
  - `localproxy-linux-x86_64.zip`
  - `localproxy-linux-aarch64.zip`
  - `localproxy-linux-armv7.zip`
- From `build-and-test.yml`:
  - `localproxy-macos-arm64.zip`
  - `localproxy-windows-x64.zip`

### 5. Publish the GitHub release

- Create the release from the tag, reusing the tag message as the title and
  body. Unwrap the lines, since GitHub does not rewrap them.
- Attach the five zipped artifacts.

Nothing in steps 3 and 5 is automated: no workflow creates a tag or publishes a
release.

## Notes

- The `uat-and-release.yml` jobs are gated on
  `github.repository == 'aws-samples/aws-iot-securetunneling-localproxy'` and
  skip pull requests from forks, so they do not run on a fork.
- Workflow artifacts expire with the repository's retention setting; re-run the
  workflow if they have aged out.
- Container images release separately from `release.yml`, which pushes the
  ubuntu, ubi8 and amazonlinux images to ECR.
- If a dependency moved, bump it in `fc_deps.json` and refresh
  `THIRD_PARTY_LICENSES` and the oss-compliance license list.
