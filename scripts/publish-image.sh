#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: publish-image.sh VERSION}
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Expected a stable semantic version, got: $version" >&2
  exit 1
fi

repository=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}
image="ghcr.io/$(printf '%s' "$repository" | tr '[:upper:]' '[:lower:]')"

docker build --tag "$image:$version" --tag "$image:latest" .
docker push "$image:$version"
docker push "$image:latest"
