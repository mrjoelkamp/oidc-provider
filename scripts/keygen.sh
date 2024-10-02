#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
cd "${REPO_ROOT}" || exit 1

generate() {
    openssl ecparam -name secp256r1 -genkey -noout -out priv.pem
    openssl ec -in priv.pem -pubout > pub.pem
}

mkdir -p "${REPO_ROOT}/keys"
pushd "${REPO_ROOT}/keys"
generate
popd
