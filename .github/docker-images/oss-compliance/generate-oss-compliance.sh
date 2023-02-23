# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/bin/bash

PRETTY_NAME=$(cat /etc/os-release | grep PRETTY_NAME)

HOME_DIR=$(pwd)

export HOME_DIR=${HOME_DIR}
LINUX_PACKAGES=${HOME_DIR}/linux-packages
BUILD_FROM_SOURCE_PACKAGES_LICENCES=${HOME_DIR}/build-from-source-packages/build-from-source-package-licenses.txt

set -e

chmod +x ${LINUX_PACKAGES}/yum-packages.sh
chmod +x ${LINUX_PACKAGES}/dpkg-packages.sh

if [[ $PRETTY_NAME == *"Ubuntu"* || $PRETTY_NAME == *"Debian"* ]]; then
  ${LINUX_PACKAGES}/dpkg-packages.sh
fi

if [[ $PRETTY_NAME == *"Amazon Linux"* || $PRETTY_NAME == *"Red Hat Enterprise Linux"* || $PRETTY_NAME == *"Fedora"* ]]; then
  ${LINUX_PACKAGES}/yum-packages.sh
fi

cp ${BUILD_FROM_SOURCE_PACKAGES_LICENCES} /root/BUILD_FROM_SOURCE_PACKAGES_LICENCES
chmod +x ${HOME_DIR}/test/test-oss-compliance.sh
bash ${HOME_DIR}/test/test-oss-compliance.sh ${HOME_DIR}