#!/bin/bash -Ex
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Intel Corporation. All rights reserved.

rc=77
# 237 is -ENODEV
ERR_NODEV=237

. $(dirname $0)/common
FWCTL="$TEST_PATH"/fwctl

trap 'err $LINENO' ERR

modprobe cxl_test

test -x "$FWCTL" || do_skip "no fwctl"
# disable trap
trap - $(compgen -A signal)
"$FWCTL"
rc=$?

echo "error: $rc"
if [ "$rc" -eq "$ERR_NODEV" ]; then
	do_skip "no fwctl char dev"
elif [ "$rc" -ne 0 ]; then
	echo "fail: $LINENO" && exit 1
fi

trap 'err $LINENO' ERR

_cxl_cleanup
