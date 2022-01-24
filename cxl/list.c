// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020-2022 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <util/json.h>
#include <json-c/json.h>
#include <cxl/libcxl.h>
#include <util/parse-options.h>

#include "filter.h"

static struct cxl_filter_params param;

static const struct option options[] = {
	OPT_STRING('m', "memdev", &param.memdev_filter, "memory device name(s)",
		   "filter by CXL memory device name(s)"),
	OPT_STRING('s', "serial", &param.serial_filter,
		   "memory device serial(s)",
		   "filter by CXL memory device serial number(s)"),
	OPT_BOOLEAN('M', "memdevs", &param.memdevs,
		    "include CXL memory device info"),
	OPT_STRING('b', "bus", &param.bus_filter, "bus device name",
		   "filter by CXL bus device name(s)"),
	OPT_BOOLEAN('B', "buses", &param.buses, "include CXL bus info"),
	OPT_STRING('p', "port", &param.port_filter, "port device name",
		   "filter by CXL port device name(s)"),
	OPT_BOOLEAN('P', "ports", &param.ports, "include CXL port info"),
	OPT_BOOLEAN('S', "single", &param.single,
		    "skip listing descendant objects"),
	OPT_BOOLEAN('i', "idle", &param.idle, "include disabled devices"),
	OPT_BOOLEAN('u', "human", &param.human,
		    "use human friendly number formats "),
	OPT_BOOLEAN('H', "health", &param.health,
		    "include memory device health information "),
	OPT_END(),
};

static int num_list_flags(void)
{
       return !!param.memdevs + !!param.buses + !!param.ports;
}

int cmd_list(int argc, const char **argv, struct cxl_ctx *ctx)
{
	const char * const u[] = {
		"cxl list [<options>]",
		NULL
	};
	int i;

	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);

	if (param.single && !param.port_filter) {
		error("-S/--single expects a port filter: -p/--port=\n");
		usage_with_options(u, options);
	}

	if (num_list_flags() == 0) {
		if (param.memdev_filter || param.serial_filter)
			param.memdevs = true;
		if (param.bus_filter)
			param.buses = true;
		if (param.port_filter)
			param.ports = true;
		if (num_list_flags() == 0) {
			/*
			 * TODO: We likely want to list regions by default if
			 * nothing was explicitly asked for. But until we have
			 * region support, print this error asking for devices
			 * explicitly.  Once region support is added, this TODO
			 * can be removed.
			 */
			error("please specify entities to list, e.g. using -m/-M\n");
			usage_with_options(u, options);
		}
	}

	log_init(&param.ctx, "cxl list", "CXL_LIST_LOG");

	if (cxl_filter_has(param.port_filter, "root") && param.ports)
		param.buses = true;

	return cxl_filter_walk(ctx, &param);
}
