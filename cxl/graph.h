/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2022 Fan Ni <fan.ni@samsung.com> */
/* Copyright (C) 2022 Matthew Ho <sunfishho12@gmail.com> */
#ifndef _CXL_TOPOLOGY_GRAPH_H_
#define _CXL_TOPOLOGY_GRAPH_H_

#include <stdbool.h>
#include <json-c/json.h>

enum output_file_type {
		FILE_PLAIN,
		FILE_GRAPH,
		FILE_UNSUPPORTED,
};

struct json_object;
void create_image(const char *filename, json_object *platform);
int output_file_type(const char *file_name);
struct json_object *parse_json_text(const char *path);
#endif
