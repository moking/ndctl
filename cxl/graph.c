// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2022 Fan Ni <fan.ni@samsung.com>
// Copyright (C) 2022 Matthew Ho <sunfishho12@gmail.com>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <util/json.h>
#include <json-c/json.h>
#include <cxl/libcxl.h>
#include <util/parse-options.h>

#include <graphviz/gvc.h>
#include <util/util.h>
#include <util/log.h>

#include "filter.h"
#include "graph.h"

static struct cxl_filter_params param;
static bool debug;

static bool device_has_dport(struct json_object *dev)
{
	json_object_object_foreach(dev, property, value_json) {
		if (!strcmp(property, "nr_dports"))
			return true;
	}

	return false;
}

static struct json_object *convert_json_obj_to_array(struct json_object *obj)
{
	struct json_object *arr = json_object_new_array();

	json_object_array_add(arr, obj);

	return arr;
}

static Agnode_t *create_node(Agraph_t *graph, char *label, bool created)
{
	return agnode(graph, label, created);
}

static const char *find_device_type(struct json_object *device)
{
	char *value;
	int depth = -1;
	bool is_device = false;

	json_object_object_foreach(device, property, value_json) {
		value = (char *)json_object_get_string(value_json);
		if (!strcmp(property, "bus") &&
		    !strcmp(value, "root0"))
			return "ACPI0017 Device";
		if (!strcmp(property, "depth")) {
			depth = json_object_get_int(value_json);
			if (is_device) {
				if (depth == 1)
					return "Host Bridge";
				else
					return "Switch Port";
			}
		}
		if (!strcmp(property, "endpoint"))
			return "Endpoint";
		if (!strcmp(property, "parent_dport")) {
			is_device = true;
			if (depth == 1)
				return "Host Bridge";
			if (depth > 1)
				return "Switch Port";
		}
		if (!strcmp(property, "memdev"))
			return "Type 3 Memory Device";
		if (!strcmp(property, "dport"))
			return "dport";
		if (!strcmp(property, "decoder"))
			return "decoder";
		if (!strcmp(property, "provider") &&
		    !strcmp(value, "cxl_test"))
			return "cxl_acpi.0";
	}

	return "unknown device";
}

static bool check_device_type(struct json_object *device, char *type)
{
	return !strcmp(find_device_type(device), type);
}

/* for labeling purposes */
static const char *find_device_ID(struct json_object *device)
{
	const char *dev_type = find_device_type(device);
	json_object *ID = NULL;

	if (!strcmp(dev_type, "ACPI0017 Device"))
		json_object_object_get_ex(device, "bus", &ID);

	if (!strcmp(dev_type, "Host Bridge")
		|| !strcmp(dev_type, "Switch Port"))
		json_object_object_get_ex(device, "host", &ID);

	if (!strcmp(dev_type, "Endpoint"))
		json_object_object_get_ex(device, "endpoint", &ID);

	if (!strcmp(dev_type, "Type 3 Memory Device"))
		json_object_object_get_ex(device, "memdev", &ID);

	if (!strcmp(dev_type, "dport"))
		json_object_object_get_ex(device, "dport", &ID);

	return json_object_get_string(ID);
}

static bool is_device(struct json_object *device)
{
	const char *dev_type = find_device_type(device);

	return (strcmp(dev_type, "dport") && strcmp(dev_type, "decoder"));
}

static const char *find_parent_dport(struct json_object *device)
{
	json_object *rp;

	if (!json_object_object_get_ex(device, "parent_dport", &rp))
		return NULL;

	return json_object_get_string(rp);
}

static char *find_parent_dport_label(struct json_object *device)
{
	char *rp_node_name;
	const char *id = find_parent_dport(device);

	if (!id)
		return NULL;

	asprintf(&rp_node_name, "dPort\nID: %s", id);
	if (!rp_node_name)
		error("asprintf failed in %s\n", __func__);

	return rp_node_name;
}

static char *find_root_port_label(struct json_object *device)
{
	char *rp_node_name;
	const char *id = find_parent_dport(device);

	if (!id)
		return NULL;

	asprintf(&rp_node_name, "Root Port\nID: %s", id);
	if (!rp_node_name)
		error("asprintf failed in %s\n", __func__);

	return rp_node_name;
}

static char *label_device(struct json_object *device)
{
	char *label;
	const char *ID = find_device_ID(device);
	const char *devname = find_device_type(device);

	asprintf(&label, "%s\nID: %s", devname, ID);
	if (!label)
		error("label allocation failed in %s\n", __func__);

	return label;
}

static void create_root_ports(struct json_object *host_bridge, Agraph_t *graph,
		       Agnode_t *hb)
{
	json_object *rps, *rp, *id_json;
	char *id, *dport_label;
	Agnode_t *dport;
	size_t nr_dports, idx;

	assert(check_device_type(host_bridge, "Host Bridge"));
	if (!json_object_object_get_ex(host_bridge, "dports", &rps)) {
		dbg(&param, "no dports attribute found at host bridge\n");
		return;
	}

	nr_dports = json_object_array_length(rps);
	for (idx = 0; idx < nr_dports; idx++) {
		rp = json_object_array_get_idx(rps, idx);
		json_object_object_get_ex(rp, "dport", &id_json);
		id = (char *)json_object_get_string(id_json);
		asprintf(&dport_label, "Root Port\nID: %s", id);
		if (!dport_label)
			error("label allocation failed when creating root port\n");
		dport = create_node(graph, dport_label, 1);
		agedge(graph, hb, dport, 0, 1);
		free(dport_label);
	}
}

static void create_downstream_ports(struct json_object *sw_port,
		Agraph_t *graph, Agnode_t *sw)
{
	json_object *dps, *dp, *id_json;
	char *id, *dport_label;
	Agnode_t *dport;
	size_t nr_dports, idx;

	assert(check_device_type(sw_port, "Switch Port"));
	if (!json_object_object_get_ex(sw_port, "dports", &dps)) {
		dbg(&param, "no dports attribute found at switch port\n");
		return;
	}

	nr_dports = json_object_array_length(dps);
	for (idx = 0; idx < nr_dports; idx++) {
		dp = json_object_array_get_idx(dps, idx);
		json_object_object_get_ex(dp, "dport", &id_json);
		id = (char *)json_object_get_string(id_json);
		asprintf(&dport_label, "dPort\nID: %s", id);
		if (!dport_label)
			error("label allocation failed when creating downstream port\n");
		dport = create_node(graph, dport_label, 1);
		agedge(graph, sw, dport, 0, 1);
		free(dport_label);
	}
}

/* for determining number of devices listed in a json array */
static size_t count_top_devices(struct json_object *top_array)
{
	size_t dev_counter = 0;
	size_t top_array_len = json_object_array_length(top_array);

	for (size_t idx = 0; idx < top_array_len; idx++)
		if (is_device(json_object_array_get_idx(top_array, idx)))
			dev_counter++;

	return dev_counter;
}

static Agnode_t **draw_subtree(struct json_object *current_array,
			       Agraph_t *graph)
{
	size_t json_array_len, nr_top_devices, obj_idx, td_idx;
	size_t idx, nr_sub_devs, nr_devs_connected;
	char *label, *parent_dport_label;
	Agnode_t **top_devices, **sub_devs, *parent_node;
	bool is_hb, is_sw;
	json_object *device, *subdev_arr, *subdev;
	json_object_iter subdev_iter;

	json_array_len = json_object_array_length(current_array);
	nr_top_devices = count_top_devices(current_array);

	if (!nr_top_devices) {
		dbg(&param, "no top devices, return directly\n");
		return NULL;
	}

	top_devices = malloc(nr_top_devices * sizeof(device));
	if (!top_devices) {
		error("allocate memory for top_devices failed\n");
		return NULL;
	}

	td_idx = 0;
	for (obj_idx = 0; obj_idx < json_array_len; obj_idx++) {
		device = json_object_array_get_idx(current_array, obj_idx);
		if (!is_device(device))
			continue;

		label = label_device(device);
		top_devices[td_idx] = create_node(graph, label, 1);

		agsafeset(top_devices[td_idx], "shape", "box", "");

		is_hb = check_device_type(device, "Host Bridge");
		is_sw = check_device_type(device, "Switch Port");

		if ((is_hb || is_sw) && !device_has_dport(device)) {
			error("no nr_dports attribute in the json obj for %s\n",
					is_hb ? "CXL host bridge" : "CXL switch");
			return top_devices;
		}

		/* Create root port nodes if device is a host bridge */
		if (is_hb)
			create_root_ports(device, graph, top_devices[td_idx]);
		else if (is_sw)
			create_downstream_ports(device, graph, top_devices[td_idx]);

		free(label);

		/* Iterate through all keys and values of an object (device) */
		json_object_object_foreachC(device, subdev_iter) {
			bool is_endpoint = check_device_type(device, "Endpoint");
			char *key = subdev_iter.key;

			subdev_arr = subdev_iter.val;
			if (is_endpoint && !strcmp(key, "memdev"))
				subdev_arr = convert_json_obj_to_array(subdev_arr);

			if (!json_object_is_type(subdev_arr, json_type_array))
				continue;
			nr_sub_devs = count_top_devices(subdev_arr);
			sub_devs = draw_subtree(subdev_arr, graph);
			if (!sub_devs)
				continue;
			if (!is_hb && !is_sw) {
				for (idx = 0; idx < nr_sub_devs; idx++)
					agedge(graph, top_devices[td_idx], sub_devs[idx], 0, 1);
				free(sub_devs);
				continue;
			}

			nr_devs_connected = 0;
			for (idx = 0;
			     idx < json_object_array_length(subdev_arr);
			     idx++) {
				subdev = json_object_array_get_idx(subdev_arr, idx);
				if (!is_device(subdev))
					continue;

				if (is_hb)
					parent_dport_label = find_root_port_label(subdev);
				else
					parent_dport_label = find_parent_dport_label(subdev);
				if (!parent_dport_label) {
					error("graph function requires parent_dport attribute\n");
					return NULL;
				}
				/* with flag = 0, it will search to locate an existing node */
				parent_node = create_node(graph, parent_dport_label, 0);
				if (parent_node) {
					agedge(graph, parent_node,
						sub_devs[nr_devs_connected ++], 0, 1);
					free(parent_dport_label);
				} else {
					dbg(&param, "create parent node failed: %s\n",
						parent_dport_label);
				}
			}
			free(sub_devs);
		}
		td_idx ++;
	}

	return top_devices;
}

struct json_object *parse_json_text(const char *path)
{
	FILE *fp;
	char *json_as_string;
	size_t file_len;
	json_object *json;

	fp = fopen(path, "r");
	if (!fp)
		error("could not read file\n");
	fseek(fp, 0, SEEK_END);
	file_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	json_as_string = malloc(file_len + 1);
	if (!json_as_string ||
	    fread(json_as_string, 1, file_len, fp) != file_len) {
		free(json_as_string);
		error("could not read file %s\n", path);
	}
	json_as_string[file_len] = '\0';
	json = json_tokener_parse(json_as_string);
	return json;
}

int output_file_type(const char *file_name)
{
	/* skip ./, ../ in the path */
	char *of_extension = strrchr(file_name, '/');

	if (!of_extension)
		of_extension = (char *)file_name;
	else
		of_extension += 1;

	of_extension = strrchr(of_extension, '.');
	if (!of_extension)
		return FILE_PLAIN;
	of_extension += 1;
	if (!strcmp(of_extension, "json") ||
			!strcmp(of_extension, "log") || !strcmp(of_extension, "txt"))
		return FILE_PLAIN;
	else if ((strcmp(of_extension, "png") && strcmp(of_extension, "jpeg") &&
				strcmp(of_extension, "jpg"))) {
		error("Unsupported output file type: %s", file_name);
		return FILE_UNSUPPORTED;
	} else
		return FILE_GRAPH;
}

void create_image(const char *filename, json_object *platform)
{
	char *output_file = (char *)filename;
	GVC_t *gvc;
	Agraph_t *graph;
	char *of_extension = strrchr(output_file, '.') + 1;
	Agnode_t **top_devices;
	FILE *FP;

	gvc = gvContext();
	if (!gvc) {
		error("Creating gvContext failed");
		return;
	}
	graph = agopen("graph", Agdirected, 0);
	if (!graph) {
		error("agopen failed when creating cxl topology image");
		goto free_ctx;
	}

	if (!of_extension || (strcmp(of_extension, "png") &&
			strcmp(of_extension, "jpeg") &&
			strcmp(of_extension, "jpg"))) {
		error("unsupported output image type, only png/jpeg/jpg supported\n");
		goto close_graph;
	}

	top_devices = draw_subtree(platform, graph);
	if (top_devices)
		free(top_devices);

	if (gvLayout(gvc, graph, "dot")) {
		error("gvLayout failed when creating cxl topology image");
		goto close_graph;
	}

	FP = fopen(output_file, "w");
	if (!FP) {
		error("open %s for storing the graph failed", output_file);
		goto create_exit;
	} else {
		gvRender(gvc, graph, strrchr(output_file, '.') + 1, FP);
		fclose(FP);
	}

create_exit:
	gvFreeLayout(gvc, graph);
close_graph:
	agclose(graph);
free_ctx:
	gvFreeContext(gvc);
}

static const struct option options[] = {
	OPT_BOOLEAN('i', "idle", &param.idle, "include disabled devices"),
	OPT_STRING(0, "input", &param.input_file,
		   "input file path for creating topology image",
		   "path to file containing a json array describing the topology"),
	OPT_STRING('o', "output-file", &param.output_file, "output file path",
		   "path to file to generate graph or dump cxl topology to"),
	OPT_INCR('v', "verbose", &param.verbose, "increase output detail"),
#ifdef ENABLE_DEBUG
	OPT_BOOLEAN(0, "debug", &debug, "debug list walk"),
#endif
	OPT_END(),
};

int cmd_graph(int argc, const char **argv, struct cxl_ctx *ctx)
{
	const char * const u[] = {
		"cxl graph [<options>]",
		NULL
	};
	int i;
	json_object *platform;

	param.verbose = 1;
	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);

	if (!param.output_file) {
		dbg(&param, "no output file given, using topology.png by default");
		param.output_file = "topology.png";
	}

	if (param.input_file) {
		if (access(param.input_file, R_OK)) {
			error("input file %s cannot be accessed\n", param.input_file);
			return 0;
		}

		platform = parse_json_text(param.input_file);
		create_image(param.output_file, platform);
		json_object_put(platform);

		return 0;
	}

	switch (param.verbose) {
	default:
	case 3:
	case 2:
		param.idle = true;
	case 1:
		param.memdevs = true;
		param.buses = true;
		param.ports = true;
		param.endpoints = true;
		param.targets = true;
	case 0:
		break;
	}

	log_init(&param.ctx, "cxl graph", "CXL_GRAPH_LOG");
	if (debug) {
		cxl_set_log_priority(ctx, LOG_DEBUG);
		param.ctx.log_priority = LOG_DEBUG;
	}

	dbg(&param, "walk topology\n");
	platform = cxl_filter_walk(ctx, &param);
	if (!platform)
		return -ENOMEM;

	switch (output_file_type(param.output_file)) {
	case FILE_GRAPH:
		create_image(param.output_file, platform);
		break;
	case FILE_PLAIN:
		FILE *fp;

		fp = fopen(param.output_file, "w+");
		if (!fp)
			error("dump to output file %s failed", param.output_file);
		else {

			/*
			 * we need increase the reference count as util_display_json_array
			 * are called more than once in which the reference count will be
			 * decreased by one each time it is called.
			 */

			json_object_get(platform);
			util_display_json_array(fp, platform, cxl_filter_to_flags(&param));
			fclose(fp);
		}
		break;
	case FILE_UNSUPPORTED:
		error("dump to output file %s skipped due to  unsupported file type"
			, param.output_file);
		break;
	}

	/*util_display_json_array(stdout, platform, cxl_filter_to_flags(&param));*/

	return 0;
}
