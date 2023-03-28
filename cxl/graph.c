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

static struct cxl_filter_params param;
static bool debug;

static bool device_has_parent_dport(struct json_object *dev)
{
	json_object_object_foreach(dev, property, value_json) {
		if (!strcmp(property, "parent_dport"))
			return true;
	}

	return false;
}

static bool device_has_dport(struct json_object *dev)
{
	json_object_object_foreach(dev, property, value_json) {
		if (!strcmp(property, "nr_dports"))
			return true;
	}

	return false;
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

	dbg(&param, "unknown device:\n%s\n",
		json_object_to_json_string_ext(device, JSON_C_TO_STRING_PRETTY));
	return NULL;
}

static bool check_device_type(struct json_object *device, char *type)
{
	const char *dev_type = find_device_type(device);
	if (dev_type)
		return !strcmp(dev_type, type);
	return false;
}

/* for labeling purposes */
static const char *find_device_ID(struct json_object *device)
{
	const char *dev_type = find_device_type(device);
	json_object *ID = NULL;

	if(!dev_type)
		return NULL;

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
	
	if (dev_type)
		return (strcmp(dev_type, "dport") && strcmp(dev_type, "decoder"));
	return false;
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

	assert(devname);
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

static Agnode_t *plot_anon_memdevs(struct json_object *current_array,
		Agraph_t *graph)
{
	size_t json_array_len, nr_top_devices;
	size_t idx;
	Agnode_t *node, *root;
	char *label;
	json_object *device;

	json_array_len = json_object_array_length(current_array);
	nr_top_devices = count_top_devices(current_array);
	if(!nr_top_devices)
		return NULL;

	assert(nr_top_devices == json_array_len);
	label = "anon memdevs";
	root = create_node(graph, label, 1);

	for (idx = 0; idx < json_array_len; idx++) {
		device = json_object_array_get_idx(current_array, idx);
		label = label_device(device);
		node = create_node(graph, label, 1);
		agsafeset(node, "shape", "box", "");
		agedge(graph, root, node, 0, 1);
		free(label);
	}
	return root;
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

			if (is_endpoint && !strcmp(key, "memdev")){
				/*subdev_arr = convert_json_obj_to_array(subdev_arr);*/
				Agnode_t *node;

				label = label_device(subdev_iter.val);
				node = create_node(graph, label, 1);
				agsafeset(node, "shape", "box", "");
				free(label);
				agedge(graph, top_devices[td_idx], node, 0, 1);
				break;
			}

			subdev_arr = subdev_iter.val;
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

static void draw_graph(struct json_object *current_array,
		Agraph_t *graph)
{
	size_t json_array_len = json_object_array_length(current_array);
	size_t idx;
	json_object_iter iter;
	json_object *device;
	Agnode_t *anon_memdevs = NULL;
	Agnode_t ** top_devices = NULL;
	size_t num_top_devices = 0;

	if (json_array_len == 1) {
		if (draw_subtree(current_array, graph))
			free(top_devices);
	} else {
		for(idx = 0; idx < json_array_len; idx++){
			device = json_object_array_get_idx(current_array, idx);
			json_object_object_foreachC(device, iter) {
				char *key = iter.key;
				json_object *val = iter.val;

				if (!strcmp(key, "anon memdevs")) {
					anon_memdevs = plot_anon_memdevs(val, graph);
				} else if (!strcmp(key, "buses")) {
					num_top_devices = json_object_array_length(val);
					top_devices = draw_subtree(val, graph);
				} else {
					error("unknown top key from cxl topology\n");
				}
			}
		}
		if (anon_memdevs && top_devices) {
			Agnode_t *root = create_node(graph, "CXL sub-system", 1);
			agsafeset(root, "shape", "box", "");
			agedge(graph, root, anon_memdevs, 0, 1);
			for (idx = 0; idx < num_top_devices; idx ++){
				agedge(graph, root, top_devices[idx], 0, 1);
			}
		}
		if (top_devices)
			free(top_devices);
	}
}

static int create_image(const char *filename, json_object *platform)
{
	int rs = 0;
	char *output_file = (char *)filename;
	GVC_t *gvc;
	Agraph_t *graph;
	char *of_extension = strrchr(output_file, '.');
	FILE *FP;

	gvc = gvContext();
	if (!gvc) {
		error("Creating gvContext failed");
		return -1;
	}
	graph = agopen("graph", Agdirected, 0);
	if (!graph) {
		error("agopen failed when creating cxl topology image");
		rs = -1;
		goto free_ctx;
	}

	if (!of_extension || (strcmp(of_extension, ".png") &&
			strcmp(of_extension, ".jpeg") &&
			strcmp(of_extension, ".jpg"))) {
		error("unsupported output image type, only png/jpeg/jpg supported\n");
		rs = -1;
		goto close_graph;
	}

	draw_graph(platform, graph);
	if (gvLayout(gvc, graph, "dot")) {
		error("gvLayout failed when creating cxl topology image");
		rs = -1;
		goto close_graph;
	}

	FP = fopen(output_file, "w");
	if (!FP) {
		error("open %s for storing the graph failed", output_file);
		rs = -1;
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

	return rs;
}

static const struct option options[] = {
	OPT_BOOLEAN('i', "idle", &param.idle, "include disabled devices"),
	OPT_STRING(0, "input", &param.input_file,
		   "input file path for creating topology image",
		   "path to file containing a json array describing the topology"),
	OPT_STRING('o', "output-file", &param.output_file, "output file path",
		   "path to file to generate graph or dump cxl topology to"),
	OPT_STRING('t', "output-format", &param.output_format, "output format",
		   "way to output cxl topology: plain or graph"),
	OPT_INCR('v', "verbose", &param.verbose, "increase output detail"),
#ifdef ENABLE_DEBUG
	OPT_BOOLEAN(0, "debug", &debug, "debug graph plot"),
#endif
	OPT_END(),
};

static int num_list_flags(void)
{
	return !!param.memdevs + !!param.buses + !!param.ports +
	       !!param.endpoints + !!param.decoders + !!param.regions;
}

static bool validate_cxl_topology_input_helper(json_object *cur_array)
{
	static bool bus_detected = false;
	static bool hb_detected = false;
	static bool memdev_detected = false;
	size_t arr_len, obj_idx;
	size_t nr_top_devices;
	bool is_hb, is_sw, is_endpoint, is_memdev;
	json_object *device;
	json_object_iter subdev_iter;

	arr_len = json_object_array_length(cur_array);
	nr_top_devices = count_top_devices(cur_array);
	if (!nr_top_devices)
		goto validate_exit;

	for (obj_idx = 0; obj_idx < arr_len; obj_idx++) {
		device = json_object_array_get_idx(cur_array, obj_idx);
		if (!is_device(device))
			continue;

		if(check_device_type(device, "ACPI0017 Device"))
			bus_detected = true;

		is_hb = check_device_type(device, "Host Bridge");
		is_sw = check_device_type(device, "Switch Port");
		is_endpoint = check_device_type(device, "Endpoint");
		is_memdev = check_device_type(device, "Type 3 Memory Device");
		if (is_hb)
			hb_detected = true;
		if(is_memdev)
			memdev_detected = true;
		if (is_hb || is_sw)
			if(!device_has_dport(device))
				return false;
		if((is_hb || is_sw || is_endpoint || is_memdev)
			&& !device_has_parent_dport(device))
			return false;

		json_object_object_foreachC(device, subdev_iter) {
			char *key = subdev_iter.key;
			json_object *subdev_arr = subdev_iter.val;
			bool memdev_field_found = is_endpoint && !strcmp(key, "memdev");

			if (!json_object_is_type(subdev_arr, json_type_array)
					&& !memdev_field_found)
				continue;
			/* skip dports list */
			if (!strcmp(key, "dports"))
				continue;
			if (memdev_field_found){
				memdev_detected = true;
				return device_has_parent_dport(subdev_arr);
			}
			else if(!validate_cxl_topology_input_helper(subdev_arr))
				return false;
		}
	}

validate_exit:
	return bus_detected && hb_detected && memdev_detected;
}

static bool validate_cxl_topology_input(json_object *cur_array)
{
	size_t json_array_len = json_object_array_length(cur_array);
	size_t idx;
	json_object_iter iter;
	json_object *device;

	if (json_array_len == 1) {
		return validate_cxl_topology_input_helper(cur_array);
	} else {
		for(idx = 0; idx < json_array_len; idx++){
			device = json_object_array_get_idx(cur_array, idx);
			json_object_object_foreachC(device, iter) {
				char *key = iter.key;
				json_object *val = iter.val;

				if (!strcmp(key, "anon memdevs")) {
					;
				} else if (!strcmp(key, "buses")) {
					if (!validate_cxl_topology_input_helper(val))
						return false;
				} else {
					error("unknown top key from cxl topology: %s\n",
						key);
					return false;
				}
			}
		}
		return true;
	}
}

int cmd_graph(int argc, const char **argv, struct cxl_ctx *ctx)
{
	const char * const u[] = {
		"cxl graph [<options>]",
		NULL
	};
	int i;
	json_object *platform;
	FILE *fp;
	int rs = 0;

	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);

	if (num_list_flags() == 0) {
		param.buses = true;
		param.ports = true;
		param.endpoints = true;
		param.memdevs = true;
		param.targets = true;
	}

	switch (param.verbose) {
	default:
	case 3:
		param.health = true;
		param.partition = true;
		param.alert_config = true;
		/* fallthrough */
	case 2:
		param.idle = true;
		/* fallthrough */
	case 1:
		param.buses = true;
		param.ports = true;
		param.endpoints = true;
		param.decoders = true;
		param.targets = true;
		/*fallthrough*/
	case 0:
		break;
	}

	log_init(&param.ctx, "cxl graph", "CXL_GRAPH_LOG");
	if (debug) {
		cxl_set_log_priority(ctx, LOG_DEBUG);
		param.ctx.log_priority = LOG_DEBUG;
	}

	if(!param.output_format)
		param.output_format = "graph";
	else if (strcmp(param.output_format, "graph")
		&& strcmp(param.output_format, "plain")) {
		error("only plain/graph is accepted for output_format\n");
		return 0;
	}

	if (!param.output_file) {
		dbg(&param, "no output file given, using topology.png by default\n");
		if (!strcmp(param.output_format, "graph"))
			param.output_file = "cxl-topology-graph.png";
		else
			param.output_file = "cxl-topology-plain.json";
	}

	if (param.input_file) {
		if (access(param.input_file, R_OK)) {
			error("input file %s cannot be accessed\n", param.input_file);
			return -EPERM;
		}

		platform = parse_json_text(param.input_file);
		if(!validate_cxl_topology_input(platform)) {
			error("cxl topology from file %s not valid\n", param.input_file);
			dbg(&param,
				"valid cxl topology should include following info:\n\
				1): cxl bus;\n\
				2): cxl host bridge (HB);\n\
				3): cxl memdev;\n\
				4): nr_dport attribute for HB and switch (if exists);\n\
				5): parent_dport attribute for port and memdev objects.\n\
				\n");
			dbg(&param, "try to generate topology file with -v option\n");
			return -1;
		}
		if (!strcmp(param.output_format, "graph")) {
			rs = create_image(param.output_file, platform);
			goto graph_exit;
		}
		else
			goto dump_plain;
	}

	dbg(&param, "walk topology\n");
	platform = cxl_filter_walk(ctx, &param);
	if (!platform)
		return -ENOMEM;

	if (!strcmp(param.output_format, "graph"))
		rs = create_image(param.output_file, platform);
	else{
dump_plain:
		fp = fopen(param.output_file, "w+");
		if (!fp) {
			error("dump to output file %s failed\n", param.output_file);
			rs = -1;
		}
		else {
			fprintf(fp, "%s\n", json_object_to_json_string_ext(platform,
				JSON_C_TO_STRING_PRETTY));
			fclose(fp);
		}
	}

graph_exit:
	if (!rs)
		;
		/*util_display_json_array(stdout, platform, cxl_filter_to_flags(&param));*/
	return 0;
}
