#!/usr/bin/env python

import oyaml as yaml

import os
import argparse
import copy


def get_yaml_all(filename):
    with open(filename, 'r') as input_file:
        return list(yaml.load_all(input_file))


def get_yaml(filename):
    with open(filename, 'r') as input_file:
        return yaml.safe_load(input_file)


def get_all_yaml_files(path):
    file_paths = []
    for r, d, f in os.walk(path):
        for file in f:
            if file.endswith('.tmpl') or file.endswith('.yaml'):
                file_paths.append(os.path.join(r, file))
        # break, so we don't recurse
        break
    file_paths = sorted(file_paths)
    return file_paths


def get_all_yaml_obj(file_paths):
    yaml_objs = []
    for file in file_paths:
        objects = get_yaml_all(file)
        for obj in objects:
            yaml_objs.append(obj)
    return yaml_objs


def process_yamls(directory):
    # Get all yaml files as array of yaml objects
    yamls = get_all_yaml_obj(get_all_yaml_files(directory))
    if len(yamls) == 0:
        return

    for obj in template_data['objects']:
        obj['spec']['resources'] = []
        if obj['kind'] == 'SelectorSyncSet':
            for y in yamls:
                obj['spec']['resources'].append(y)

    output_data['objects'].append(obj)


if __name__ == '__main__':
    # Argument parser
    parser = argparse.ArgumentParser(description="selectorsyncset generation tool", usage='%(prog)s [options]')
    parser.add_argument("--template-dir", "-t", required=True, help="Path to template directory [required]")
    parser.add_argument("--build-dir", "-b", required=True, help="Path to folder containing yaml files [required]")
    parser.add_argument("--destination", "-d", required=True, help="Destination for selectorsynceset file [required]")
    parser.add_argument("--repo-name", "-r", required=True, help="Name of the repository [required]")
    arguments = parser.parse_args()

    # Get the template data
    template_data = get_yaml(os.path.join(
        arguments.build_dir, "00-osd-managed-cluster-validating-webhooks.selectorsyncset.yaml.tmpl"))

    # The templates and script are shared across repos (copy & paste).
    # Set the REPO_NAME parameter.
    for p in template_data['parameters']:
        if p['name'] == 'REPO_NAME':
            p['value'] = arguments.repo_name

    output_data = copy.deepcopy(template_data)
    output_data.pop("objects")
    output_data['objects'] = []

    # for each subdir of yaml_directory append 'object' to template
    process_yamls(arguments.template_dir)

    # write template file ordering by keys
    with open(arguments.destination, 'w') as outfile:
        yaml.dump(output_data, outfile)
