#!/usr/bin/python3

import os
import json
import sys


def concatenate_json_files(input_dir):
    json_files = []
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".json"):
                json_files.append(os.path.join(root, file))

    data = dict()
    for json_file in json_files:
        with open(json_file, "r") as file:
            if os.stat(json_file).st_size == 0:
                # skip empty file else json.load() fails
                continue
            json_data = json.load(file)
            print(type(json_data), file)
            data = data | json_data

    output_file = os.path.join(os.getcwd(), "concatenated.json")
    with open(output_file, "w") as file:
        json.dump([data], file)

    print(f"JSON files concatenated successfully! Output file: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory_path>")
        sys.exit(1)

    input_directory = sys.argv[1]
    concatenate_json_files(input_directory)
