#!/usr/bin/python
# -*- coding:utf-8 -*-
# Filename: main.py

import argparse
import logging
import os
import sys
import time

from envyaml import EnvYAML
from prometheus_client import start_http_server

from app.exporter import MetricExporter


def get_configs():
    parser = argparse.ArgumentParser(description="AWS Cost Exporter, exposing AWS cost data as Prometheus metrics.")
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="The config file (exporter_config.yaml) for the exporter",
    )
    args = parser.parse_args()

    if not os.path.exists(args.config):
        logging.error("AWS Cost Exporter config file does not exist, or it is not a file!")
        sys.exit(1)

    config = EnvYAML(args.config)
    return config


def validate_configs(config):

    if len(config["target_aws_accounts"]) == 0:
        logging.error("There should be at least one target AWS accounts defined in the config!")
        sys.exit(1)

    labels = config["target_aws_accounts"][0].keys()

    if "Publisher" not in labels:
        logging.error("Publisher is a mandatory key in target_aws_accounts!")
        sys.exit(1)

    for i in range(1, len(config["target_aws_accounts"])):
        if labels != config["target_aws_accounts"][i].keys():
            logging.error("All the target AWS accounts should have the same set of keys (labels)!")
            sys.exit(1)

    for config_metric in config["metrics"]:

        if config_metric["group_by"]["enabled"]:
            if len(config_metric["group_by"]["groups"]) < 1 or len(config_metric["group_by"]["groups"]) > 2:
                logging.error("If group_by is enabled, there should be at least one group, and at most two groups!")
                sys.exit(1)
            group_label_names = set()
            for group in config_metric["group_by"]["groups"]:
                if group["label_name"] in group_label_names:
                    logging.error("Group label names should be unique!")
                    sys.exit(1)
                else:
                    group_label_names.add(group["label_name"])
        if group_label_names and (group_label_names & set(labels)):
            logging.error("Some label names in group_by are the same as AWS account labels!")
            sys.exit(1)



def main(config):

    start_http_server(config["exporter_port"])
    while True:
        for config_metric in config["metrics"]:
            app_metrics = MetricExporter(
                polling_interval_seconds=config["polling_interval_seconds"],
                aws_access_key=config["aws_access_key"],
                aws_access_secret=config["aws_access_secret"],
                aws_assumed_role_name=config["aws_assumed_role_name"],
                targets=config["target_aws_accounts"],
                metric_name=config_metric["metric_name"],
                group_by=config_metric["group_by"],
            )
            app_metrics.run_metrics()
        time.sleep(config["polling_interval_seconds"])

if __name__ == "__main__":
    logger_format = "%(asctime)-15s %(levelname)-8s %(message)s"
    logging.basicConfig(level=logging.INFO, format=logger_format)
    config = get_configs()
    validate_configs(config)
    main(config)
