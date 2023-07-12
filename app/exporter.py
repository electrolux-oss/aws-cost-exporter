#!/usr/bin/python
# -*- coding:utf-8 -*-
# Filename: exporter.py

import time
import boto3
from datetime import datetime
from dateutil.relativedelta import relativedelta
from prometheus_client import Gauge
import logging


class MetricExporter:
    def __init__(self, polling_interval_seconds, aws_access_key, aws_access_secret, aws_assumed_role_name, group_by, targets):
        self.polling_interval_seconds = polling_interval_seconds
        self.targets = targets
        self.aws_access_key = aws_access_key
        self.aws_access_secret = aws_access_secret
        self.aws_assumed_role_name = aws_assumed_role_name
        self.group_by = group_by
        # we have verified that there is at least one target
        self.labels = set(targets[0].keys())
        # for now we only support exporting one type of cost (Usage)
        self.labels.add("ChargeType")
        if group_by["enabled"]:
            for group in group_by["groups"]:
                self.labels.add(group["label_name"])
        self.aws_cost = Gauge(
            "aws_cost", "Daily cost of an AWS account", self.labels)

    def run_metrics_loop(self):
        while True:
            self.fetch()
            time.sleep(self.polling_interval_seconds)

    def get_aws_account_session(self, account_id):
        sts_client = boto3.client(
            "sts",
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_access_secret,
        )

        assumed_role_object = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{self.aws_assumed_role_name}",
            RoleSessionName="AssumeRoleSession1"
        )

        return assumed_role_object["Credentials"]

    def query_aws_cost_explorer(self, aws_client, group_by):
        end_date = datetime.today()
        start_date = end_date - relativedelta(days=1)
        groups = list()
        if group_by["enabled"]:
            for group in group_by["groups"]:
                groups.append({
                    "Type": group["type"],
                    "Key": group["key"]
                })

        response = aws_client.get_cost_and_usage(
            TimePeriod={
                "Start": start_date.strftime("%Y-%m-%d"),
                "End": end_date.strftime("%Y-%m-%d")
            },
            Filter={
                "Dimensions": {
                    "Key": "RECORD_TYPE",
                    "Values": ["Usage"]
                }
            },
            Granularity="DAILY",
            Metrics=[
                "UnblendedCost"
            ],
            GroupBy=groups
        )
        return response["ResultsByTime"]

    def fetch(self):
        for aws_account in self.targets:
            logging.info("querying cost data for aws account %s" %
                         aws_account["Publisher"])
            aws_credentials = self.get_aws_account_session(
                aws_account["Publisher"])
            aws_client = boto3.client(
                "ce",
                aws_access_key_id=aws_credentials["AccessKeyId"],
                aws_secret_access_key=aws_credentials["SecretAccessKey"],
                aws_session_token=aws_credentials["SessionToken"],
                region_name="us-east-1"
            )
            cost_response = self.query_aws_cost_explorer(
                aws_client, self.group_by)

            for result in cost_response:
                if not self.group_by["enabled"]:
                    cost = float(result["Total"]["UnblendedCost"]["Amount"])
                    self.aws_cost.labels(
                        **aws_account, ChargeType="Usage").set(cost)
                else:
                    merged_minor_cost = 0
                    for item in result["Groups"]:
                        cost = float(item["Metrics"]
                                     ["UnblendedCost"]["Amount"])

                        group_key_values = dict()
                        for i in range(len(self.group_by["groups"])):
                            if self.group_by["groups"][i]["type"] == "TAG":
                                value = item["Keys"][i].split("$")[1]
                            else:
                                value = item["Keys"][i]
                            group_key_values.update(
                                {self.group_by["groups"][i]["label_name"]: value})

                        if self.group_by["merge_minor_cost"]["enabled"] and \
                                cost < self.group_by["merge_minor_cost"]["threshold"]:
                            merged_minor_cost += cost
                        else:
                            self.aws_cost.labels(
                                **aws_account, **group_key_values, ChargeType="Usage").set(cost)

                    if merged_minor_cost > 0:
                        group_key_values = dict()
                        for i in range(len(self.group_by["groups"])):
                            group_key_values.update(
                                {self.group_by["groups"][i]["label_name"]: self.group_by["merge_minor_cost"]["tag_value"]})
                        self.aws_cost.labels(
                            **aws_account, **group_key_values, ChargeType="Usage").set(merged_minor_cost)
