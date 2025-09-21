#!/usr/bin/python
# -*- coding:utf-8 -*-
# Filename: exporter.py

import logging
from datetime import datetime

import boto3
from dateutil.relativedelta import relativedelta
from prometheus_client import Gauge


class MetricExporter:
    def __init__(
        self,
        polling_interval_seconds,
        metric_name,
        aws_access_key,
        aws_access_secret,
        aws_assumed_role_name,
        group_by,
        targets,
        metric_type,
        record_types=None,
        tag_filters=None,  # Added tag_filters parameter
        granularity="DAILY",
    ):
        self.polling_interval_seconds = polling_interval_seconds
        self.metric_name = metric_name
        self.targets = targets
        self.aws_access_key = aws_access_key
        self.aws_access_secret = aws_access_secret
        self.aws_assumed_role_name = aws_assumed_role_name
        self.group_by = group_by
        self.metric_type = metric_type  # Store metrics
        self.record_types = record_types
        self.tag_filters = tag_filters  # Store tag filters
        self.granularity = granularity
        self.dimension_alias = {}  # Store dimension value alias per group

        # We have verified that there is at least one target
        self.labels = set(targets[0].keys())

        # For now we only support exporting one type of cost (Usage)
        self.labels.add("ChargeType")

        # If record_types is not provided, use the default value
        if record_types is None:
            record_types = []
            record_types.append("Usage")

        if group_by["enabled"]:
            for group in group_by["groups"]:
                # Handle dimension alias if present
                if group["type"] == "DIMENSION" and "alias" in group:
                    # Store the alias mapping for this dimension
                    self.dimension_alias[group["key"]] = {
                        "map": group["alias"]["map"],
                        "label": group["alias"]["label_name"],
                    }
                    self.labels.add(group["alias"]["label_name"])

                self.labels.add(group["label_name"])

        metric_description = f"{self.granularity.lower().capitalize()} cost of an AWS account in USD"
        if self.granularity == "MONTHLY":
            metric_description = "Month-to-date cost of an AWS account in USD"

        self.cost_metric = Gauge(
            self.metric_name,
            metric_description,
            self.labels,
        )

    def run_metrics(self):
        # Every time we clear up all the existing labels before setting new ones
        self.cost_metric.clear()

        for aws_account in self.targets:
            logging.info("Querying cost data for AWS account %s" % aws_account["Publisher"])
            try:
                self.fetch(aws_account)
            except Exception as e:
                logging.error(e)
                continue

    def get_aws_account_session_via_iam_role(self, account_id):
        if self.aws_access_key and self.aws_access_secret:
            sts_client = boto3.client(
                "sts",
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_access_secret,
            )
        else:
            sts_client = boto3.client("sts")

        assumed_role_object = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{self.aws_assumed_role_name}",
            RoleSessionName="AssumeRoleSession1",
        )

        return assumed_role_object["Credentials"]

    def query_aws_cost_explorer(self, aws_client, group_by, tag_filters=None):
        results = list()
        date_format = "%Y-%m-%d"
        end_date = datetime.today()

        # Set start date based on granularity
        if self.granularity == "HOURLY":
            date_format = "%Y-%m-%dT%H:%M:%SZ"
            start_date = end_date - relativedelta(seconds=self.polling_interval_seconds)

        elif self.granularity == "DAILY":
            start_date = end_date - relativedelta(days=1)

        elif self.granularity == "MONTHLY":
            # First day of current month for month-to-date
            start_date = datetime(end_date.year, end_date.month, 1)
        else:
            # Default to daily if granularity is not recognized
            start_date = end_date - relativedelta(days=1)

        # Keep the 'groups' code as specified
        groups = list()
        if group_by["enabled"]:
            for group in group_by["groups"]:
                groups.append({"Type": group["type"], "Key": group["key"]})

        # Build the base filter with RECORD_TYPE
        base_filter = {"Dimensions": {"Key": "RECORD_TYPE", "Values": self.record_types}}

        # Include tag filters if provided
        if tag_filters:
            tag_filter_list = []
            for tag_filter in tag_filters:
                tag_key = tag_filter["tag_key"]
                tag_values = tag_filter["tag_values"]
                tag_filter_list.append(
                    {
                        "Tags": {
                            "Key": tag_key,
                            "Values": tag_values,
                            "MatchOptions": ["EQUALS"],
                        }
                    }
                )

            # Combine the base filter and tag filters using 'And'
            combined_filter = {"And": [base_filter] + tag_filter_list}
        else:
            combined_filter = base_filter

        next_page_token = ""
        while True:
            response = aws_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime(date_format),
                    "End": end_date.strftime(date_format),
                },
                Filter=combined_filter,
                Granularity=self.granularity,
                Metrics=[self.metric_type],  # Use dynamic metrics
                GroupBy=groups,
                **({"NextPageToken": next_page_token} if next_page_token else {}),
            )
            results.extend(response["ResultsByTime"])
            if "NextPageToken" in response:
                next_page_token = response["NextPageToken"]
            else:
                break

        return results

    def fetch(self, aws_account):
        if self.aws_assumed_role_name:
            # assume role first
            aws_credentials = self.get_aws_account_session_via_iam_role(aws_account["Publisher"])
            aws_client = boto3.client(
                "ce",
                aws_access_key_id=aws_credentials["AccessKeyId"],
                aws_secret_access_key=aws_credentials["SecretAccessKey"],
                aws_session_token=aws_credentials["SessionToken"],
                region_name="us-east-1",
            )
        else:
            if self.aws_access_key and self.aws_access_secret:
                aws_client = boto3.client(
                    "ce",
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_access_secret,
                    region_name="us-east-1",
                )
            else:
                # no credentials are provided via the config file
                # rely on the default credentials chain in boto3
                aws_client = boto3.client(
                    "ce",
                    region_name="us-east-1",
                )

        # Pass tag_filters to query_aws_cost_explorer
        cost_response = self.query_aws_cost_explorer(
            aws_client,
            self.group_by,
            self.tag_filters,  # Include tag filters
        )

        for result in cost_response:
            if not self.group_by["enabled"]:
                cost = float(result["Total"][self.metric_type]["Amount"])
                self.cost_metric.labels(**aws_account, ChargeType="Usage").set(cost)
            else:
                merged_minor_cost = 0
                for item in result["Groups"]:
                    cost = float(item["Metrics"][self.metric_type]["Amount"])

                    group_key_values = dict()
                    for i in range(len(self.group_by["groups"])):
                        group = self.group_by["groups"][i]
                        if group["type"] == "TAG":
                            value = item["Keys"][i].split("$")[1]
                            group_key_values[group["label_name"]] = value
                        else:
                            value = item["Keys"][i]
                            # Check if this dimension has alias
                            if group["type"] == "DIMENSION" and group["key"] in self.dimension_alias:
                                alias = self.dimension_alias[group["key"]]
                                # Add both original and aliased values
                                group_key_values[group["label_name"]] = value
                                alias_value = alias["map"].get(value)
                                if alias_value is not None:
                                    group_key_values[alias["label"]] = alias_value
                                else:
                                    group_key_values[alias["label"]] = ""
                            else:
                                group_key_values[group["label_name"]] = value

                    if (
                        self.group_by["merge_minor_cost"]["enabled"]
                        and cost < self.group_by["merge_minor_cost"]["threshold"]
                    ):
                        merged_minor_cost += cost
                    else:
                        self.cost_metric.labels(**aws_account, **group_key_values, ChargeType="Usage").set(cost)

                if merged_minor_cost > 0:
                    group_key_values = dict()
                    for i in range(len(self.group_by["groups"])):
                        group = self.group_by["groups"][i]
                        merged_value = self.group_by["merge_minor_cost"]["tag_value"]
                        if group["type"] == "DIMENSION" and group["key"] in self.dimension_alias:
                            alias = self.dimension_alias[group["key"]]
                            # Add both original and aliased values for merged costs
                            group_key_values[group["label_name"]] = merged_value
                            alias_value = alias["map"].get(merged_value)
                            if alias_value is not None:
                                group_key_values[alias["label"]] = alias_value
                        else:
                            group_key_values[group["label_name"]] = merged_value
                    self.cost_metric.labels(**aws_account, **group_key_values, ChargeType="Usage").set(
                        merged_minor_cost
                    )
