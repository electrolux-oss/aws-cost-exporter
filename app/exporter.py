#!/usr/bin/python
# -*- coding:utf-8 -*-
# Filename: exporter.py

import logging
import time
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
        data_delay_days=0,
        metric_description=None,
        record_types=None,
        tag_filters=None,
        dimension_filters=None,  # New parameter
        granularity="DAILY",
    ):
        self.polling_interval_seconds = polling_interval_seconds
        self.metric_name = metric_name
        self.targets = targets
        self.aws_access_key = aws_access_key
        self.aws_access_secret = aws_access_secret
        self.aws_assumed_role_name = aws_assumed_role_name
        self.group_by = group_by
        self.metric_type = metric_type
        self.data_delay_days = data_delay_days
        self.metric_description = metric_description
        self.tag_filters = tag_filters
        self.granularity = granularity
        self.dimension_alias = {}

        # Process dimension_filters: separate iterate vs static
        self.dimension_filters = dimension_filters or []
        self.iterate_filters = []
        self.static_filters = []
        
        for df in self.dimension_filters:
            if df.get("iterate", False):
                self.iterate_filters.append(df)
            else:
                self.static_filters.append(df)

        # We have verified that there is at least one target
        self.labels = set(targets[0].keys())
        self.labels.add("ChargeType")

        # If record_types is not provided, determine default based on metric_type
        if record_types is None:
            self.record_types = self._get_default_record_types(metric_type)
            logging.info(
                f"Using default record_types for {metric_type}: {self.record_types}"
            )
        else:
            self.record_types = record_types

        if group_by["enabled"]:
            for group in group_by["groups"]:
                if group["type"] == "DIMENSION" and "alias" in group:
                    self.dimension_alias[group["key"]] = {
                        "map": group["alias"]["map"],
                        "label": group["alias"]["label_name"],
                    }
                    self.labels.add(group["alias"]["label_name"])
                self.labels.add(group["label_name"])

        # Add labels from iterate dimension_filters
        for df in self.iterate_filters:
            if "label_name" in df:
                self.labels.add(df["label_name"])
            if "alias" in df:
                self.labels.add(df["alias"]["label_name"])

        if self.metric_description is None:
            self.metric_description = f"{self.granularity.lower().capitalize()} cost of an AWS account in USD"
            if self.granularity == "MONTHLY":
                self.metric_description = "Month-to-date cost of an AWS account in USD"

        self.cost_metric = Gauge(
            self.metric_name,
            self.metric_description,
            self.labels,
        )

    def _get_default_record_types(self, metric_type):
        """
        Returns appropriate default record types based on the metric type.
        """
        base_types = ["Usage"]
        amortized_types = ["AmortizedCost", "NetAmortizedCost"]

        if metric_type in amortized_types:
            return base_types + [
                "SavingsPlanCoveredUsage",
                "SavingsPlanRecurringFee",
                "SavingsPlanUpfrontFee",
                "DiscountedUsage",
                "RIFee",
            ]

        return base_types

    def run_metrics(self):
        self.cost_metric.clear()

        for aws_account in self.targets:
            logging.info("Querying cost data for AWS account %s" % aws_account["Publisher"])
            try:
                if self.iterate_filters:
                    self._run_with_iteration(aws_account)
                else:
                    self._fetch_with_filters(aws_account, self.static_filters, {})
            except Exception as e:
                logging.error(e)
                continue

    def _run_with_iteration(self, aws_account):
        """
        Run queries by iterating over dimension_filters with iterate=true.
        Currently supports one iterate filter (can be extended for multiple).
        """
        if len(self.iterate_filters) > 1:
            logging.warning("Multiple iterate filters not fully supported, using first only")
        
        iterate_filter = self.iterate_filters[0]
        values = iterate_filter.get("values", [])
        
        for i, value in enumerate(values):
            # Rate limiting: 200ms between requests
            if i > 0:
                time.sleep(0.2)
            
            # Build dimension filter for this specific value
            current_filters = self.static_filters + [{
                "key": iterate_filter["key"],
                "values": [value]
            }]
            
            # Build extra labels from iterate filter
            iterate_labels = {}
            if "label_name" in iterate_filter:
                iterate_labels[iterate_filter["label_name"]] = value
            if "alias" in iterate_filter:
                alias_value = iterate_filter["alias"]["map"].get(value, "")
                iterate_labels[iterate_filter["alias"]["label_name"]] = alias_value
            
            logging.info(f"  Iterating dimension {iterate_filter['key']}={value}")
            try:
                self._fetch_with_filters(aws_account, current_filters, iterate_labels)
            except Exception as e:
                logging.error(f"Error fetching for {iterate_filter['key']}={value}: {e}")
                continue

    def _fetch_with_filters(self, aws_account, dimension_filters, extra_labels):
        """
        Fetch cost data with specified dimension filters and add extra labels.
        """
        aws_client = self._get_aws_client(aws_account)
        
        cost_response = self.query_aws_cost_explorer(
            aws_client,
            self.group_by,
            self.tag_filters,
            dimension_filters,
        )

        for result in cost_response:
            if not self.group_by["enabled"]:
                cost = float(result["Total"][self.metric_type]["Amount"])
                self.cost_metric.labels(
                    **aws_account, 
                    **extra_labels,
                    ChargeType="Usage"
                ).set(cost)
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
                            if group["type"] == "DIMENSION" and group["key"] in self.dimension_alias:
                                alias = self.dimension_alias[group["key"]]
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
                        self.cost_metric.labels(
                            **aws_account, 
                            **extra_labels,
                            **group_key_values, 
                            ChargeType="Usage"
                        ).set(cost)

                if merged_minor_cost > 0:
                    group_key_values = dict()
                    for i in range(len(self.group_by["groups"])):
                        group = self.group_by["groups"][i]
                        merged_value = self.group_by["merge_minor_cost"]["tag_value"]
                        if group["type"] == "DIMENSION" and group["key"] in self.dimension_alias:
                            alias = self.dimension_alias[group["key"]]
                            group_key_values[group["label_name"]] = merged_value
                            alias_value = alias["map"].get(merged_value)
                            if alias_value is not None:
                                group_key_values[alias["label"]] = alias_value
                        else:
                            group_key_values[group["label_name"]] = merged_value
                    self.cost_metric.labels(
                        **aws_account, 
                        **extra_labels,
                        **group_key_values, 
                        ChargeType="Usage"
                    ).set(merged_minor_cost)

    def _get_aws_client(self, aws_account):
        """Get AWS Cost Explorer client for the account."""
        if self.aws_assumed_role_name:
            aws_credentials = self.get_aws_account_session_via_iam_role(aws_account["Publisher"])
            return boto3.client(
                "ce",
                aws_access_key_id=aws_credentials["AccessKeyId"],
                aws_secret_access_key=aws_credentials["SecretAccessKey"],
                aws_session_token=aws_credentials["SessionToken"],
                region_name="us-east-1",
            )
        else:
            if self.aws_access_key and self.aws_access_secret:
                return boto3.client(
                    "ce",
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_access_secret,
                    region_name="us-east-1",
                )
            else:
                return boto3.client(
                    "ce",
                    region_name="us-east-1",
                )

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

    def query_aws_cost_explorer(self, aws_client, group_by, tag_filters=None, dimension_filters=None):
        results = list()
        end_date = datetime.today() - relativedelta(days=self.data_delay_days)

        if self.granularity == "DAILY":
            start_date = end_date - relativedelta(days=1)
        elif self.granularity == "MONTHLY":
            start_date = datetime(end_date.year, end_date.month, 1)
            end_date = end_date + relativedelta(days=1)
        else:
            start_date = end_date - relativedelta(days=1)

        groups = list()
        if group_by["enabled"]:
            for group in group_by["groups"]:
                groups.append({"Type": group["type"], "Key": group["key"]})

        # Build the base filter with RECORD_TYPE
        base_filter = {"Dimensions": {"Key": "RECORD_TYPE", "Values": self.record_types}}
        additional_filters = []

        # Include tag filters if provided (existing logic)
        if tag_filters:
            for tag_filter in tag_filters:
                additional_filters.append({
                    "Tags": {
                        "Key": tag_filter["tag_key"],
                        "Values": tag_filter["tag_values"],
                        "MatchOptions": ["EQUALS"],
                    }
                })

        # Include dimension filters if provided (new logic, parallel to tag_filters)
        if dimension_filters:
            for dim_filter in dimension_filters:
                additional_filters.append({
                    "Dimensions": {
                        "Key": dim_filter["key"],
                        "Values": dim_filter["values"],
                    }
                })

        # Combine all filters
        if additional_filters:
            combined_filter = {"And": [base_filter] + additional_filters}
        else:
            combined_filter = base_filter

        next_page_token = ""
        while True:
            response = aws_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
                Filter=combined_filter,
                Granularity=self.granularity,
                Metrics=[self.metric_type],
                GroupBy=groups,
                **({"NextPageToken": next_page_token} if next_page_token else {}),
            )
            results.extend(response["ResultsByTime"])
            if "NextPageToken" in response:
                next_page_token = response["NextPageToken"]
            else:
                break

        return results

    # Keep old fetch method for backward compatibility
    def fetch(self, aws_account):
        """Legacy method - now calls _fetch_with_filters with static filters."""
        self._fetch_with_filters(aws_account, self.static_filters, {})
