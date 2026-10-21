#!/usr/bin/python
# -*- coding:utf-8 -*-
# Filename: exporter.py

import logging
import os
import time
from datetime import datetime, timezone

import boto3
from dateutil.relativedelta import relativedelta
from prometheus_client import Gauge

# Rate limiting delay between iterate requests (in seconds)
# This prevents hitting AWS API rate limits when iterating over many dimension values
ITERATE_DELAY_SECONDS = 0.2

# Label name added to metrics when metric_types (list) is used instead of metric_type (string).
METRIC_TYPE_LABEL = "MetricType"


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
        metric_type=None,
        metric_types=None,
        data_delay_days=0,
        metric_description=None,
        record_types=None,
        tag_filters=None,
        dimension_filters=None,
        granularity="DAILY",
        hourly_time_range_hours=24,
    ):
        self.polling_interval_seconds = polling_interval_seconds
        self.metric_name = metric_name
        self.targets = targets
        self.aws_access_key = aws_access_key
        self.aws_access_secret = aws_access_secret
        self.aws_assumed_role_name = aws_assumed_role_name
        self.aws_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        self.aws_partition = boto3.Session().get_partition_for_region(self.aws_region)
        self.group_by = group_by
        self.data_delay_days = data_delay_days
        self.hourly_time_range_hours = hourly_time_range_hours
        self.metric_description = metric_description
        self.tag_filters = tag_filters
        self.granularity = granularity
        self.dimension_alias = {}

        # Normalize metric_type / metric_types into a single list.
        #
        # - metric_type (str): legacy single-value form; no MetricType label is added to
        #   exported metrics so existing dashboards and queries are not broken.
        # - metric_types (list): new multi-value form; a MetricType label is added to every
        #   exported metric so the values can be distinguished in Prometheus/Grafana.
        #
        # Exactly one of the two must be supplied; validation in main.py enforces this.
        if metric_types is not None:
            self.metric_types = list(metric_types)
            self.add_metric_type_label = True
        else:
            self.metric_types = [metric_type]
            self.add_metric_type_label = False

        # Process dimension_filters: separate iterate vs static filters
        # - iterate=true: Makes N API requests (one per value), adds values as labels
        # - iterate=false (default): Single API request with Filter, no labels added
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

        # Hourly granularity returns one datapoint per hour, so each datapoint
        # needs a label with its period start time to avoid overwriting the others.
        # Note: the hour's event time therefore lives in this label, not in the
        # Prometheus sample timestamp (which is scrape time) — see the "Querying
        # HOURLY metrics" section in README.md for the query implications.
        if self.granularity == "HOURLY":
            self.labels.add("PeriodStart")

        # When using metric_types, add MetricType as a label dimension.
        if self.add_metric_type_label:
            self.labels.add(METRIC_TYPE_LABEL)

        # If record_types is not provided, determine default based on metric_types.
        # For amortized cost types, we need to include Savings Plan and Reserved Instance
        # related record types to get accurate amortized values.
        if record_types is None:
            self.record_types = self._get_default_record_types(self.metric_types)
            logging.info(f"Using default record_types for {self.metric_types}: {self.record_types}")
        else:
            self.record_types = record_types

        if group_by["enabled"]:
            for group in group_by["groups"]:
                # Handle dimension alias if present
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

    def _get_default_record_types(self, metric_types):
        """
        Returns appropriate default record types based on the requested metric types.

        If any requested type is AmortizedCost or NetAmortizedCost, include the Savings
        Plan and Reserved Instance record types needed for accurate amortized values.

        See: https://github.com/electrolux-oss/aws-cost-exporter/issues/27
        See: https://github.com/electrolux-oss/aws-cost-exporter/issues/30
        """
        base_types = ["Usage"]
        amortized_types = {"AmortizedCost", "NetAmortizedCost"}

        if any(mt in amortized_types for mt in metric_types):
            return base_types + [
                "SavingsPlanCoveredUsage",
                "SavingsPlanRecurringFee",
                "SavingsPlanUpfrontFee",
                "DiscountedUsage",
                "RIFee",
            ]

        return base_types

    def run_metrics(self):
        # Every time we clear up all the existing labels before setting new ones
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

        This allows adding a third dimension as a label by making N separate API requests,
        bypassing the AWS Cost Explorer limitation of max 2 GroupBy dimensions.

        Currently supports one iterate filter. If multiple are configured, only the first
        is used and a warning is logged.
        """
        if len(self.iterate_filters) > 1:
            logging.warning("Multiple iterate filters not fully supported, using first only")

        iterate_filter = self.iterate_filters[0]
        values = iterate_filter.get("values", [])

        for i, value in enumerate(values):
            if i > 0:
                time.sleep(ITERATE_DELAY_SECONDS)

            current_filters = self.static_filters + [{"key": iterate_filter["key"], "values": [value]}]

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

    def _parse_group_key_values(self, item):
        """Extract label:value pairs from a Cost Explorer result group item."""
        group_key_values = {}
        for i, group in enumerate(self.group_by["groups"]):
            if group["type"] == "TAG":
                value = item["Keys"][i].split("$")[1]
                group_key_values[group["label_name"]] = value
            else:
                value = item["Keys"][i]
                if group["type"] == "DIMENSION" and group["key"] in self.dimension_alias:
                    alias = self.dimension_alias[group["key"]]
                    group_key_values[group["label_name"]] = value
                    alias_value = alias["map"].get(value)
                    group_key_values[alias["label"]] = alias_value if alias_value is not None else ""
                else:
                    group_key_values[group["label_name"]] = value
        return group_key_values

    def _build_merged_group_key_values(self):
        """Build label:value pairs for the merge_minor_cost catch-all group."""
        group_key_values = {}
        merged_value = self.group_by["merge_minor_cost"]["tag_value"]
        for group in self.group_by["groups"]:
            if group["type"] == "DIMENSION" and group["key"] in self.dimension_alias:
                alias = self.dimension_alias[group["key"]]
                group_key_values[group["label_name"]] = merged_value
                alias_value = alias["map"].get(merged_value)
                if alias_value is not None:
                    group_key_values[alias["label"]] = alias_value
            else:
                group_key_values[group["label_name"]] = merged_value
        return group_key_values

    def _fetch_with_filters(self, aws_account, dimension_filters, extra_labels):
        """
        Fetch cost data with specified dimension filters and add extra labels.

        Args:
            aws_account: Target AWS account configuration
            dimension_filters: List of dimension filters to apply to the API request
            extra_labels: Additional labels to add to each metric (from iterate mode)
        """
        aws_client = self._get_aws_client(aws_account)

        cost_response = self.query_aws_cost_explorer(
            aws_client,
            self.group_by,
            self.tag_filters,
            dimension_filters,
        )

        for result in cost_response:
            # With hourly granularity every result is one hour's datapoint,
            # exposed as its own time series via the PeriodStart label
            period_labels = {}
            if self.granularity == "HOURLY":
                period_labels["PeriodStart"] = result["TimePeriod"]["Start"]

            if not self.group_by["enabled"]:
                for metric_type in self.metric_types:
                    cost = float(result["Total"][metric_type]["Amount"])
                    type_label = {METRIC_TYPE_LABEL: metric_type} if self.add_metric_type_label else {}
                    self.cost_metric.labels(
                        **aws_account, **extra_labels, **period_labels, **type_label, ChargeType="Usage"
                    ).set(cost)
            else:
                # Track merged minor costs separately per metric type so that the threshold
                # check is applied independently for each cost view.
                merged_minor_costs = {mt: 0.0 for mt in self.metric_types}

                for item in result["Groups"]:
                    group_key_values = self._parse_group_key_values(item)

                    for metric_type in self.metric_types:
                        cost = float(item["Metrics"][metric_type]["Amount"])
                        type_label = {METRIC_TYPE_LABEL: metric_type} if self.add_metric_type_label else {}

                        if (
                            self.group_by["merge_minor_cost"]["enabled"]
                            and cost < self.group_by["merge_minor_cost"]["threshold"]
                        ):
                            merged_minor_costs[metric_type] += cost
                        else:
                            self.cost_metric.labels(
                                **aws_account,
                                **extra_labels,
                                **group_key_values,
                                **period_labels,
                                **type_label,
                                ChargeType="Usage",
                            ).set(cost)

                merged_group_key_values = self._build_merged_group_key_values()
                for metric_type, merged_cost in merged_minor_costs.items():
                    if merged_cost > 0:
                        type_label = {METRIC_TYPE_LABEL: metric_type} if self.add_metric_type_label else {}
                        self.cost_metric.labels(
                            **aws_account,
                            **extra_labels,
                            **merged_group_key_values,
                            **period_labels,
                            **type_label,
                            ChargeType="Usage",
                        ).set(merged_cost)

    def _get_aws_client(self, aws_account):
        """
        Get AWS Cost Explorer client for the specified account.

        Handles three authentication scenarios:
        1. Assume role via STS (if aws_assumed_role_name is configured)
        2. Static credentials (if aws_access_key and aws_access_secret are provided)
        3. Default credentials chain (boto3 default behavior)
        """
        if self.aws_assumed_role_name:
            aws_credentials = self.get_aws_account_session_via_iam_role(aws_account["Publisher"])
            return boto3.client(
                "ce",
                aws_access_key_id=aws_credentials["AccessKeyId"],
                aws_secret_access_key=aws_credentials["SecretAccessKey"],
                aws_session_token=aws_credentials["SessionToken"],
                region_name=self.aws_region,
            )
        else:
            if self.aws_access_key and self.aws_access_secret:
                return boto3.client(
                    "ce",
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_access_secret,
                    region_name=self.aws_region,
                )
            else:
                return boto3.client("ce", region_name=self.aws_region)

    def get_aws_account_session_via_iam_role(self, account_id):
        if self.aws_access_key and self.aws_access_secret:
            sts_client = boto3.client(
                "sts",
                region_name=self.aws_region,
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_access_secret,
            )
        else:
            sts_client = boto3.client("sts", region_name=self.aws_region)

        assumed_role_object = sts_client.assume_role(
            RoleArn=f"arn:{self.aws_partition}:iam::{account_id}:role/{self.aws_assumed_role_name}",
            RoleSessionName="AssumeRoleSession1",
        )

        return assumed_role_object["Credentials"]

    def query_aws_cost_explorer(self, aws_client, group_by, tag_filters=None, dimension_filters=None):
        """
        Query AWS Cost Explorer API with the specified filters.

        Args:
            aws_client: boto3 Cost Explorer client
            group_by: GroupBy configuration from the metric config
            tag_filters: Optional list of tag filters
            dimension_filters: Optional list of dimension filters

        Returns:
            List of ResultsByTime from AWS Cost Explorer response
        """
        results = list()
        date_format = "%Y-%m-%d"
        end_date = datetime.today() - relativedelta(days=self.data_delay_days)

        if self.granularity == "HOURLY":
            date_format = "%Y-%m-%dT%H:%M:%SZ"
            # Cost Explorer expects UTC timestamps; align to the top of the hour
            # so only complete hourly datapoints are queried
            end_date = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - relativedelta(
                days=self.data_delay_days
            )
            start_date = end_date - relativedelta(hours=self.hourly_time_range_hours)
        elif self.granularity == "DAILY":
            start_date = end_date - relativedelta(days=1)
        elif self.granularity == "MONTHLY":
            # First day of month (relative to the delayed end_date) for month-to-date
            start_date = datetime(end_date.year, end_date.month, 1)
            # Add one day as AWS requires `End` > `Start`, and `End` is exclusive.
            # This also makes month-to-date include the (delayed) current day.
            end_date = end_date + relativedelta(days=1)
        else:
            start_date = end_date - relativedelta(days=1)

        groups = list()
        if group_by["enabled"]:
            for group in group_by["groups"]:
                groups.append({"Type": group["type"], "Key": group["key"]})

        base_filter = {"Dimensions": {"Key": "RECORD_TYPE", "Values": self.record_types}}
        additional_filters = []

        if tag_filters:
            for tag_filter in tag_filters:
                additional_filters.append(
                    {
                        "Tags": {
                            "Key": tag_filter["tag_key"],
                            "Values": tag_filter["tag_values"],
                            "MatchOptions": ["EQUALS"],
                        }
                    }
                )

        if dimension_filters:
            for dim_filter in dimension_filters:
                additional_filters.append(
                    {
                        "Dimensions": {
                            "Key": dim_filter["key"],
                            "Values": dim_filter["values"],
                        }
                    }
                )

        combined_filter = {"And": [base_filter] + additional_filters} if additional_filters else base_filter

        next_page_token = ""
        while True:
            response = aws_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime(date_format),
                    "End": end_date.strftime(date_format),
                },
                Filter=combined_filter,
                Granularity=self.granularity,
                Metrics=self.metric_types,
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
        """
        Fetch cost data for an AWS account.

        This is the legacy method maintained for backward compatibility.
        It now delegates to _fetch_with_filters with static filters only.
        """
        self._fetch_with_filters(aws_account, self.static_filters, {})
