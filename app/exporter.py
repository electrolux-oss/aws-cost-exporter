#!/usr/bin/python
# -*- coding:utf-8 -*-
# Filename: exporter.py

import logging
import time
from datetime import datetime

import boto3
from dateutil.relativedelta import relativedelta
from prometheus_client import Gauge

# Rate limiting delay between iterate requests (in seconds)
# This prevents hitting AWS API rate limits when iterating over many dimension values
ITERATE_DELAY_SECONDS = 0.2


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
        tag_filters=None,  # Added tag_filters parameter
        dimension_filters=None,  # Added dimension_filters parameter for filtering by AWS dimensions
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
        self.data_delay_days = data_delay_days
        self.metric_description = metric_description
        self.tag_filters = tag_filters  # Store tag filters
        self.granularity = granularity
        self.dimension_alias = {}  # Store dimension value alias per group

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

        # For now we only support exporting one type of cost (Usage)
        self.labels.add("ChargeType")

        # If record_types is not provided, determine default based on metric_type
        # For amortized cost types, we need to include additional record types to get accurate values
        if record_types is None:
            self.record_types = self._get_default_record_types(metric_type)
            logging.info(f"Using default record_types for {metric_type}: {self.record_types}")
        else:
            self.record_types = record_types

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

        # Add labels from iterate dimension_filters
        # These labels will be populated with values during iteration
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

        For AmortizedCost and NetAmortizedCost, we need to include Savings Plan and
        Reserved Instance related record types to get accurate amortized values.
        Without these, amortized costs will appear the same as unblended costs.

        See: https://github.com/electrolux-oss/aws-cost-exporter/issues/27
        See: https://github.com/electrolux-oss/aws-cost-exporter/issues/30
        """
        # Base record types for all metric types
        base_types = ["Usage"]

        # Amortized cost types need additional record types for accurate calculation
        amortized_types = ["AmortizedCost", "NetAmortizedCost"]

        if metric_type in amortized_types:
            # Include Savings Plan and Reserved Instance related record types
            # These are required to properly calculate amortized costs
            return base_types + [
                "SavingsPlanCoveredUsage",
                "SavingsPlanRecurringFee",
                "SavingsPlanUpfrontFee",
                "DiscountedUsage",  # For Reserved Instance usage
                "RIFee",  # For Reserved Instance fees
            ]

        return base_types

    def run_metrics(self):
        # Every time we clear up all the existing labels before setting new ones
        self.cost_metric.clear()

        for aws_account in self.targets:
            logging.info("Querying cost data for AWS account %s" % aws_account["Publisher"])
            try:
                if self.iterate_filters:
                    # Use iteration mode when iterate dimension_filters are configured
                    self._run_with_iteration(aws_account)
                else:
                    # Use standard mode with static filters only
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
            # Rate limiting: delay between requests to avoid hitting AWS API limits
            if i > 0:
                time.sleep(ITERATE_DELAY_SECONDS)

            # Build dimension filter for this specific value
            current_filters = self.static_filters + [{"key": iterate_filter["key"], "values": [value]}]

            # Build extra labels from iterate filter
            # These labels are added to each metric with the current iteration value
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

        Args:
            aws_account: Target AWS account configuration
            dimension_filters: List of dimension filters to apply to the API request
            extra_labels: Additional labels to add to each metric (from iterate mode)
        """
        aws_client = self._get_aws_client(aws_account)

        # Pass both tag_filters and dimension_filters to query_aws_cost_explorer
        cost_response = self.query_aws_cost_explorer(
            aws_client,
            self.group_by,
            self.tag_filters,
            dimension_filters,
        )

        for result in cost_response:
            if not self.group_by["enabled"]:
                cost = float(result["Total"][self.metric_type]["Amount"])
                self.cost_metric.labels(**aws_account, **extra_labels, ChargeType="Usage").set(cost)
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
                        self.cost_metric.labels(
                            **aws_account, **extra_labels, **group_key_values, ChargeType="Usage"
                        ).set(cost)

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
                    self.cost_metric.labels(**aws_account, **extra_labels, **group_key_values, ChargeType="Usage").set(
                        merged_minor_cost
                    )

    def _get_aws_client(self, aws_account):
        """
        Get AWS Cost Explorer client for the specified account.

        Handles three authentication scenarios:
        1. Assume role via STS (if aws_assumed_role_name is configured)
        2. Static credentials (if aws_access_key and aws_access_secret are provided)
        3. Default credentials chain (boto3 default behavior)
        """
        if self.aws_assumed_role_name:
            # assume role first
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
                # no credentials are provided via the config file
                # rely on the default credentials chain in boto3
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
        end_date = datetime.today() - relativedelta(days=self.data_delay_days)

        # Set start date based on granularity
        if self.granularity == "DAILY":
            start_date = end_date - relativedelta(days=1)
        elif self.granularity == "MONTHLY":
            # First day of month (relative to the delayed end_date) for month-to-date
            start_date = datetime(end_date.year, end_date.month, 1)
            # Add one day as AWS requires `End` > `Start`, and `End` is exclusive.
            # This also makes month-to-date include the (delayed) current day.
            end_date = end_date + relativedelta(days=1)
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
        additional_filters = []

        # Include tag filters if provided (existing logic)
        if tag_filters:
            for tag_filter in tag_filters:
                tag_key = tag_filter["tag_key"]
                tag_values = tag_filter["tag_values"]
                additional_filters.append(
                    {
                        "Tags": {
                            "Key": tag_key,
                            "Values": tag_values,
                            "MatchOptions": ["EQUALS"],
                        }
                    }
                )

        # Include dimension filters if provided
        # Dimension filters allow filtering by AWS dimensions like LINKED_ACCOUNT, SERVICE, etc.
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

        # Combine the base filter and additional filters using 'And'
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
        """
        Fetch cost data for an AWS account.

        This is the legacy method maintained for backward compatibility.
        It now delegates to _fetch_with_filters with static filters only.
        """
        self._fetch_with_filters(aws_account, self.static_filters, {})
