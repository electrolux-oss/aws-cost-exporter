# AWS Cost Metrics Exporter

Cloud providers like AWS and Azure usually provide cost management portals, dashboards, and APIs for their own products. If a user has a multi-cloud environment, she needs to check the cost information in different places.

This AWS Cost Metrics Exporter helps users to fetch AWS cost information using AWS Cost Explorer APIs and exposes them as standard Prometheus metrics. This enables users to have cost-related metrics present in the same place where their business metrics are. The design also makes it possible to collect cost data from different providers and design one single dashboard for all the costs.

## How Does This Work

AWS Cost Metrics Exporter fetches cost data from a list of AWS accounts, each of which provides a necessary IAM role for the exporter. It regularly queries the AWS [GetCostAndUsage](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsage.html) to get the whole AWS account's cost. It is configurable to have different queries, such as group by services and tags, merge minor cost to one single category, etc. The following figure describes how AWS Cost Metrics Exporter works.

![aws-cost-exporter-design](doc/images/aws-cost-exporter-design.png)

## Setup AWS IAM User, Role and Policy

Note that if there is a list of AWS accounts for cost data collection, only **ONE** user needs to be created. This user is usually created in the AWS account where the exporter is deployed to (an EKS cluster). This can be done from the AWS console - IAM portal or by terraform code.

After creating the user, visit the security credentials tab and create an access key for it. The access key and secret key will be needed when deploying the exporter.

For each target AWS account, a role for AWS Cost Metrics Exporter needs to be created. The name of this role needs to be put into the configuration file (`aws_assumed_role_name`).

Regarding the permissions, the role should at least have the following inline policy.

```
{
    "Statement": [
        {
            "Action": "ce:GetCostAndUsage",
            "Effect": "Allow",
            "Resource": "*",
            "Sid": ""
        }
    ],
    "Version": "2012-10-17"
}
```

Under the trust relationships tab, add the following policy to it (add the ARN of the created user to `<arn_of_the_cretaed_user>`, the correct format should be `arn:aws:iam::xxxxxxxxxxxx:user/username`):

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "<arn_of_the_cretaed_user>"
                ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

## Deployment

Modify the `exporter_config.yaml` file first, then use one of the following methods to run the exporter.

### Docker

```
docker run --rm -v ./exporter_config.yaml:/app/exporter_config.yaml -p 9090:9090 -e AWS_ACCESS_KEY=${AWS_ACCESS_KEY} -e AWS_ACCESS_SECRET=${AWS_ACCESS_SECRET} opensourceelectrolux/finops-aws-cost-exporter:1.0.0
```

### Kubernetes

- Create Namespace
```
kubectl create ns finops
```

- Create Secret
```
kubectl create secret generic aws-cost-exporter \
    --namespace=finops \
    --from-literal=aws_access_key='${AWS_ACCESS_KEY}' \
    --from-literal=aws_access_secret='${AWS_ACCESS_SECRET}'
```

- Create ConfigMap
```
kubectl create configmap aws-cost-exporter-config --namespace finops --from-file=./exporter_config.yaml
```

- Create Deployment
```
kubectl create --namespace finops -f ./deployment/k8s/deployment.yaml
```