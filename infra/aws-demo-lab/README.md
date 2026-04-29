# Optional AWS CSPM Demo Lab

This optional lab creates safe, low-cost AWS resources that intentionally produce CSPM findings for portfolio testing.

Use only in a demo or sandbox AWS account. Delete the stack after testing. The template does not create EC2 instances, public S3 buckets, admin users, or real access keys.

## Deploy

Find a demo VPC ID first:

```bash
aws ec2 describe-vpcs --filters Name=is-default,Values=true --query "Vpcs[0].VpcId" --output text
```

Deploy the stack:

```bash
aws cloudformation deploy \
  --stack-name cloud-iam-cspm-demo-lab \
  --template-file infra/aws-demo-lab/cloudformation.yaml \
  --parameter-overrides VpcId=vpc-xxxxxxxx
```

## Expected Findings

- S3 default encryption disabled
- S3 versioning disabled
- S3 server access logging disabled
- Security group SSH open to the internet
- Security group RDP open to the internet
- Security group PostgreSQL open to the internet

## Delete

```bash
aws cloudformation delete-stack --stack-name cloud-iam-cspm-demo-lab
```

Wait for deletion to complete:

```bash
aws cloudformation wait stack-delete-complete --stack-name cloud-iam-cspm-demo-lab
```

## Notes

- The security group is intentionally misconfigured but is not attached to an EC2 instance.
- The S3 bucket is private and has public access blocked.
- Do not upload real data to the bucket.
- CloudTrail is not created by default to keep this lab simple and low-cost.
