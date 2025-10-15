class PolicyUtils:
    """IAM policy statement utilities and predefined permissions"""
    
    @staticmethod
    def join_permissions(*permission_lists):
        """Combine multiple permission lists removing duplicates"""
        unique_permissions = set()
        for permissions in permission_lists:
            unique_permissions.update(permissions)
        return list(unique_permissions)
    
    # Generic permission sets for different AWS services
    
    # Step Function permissions
    STEP_FUNCTIONS_START_EXECUTION = [
        "states:StartExecution"
    ]

    # S3 permissions
    S3_READ = [   
        "s3:ListBucket",
        "s3:GetObject",
        "s3:GetBucketLocation"
    ]
    
    S3_WRITE = [
        "s3:PutObject",
        "s3:DeleteObject"
    ]
    
    S3_FULL = S3_READ + S3_WRITE
    
    # CloudWatch Logs permissions
    LOGS_WRITE = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
    ]
    
    LOGS_READ = [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents"
    ]
    
    LOGS_ADMIN = [
        "logs:CreateLogDelivery",
        "logs:GetLogDelivery",
        "logs:UpdateLogDelivery",
        "logs:DeleteLogDelivery",
        "logs:ListLogDeliveries",
        "logs:PutResourcePolicy",
        "logs:DescribeResourcePolicies",
        "logs:DescribeLogGroups"
    ]

    # IAM permissions
    IAM_PASS_ROLE = [
        "iam:PassRole"
    ]
    
    IAM_GET_ROLE = [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies"
    ]
    
    IAM_ROLE_MANAGEMENT = IAM_PASS_ROLE + IAM_GET_ROLE + [
        "iam:CreateRole",
        "iam:UpdateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy"
    ]

    # SNS permissions
    SNS_PUBLISH = [
        "sns:Publish"
    ]
    
    SNS_SUBSCRIBE = [
        "sns:Subscribe",
        "sns:Unsubscribe",
        "sns:ListSubscriptionsByTopic"
    ]
    
    SNS_FULL = SNS_PUBLISH + SNS_SUBSCRIBE

    # DynamoDB permissions
    DYNAMODB_READ = [
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem"
    ]
    
    DYNAMODB_WRITE = [
        "dynamodb:DescribeTable",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:BatchWriteItem"
    ]
    
    DYNAMODB_FULL = DYNAMODB_READ + DYNAMODB_WRITE
    
    # Glue job permissions
    GLUE_JOB_EXECUTE = [
        "glue:StartJobRun",
        "glue:GetJobRun", 
        "glue:GetJobRuns",
        "glue:BatchStopJobRun"
    ]

    GLUE_START_JOB = [
        "glue:StartJobRun",
    ]

    # Glue crawler permissions
    GLUE_CRAWLER_EXECUTE = [
        "glue:StartCrawler",
        "glue:GetCrawler",
        "glue:StopCrawler",
        "glue:GetCrawlerMetrics"
    ]
    
    # Glue catalog permissions
    GLUE_CATALOG_READ = [
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetPartition",
        "glue:GetPartitions",
        "glue:BatchGetPartition"
    ]
    
    GLUE_CATALOG_WRITE = [
        "glue:CreateDatabase",
        "glue:UpdateDatabase",
        "glue:CreateTable",
        "glue:UpdateTable",
        "glue:BatchCreatePartition",
        "glue:CreatePartition",
        "glue:UpdatePartition"
    ]
    
    GLUE_CATALOG_FULL = GLUE_CATALOG_READ + GLUE_CATALOG_WRITE
    
    # Lake Formation permissions
    LAKE_FORMATION_ACCESS = [
        "lakeformation:GetDataAccess",
        "lakeformation:GrantPermissions",
        "lakeformation:RevokePermissions"
    ]
    
    # Lake Formation Tag permissions (for LF-Tags management)
    LAKE_FORMATION_TAG_ADMIN = [
        "lakeformation:CreateLFTag",
        "lakeformation:DeleteLFTag",
        "lakeformation:GetLFTag",
        "lakeformation:ListLFTags",
        "lakeformation:UpdateLFTag",
        "lakeformation:AddLFTagsToResource",
        "lakeformation:RemoveLFTagsFromResource",
        "lakeformation:GetResourceLFTags",
        "lakeformation:ListLFTagsFor",
        "lakeformation:SearchTablesByLFTags",
        "lakeformation:SearchDatabasesByLFTags"
    ]
    
    # Lake Formation comprehensive permissions for data lake operations
    LAKE_FORMATION_FULL = LAKE_FORMATION_ACCESS + LAKE_FORMATION_TAG_ADMIN + [
        "lakeformation:RegisterResource",
        "lakeformation:DeregisterResource",
        "lakeformation:DescribeResource",
        "lakeformation:ListResources",
        "lakeformation:GetTableObjects",
        "lakeformation:UpdateTableObjects",
        "lakeformation:DeleteObjectsOnCancel",
        "lakeformation:GetWorkUnits",
        "lakeformation:GetWorkUnitResults",
        "lakeformation:StartQueryPlanning",
        "lakeformation:GetQueryPlanning",
        "lakeformation:GetQueryState",
        "lakeformation:StartTransaction",
        "lakeformation:CommitTransaction",
        "lakeformation:CancelTransaction",
        "lakeformation:ExtendTransaction",
        "lakeformation:DescribeTransaction",
        "lakeformation:ListTransactions",
        "lakeformation:GetTemporaryGlueTableCredentials",
        "lakeformation:GetTemporaryGluePartitionCredentials"
    ]
    
    # Step Function permissions
    STEP_FUNCTIONS_EXECUTE = [
        "states:StartExecution",
        "states:StopExecution",
        "states:DescribeExecution"
    ]
    
    # Lambda permissions
    LAMBDA_INVOKE = [
        "lambda:InvokeFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions"
    ]
    
    # EventBridge permissions
    EVENTBRIDGE_MANAGE = [
        "events:CreateRule",
        "events:DeleteRule",
        "events:DescribeRule",
        "events:PutRule",
        "events:PutTargets",
        "events:RemoveTargets",
        "events:TagResource",
        "events:UntagResource"
    ]

    # AppFlow permissions (kept for backward compatibility)
    APPFLOW_READ_WRITE = [
        "appflow:TagResource",
        "appflow:DescribeFlow",
        "appflow:StartFlow",
        "appflow:StopFlow"
    ]

    # Secret Manager permissions
    SECRET_MANAGER_READ = [
        "secretsmanager:GetSecretValue",
        "kms:Decrypt"
    ]
    
    # Role-specific permission sets (for backward compatibility)
    # These can be constructed from the generic sets above
    
    # Permissions for extract Glue jobs
    GLUE_EXTRACT_JOB = S3_FULL + DYNAMODB_WRITE + SNS_PUBLISH + SECRET_MANAGER_READ
    
    # Permissions for light transform Glue jobs
    GLUE_LIGHT_TRANSFORM_JOB = S3_FULL + DYNAMODB_WRITE + SNS_PUBLISH
    
    # Permissions for crawler Glue jobs
    GLUE_CRAWLER_JOB = S3_READ + GLUE_CATALOG_FULL + GLUE_CRAWLER_EXECUTE
    
    # Step Function execution permissions (alias for backward compatibility)
    STEP_FUNCTION_EXECUTION = STEP_FUNCTIONS_EXECUTE
    
    # Crawler start job (alias for backward compatibility)
    CRAWLER_START_JOB = GLUE_CRAWLER_EXECUTE