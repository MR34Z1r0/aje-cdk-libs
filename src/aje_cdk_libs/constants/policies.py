class PolicyUtils:
    """IAM policy statement utilities and predefined permissions"""
    
    @staticmethod
    def join_permissions(*permission_lists):
        """Combine multiple permission lists removing duplicates"""
        unique_permissions = set()
        for permissions in permission_lists:
            unique_permissions.update(permissions)
        return list(unique_permissions)
    
    # Predefined permission sets

    LAMBDA_INVOKE = [
        "lambda:InvokeFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions"
    ]

    APPFLOW_READ_WRITE = [
        "appflow:TagResource",
        "appflow:DescribeFlow",
        "appflow:StartFlow",
        "appflow:StopFlow"
    ]
    
    S3_READ = [   
        "s3:ListBucket",
        "s3:GetObject",
        "s3:GetBucketLocation"
    ]
    
    S3_WRITE = [
        "s3:PutObject",
        "s3:DeleteObject"
    ]
    
    LOGS_WRITE = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
    ]

    SNS_PUBLISH = [
        "sns:Publish",
        "sns:Subscribe",
        "sns:Unsubscribe",
        "sns:ListSubscriptionsByTopic"
    ]

    DYNAMODB_READ = [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem"
    ]
    
    GLUE_START_JOB = [
        "glue:StartJobRun",
        "glue:GetJobRun", 
        "glue:GetJobRuns",
        "glue:BatchStopJobRun"
        ]
    
    CRAWLER_START_JOB = [
        "glue:StartCrawler",
        "glue:GetCrawler",
        "glue:StopCrawler"
        ]
    
    STEP_FUNCTIONS_START_EXECUTION = [
        "states:StartExecution",
        "states:StopExecution",
        "states:DescribeExecution"
        ]