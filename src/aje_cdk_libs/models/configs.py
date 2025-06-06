from dataclasses import dataclass, field
from typing import Dict, List, Optional
from aws_cdk import (
    Tags, Duration, SecretValue,RemovalPolicy,
    aws_iam as iam,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    aws_glue as glue,
    aws_dynamodb as dynamodb,
    aws_dms as dms,
    aws_lambda as _lambda,
    aws_stepfunctions as sf,
    aws_sns as sns,
    aws_apigateway as apigw,
    aws_logs as logs,
    aws_sqs as sqs,
    aws_glue_alpha as glue,
    aws_s3_deployment as s3_deployment
)
    
@dataclass
class LambdaConfig:
    """Configuration for Lambda function creation"""
    function_name: str
    handler: str  # Module name without .py
    code_path: str  # Path to Lambda code 
    memory_size: Optional[int] = 512
    timeout: Optional[Duration] = Duration.seconds(5)
    runtime: Optional[str] = _lambda.Runtime.PYTHON_3_11
    environment: Optional[Dict[str, str]] = None
    layers: Optional[List] = None
    log_retention: Optional[logs.RetentionDays] = logs.RetentionDays.ONE_WEEK
    removal_policy: Optional[RemovalPolicy] = RemovalPolicy.DESTROY
    role: Optional[iam.Role] = None

@dataclass
class LambdaDockerConfig:
    """Configuration for Lambda function creation"""
    function_name: str
    code: _lambda.DockerImageCode
    memory_size: Optional[int] = 1024
    timeout: Optional[Duration] = Duration.seconds(60)
    environment: Optional[Dict[str, str]] = None
    removal_policy: Optional[RemovalPolicy] = RemovalPolicy.DESTROY
    role: Optional[iam.Role] = None
     
@dataclass
class DynamoDBConfig:
    """Configuration for DynamoDB table creation"""
    table_name: str
    partition_key: str = "PK"
    partition_key_type: dynamodb.AttributeType = dynamodb.AttributeType.STRING
    sort_key: Optional[str] = None
    sort_key_type: Optional[dynamodb.AttributeType] = None
    billing_mode: Optional[dynamodb.BillingMode] = dynamodb.BillingMode.PAY_PER_REQUEST
    stream: Optional[dynamodb.StreamViewType] = None
    removal_policy: Optional[RemovalPolicy] = RemovalPolicy.DESTROY
    encryption: Optional[dynamodb.TableEncryption] = dynamodb.TableEncryption.AWS_MANAGED
    point_in_time_recovery: Optional[bool] = True

@dataclass
class LambdaRestApiConfig:
    """Configuration for Lambda Rest API creation"""
    rest_api_name: str
    handler: _lambda.Function  
    deploy_options: apigw.StageOptions
    default_cors_preflight_options: apigw.CorsOptions
    default_method_options: apigw.MethodOptions
    endpoint_types: List[apigw.EndpointType] = field(default_factory=lambda: [apigw.EndpointType.REGIONAL])
    description: Optional[str] = None
    cloud_watch_role: Optional[bool] = False
    proxy: Optional[bool] = False 

@dataclass
class SQSConfig:
    """Configuration for SQS queue creation"""
    queue_name: str
    retention_period: Duration 
    dead_letter_queue: Optional[sqs.DeadLetterQueue] = None
    visibility_timeout: Optional[Duration] = None
    message_retention_period: Optional[Duration] = None
    fifo: Optional[bool] = None
    content_based_deduplication: Optional[bool] = None
    removal_policy: Optional[RemovalPolicy] = None
    maximum_message_size: Optional[int] = None
    
@dataclass
class S3Config:
    """Configuration for S3 bucket creation"""
    bucket_name: str
    versioned: bool = False
    removal_policy: Optional[RemovalPolicy] = None
    block_public_access: Optional[s3.BlockPublicAccess]= s3.BlockPublicAccess.BLOCK_ALL   

@dataclass
class SNSTopicConfig:
    """Configuration for SNS topic creation"""
    topic_name: str
    removal_policy: Optional[RemovalPolicy] = None

@dataclass
class SecretConfig:
    """Configuration for Secret creation"""
    secret_name: str
    secret_value: str

@dataclass
class S3DeploymentConfig:
    """Configuration for S3 bucket deployment"""
    name: str
    sources: List[s3_deployment.Source]
    destination_bucket: s3.Bucket
    destination_key_prefix: str
    prune: bool = False

@dataclass
class GlueJobConfig:
    """Configuration for Glue job creation"""
    job_name: str
    executable: glue.JobExecutable
    connections: Optional[List[glue.Connection]] = None
    default_arguments: Optional[Dict[str, str]] = None
    worker_type: Optional[glue.WorkerType] = None
    worker_count: Optional[int] = None
    continuous_logging: Optional[glue.ContinuousLoggingProps] = None
    timeout: Optional[Duration] = None
    max_concurrent_runs: Optional[int] = None
    role: Optional[iam.Role] = None

#@dataclass
#class GlueJobPythonShellConfig:
#    """Configuration for Glue job creation with Python shell"""
#    job_name: str
#    script: str
#    python_version: Optional[glue.PythonVersion] = glue.PythonVersion.THREE
#    glue_version: Optional[glue.GlueVersion] = glue.GlueVersion.V3_0
#    description: Optional[str] = None
#    max_capacity: Optional[float] = None
#    role: Optional[iam.Role] = None
#    continuous_logging: Optional[glue.ContinuousLoggingProps] = None
#    worker_type: Optional[glue.WorkerType] = None
#    max_concurrent_runs: Optional[int] = None
#    timeout: Optional[Duration] = Duration.hours(1)
#    number_of_workers: Optional[int] = 1
#    max_retries: Optional[int] = 0
#    arguments: Optional[Dict[str, str]] = None

@dataclass
class StepFunctionConfig:
    """Configuration for Step Functions state machine creation"""
    name: str
    definition: Dict[str, str] = None
    definition_body: Optional[sf.DefinitionBody] = None
    role: Optional[iam.Role] = None
    timeout: Optional[Duration] = Duration.hours(1)

@dataclass
class RoleConfig:
    """Configuration for IAM role creation"""
    role_name: str
    assumed_by: iam.IPrincipal
    managed_policies: Optional[List[iam.IManagedPolicy]] = None
    inline_policies: Optional[Dict[str, iam.PolicyDocument]] = None
    permissions_boundary: Optional[iam.IPolicy] = None
    description: Optional[str] = None
    max_session_duration: Optional[Duration] = None
        
#############################################################    
@dataclass
class ApiGatewayConfig:
    """Configuration for API Gateway creation"""
    name: str
    description: str
    endpoint_types: List[apigw.EndpointType] = field(default_factory=lambda: [apigw.EndpointType.REGIONAL])
    deploy: bool = True
    deploy_options: Optional[apigw.StageOptions] = None
    policy: Optional[iam.Policy] = None
    binary_media_types: List[str] = None
    minimum_compression_size: int = 0
    tracing_enabled: bool = False 

@dataclass
class ApiGatewayDeploymentConfig:
    """Configuration for API Gateway deployment creation"""
    deployment_name: str
    description: str
    api: apigw.RestApi

@dataclass
class ApiGatewayStageConfig:
    """Configuration for API Gateway stage creation"""
    stage_name: str
    deployment: apigw.Deployment
    logging_level: str = "INFO"
    data_trace_enabled: bool = False

@dataclass
class DMSEndpointConfig:
    """Configuration for DMS endpoint creation"""
    name: str
    engine_name: str
    username: str
    password: str
    server_name: str
    port: int
    database_name: str
    s3_settings: Dict[str, str]
    kms_settings: Dict[str, str]
    tags: Optional[Dict[str, str]] = None



    