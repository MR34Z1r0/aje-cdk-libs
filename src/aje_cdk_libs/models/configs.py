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
    aws_s3_deployment as s3_deployment,
    aws_scheduler as scheduler,
    aws_appflow as appflow,
    aws_events as events
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
    tags: Optional[Dict[str, str]] = None

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
    block_public_access: Optional[s3.BlockPublicAccess]= None   

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
@dataclass
class GlueJobConfig:
    """Configuration for Glue job creation"""
    job_name: str
    executable: glue.JobExecutable
    connections: Optional[List[glue.Connection]] = None
    default_arguments: Optional[Dict[str, str]] = None
    worker_type: Optional[glue.WorkerType] = None
    worker_count: Optional[int] = None
    max_capacity: Optional[float] = None  # For PythonShell jobs only
    continuous_logging: Optional[glue.ContinuousLoggingProps] = None
    timeout: Optional[Duration] = None
    max_concurrent_runs: Optional[int] = None
    role: Optional[iam.Role] = None
    tags: Optional[Dict[str, str]] = None

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
    disable_auto_permissions: bool = False  # New flag to prevent auto-permission grants
    tags: Optional[Dict[str, str]] = None

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

@dataclass
class GlueRoleConfig:
    """Base configuration for Glue role creation with minimum permissions"""
    role_name: str
    assumed_by: iam.IPrincipal = field(default_factory=lambda: iam.ServicePrincipal("glue.amazonaws.com"))
    managed_policies: List[iam.IManagedPolicy] = field(default_factory=lambda: [
        iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSGlueServiceRole')
    ])
    additional_policies: Optional[List[str]] = None
    resource_arns: Optional[Dict[str, List[str]]] = None
    inline_policies: Optional[Dict[str, iam.PolicyDocument]] = None
    description: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    
@dataclass
class StepFunctionRoleConfig:
    """Configuration for Step Function role creation with minimum permissions"""
    role_name: str
    assumed_by: iam.IPrincipal = field(default_factory=lambda: iam.ServicePrincipal("states.amazonaws.com"))
    managed_policies: Optional[List[iam.IManagedPolicy]] = None
    additional_policies: Optional[List[str]] = None
    resource_arns: Optional[Dict[str, List[str]]] = None
    inline_policies: Optional[Dict[str, iam.PolicyDocument]] = None
    description: Optional[str] = None
    tags: Optional[Dict[str, str]] = None

@dataclass
class GlueConnectionConfig:
    """Configuration for Glue VPC connection creation"""
    connection_name: str
    vpc_id: str
    subnet_id: str
    security_group_id: str
    availability_zone: str = 'us-east-2a'
    description: Optional[str] = None
    tags: Optional[Dict[str, str]] = None

@dataclass
class GlueJdbcConnectionConfig:
    """Configuration for Glue JDBC connection creation"""
    connection_name: str
    jdbc_url: str
    username: str
    password: str
    subnet_id: str
    security_group_id: str
    availability_zone: str = 'us-east-2a'
    description: Optional[str] = None
    tags: Optional[Dict[str, str]] = None

@dataclass
class EventBridgeSchedulerConfig:
    """Configuration for EventBridge Scheduler creation"""
    schedule_name: str
    schedule_expression: str  # Cron or rate expression
    target_arn: str  # ARN of the target (Step Function, Lambda, etc.)
    target_role_arn: str  # IAM role ARN for the scheduler to assume
    description: Optional[str] = None
    flexible_time_window_mode: str = "OFF"  # OFF or FLEXIBLE
    flexible_time_window_maximum_window_in_minutes: Optional[int] = None
    group_name: Optional[str] = "default"
    target_input: Optional[str] = None  # JSON string input for the target
    target_retry_policy_maximum_retry_attempts: Optional[int] = 3
    target_retry_policy_maximum_event_age_in_seconds: Optional[int] = 86400  # 24 hours
    state: str = "ENABLED"  # ENABLED or DISABLED
    timezone: str = "UTC"
    tags: Optional[Dict[str, str]] = None

@dataclass
class AppflowConfig:
    """Configuration for Appflow creation"""
    flow_name: str
    source_flow_config: appflow.CfnFlow.SourceFlowConfigProperty
    destination_flow_config_list: List[appflow.CfnFlow.DestinationFlowConfigProperty]
    tasks: List[appflow.CfnFlow.TaskProperty]
    trigger_config: appflow.CfnFlow.TriggerConfigProperty
    flow_status: str = "Active"
    description: Optional[str] = None
    tags: Optional[Dict[str, str]] = None


@dataclass
class EventBridgeRuleConfig:
    """Configuration for EventBridge Rule creation"""
    rule_name: str
    description: Optional[str] = None
    event_pattern: Dict[str, List[str]] = None
    schedule_expression: Optional[str] = None
    targets: List[events.CfnRule.TargetProperty] = None
    event_bus_name: Optional[str] = None
    state: str = "ENABLED"
    role_arn: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    enabled: bool = True
    event_bus_name: Optional[str] = None
    tags: Optional[Dict[str, str]] = None

@dataclass
class EventBridgeTargetConfig:
    """Configuration for EventBridge Rule targets"""
    # Lambda target
    lambda_function: Optional[_lambda.IFunction] = None
    
    # Step Function target
    state_machine: Optional[sf.IStateMachine] = None
    state_machine_role: Optional[iam.IRole] = None
    
    # SQS target
    sqs_queue: Optional[sqs.IQueue] = None
    
    # SNS target
    sns_topic: Optional[sns.ITopic] = None
    
    # Generic ARN target (for custom cases)
    arn: Optional[str] = None
    
    # Common target properties
    retry_attempts: int = 2
    max_event_age: Duration = Duration.hours(2)
    dead_letter_queue: Optional[sqs.IQueue] = None
    
    # Input transformation
    input_transformer: Optional[events.RuleTargetInput] = None
    input_path: Optional[str] = None
    
    # Target-specific settings
    message_group_id: Optional[str] = None  # For FIFO SQS
