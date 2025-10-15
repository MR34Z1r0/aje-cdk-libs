from aws_cdk import (
    Tags, Duration, SecretValue, Aws,
    aws_iam as iam,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    aws_glue_alpha as glue,
    aws_dynamodb as dynamodb,
    aws_dms as dms,
    aws_lambda as _lambda,
    aws_stepfunctions as sf,
    aws_sns as sns,
    aws_apigateway as apigw,
    aws_sqs as sqs,
    aws_s3_deployment as s3_deployment,
    aws_scheduler as scheduler,
    aws_events as events,
    aws_events_targets as targets
)
from ..constants.services import Services
from ..constants.policies import PolicyUtils
from ..constants.environments import Environments
from ..constants.project_config import ProjectConfig
from ..models.configs import *
from .name_builder import NameBuilder

class ResourceBuilder:
    """Main builder class for AWS CDK resources"""
    
    def __init__(self, stack, project_config: ProjectConfig):
        self.stack = stack 
        self.project_config = project_config 
        self.name_builder = NameBuilder(self.project_config)
    
    def build_lambda_function(self, config: LambdaConfig) -> _lambda.Function:
        """Create a Lambda function with standardized configuration"""
        function_name = self.name_builder.build(Services.LAMBDA_FUNCTION, config.function_name)        
        fn = _lambda.Function(  
            self.stack, function_name,
            function_name=function_name,
            runtime=config.runtime,
            handler=config.handler,
            code=_lambda.Code.from_asset(config.code_path),
            memory_size=config.memory_size,
            environment=config.environment,
            layers=config.layers,
            timeout=config.timeout,
            role=config.role
        )        
        self.tag_resource(fn, function_name, "AWS Lambda")        
        return fn
    
    def build_lambda_docker_function(self, config: LambdaDockerConfig) -> _lambda.DockerImageFunction:
        """Create a Lambda function with standardized configuration"""
        function_name = self.name_builder.build(Services.LAMBDA_FUNCTION, config.function_name)        
        fn = _lambda.DockerImageFunction(  
            self.stack, function_name,
            function_name=function_name,
            code=config.code,
            memory_size=config.memory_size,
            environment=config.environment,
            timeout=config.timeout,
            role=config.role
        )
        self.tag_resource(fn, function_name, "AWS Lambda")        
        return fn
    
    def build_dynamodb_table(self, config: DynamoDBConfig) -> dynamodb.Table:
        """Create a DynamoDB table with standard configuration"""
        table_name = self.name_builder.build(Services.DYNAMODB_TABLE, config.table_name)
        
        table = dynamodb.Table(
            self.stack, table_name,
            table_name=table_name,
            partition_key=dynamodb.Attribute(
                name=config.partition_key,
                type=config.partition_key_type
            ),
            sort_key=dynamodb.Attribute(
                name=config.sort_key,
                type=config.sort_key_type
            ) if config.sort_key else None,
            stream=config.stream,
            billing_mode=config.billing_mode,
            removal_policy=config.removal_policy,
            encryption=config.encryption,
            point_in_time_recovery=config.point_in_time_recovery  
        )
        
        self.tag_resource(table, table_name, "AWS DynamoDB")
        return table
            
    def tag_resource(self, resource, name: str, service_name: str, additional_tags=None):
        """Apply standard tagging to resources"""
        # Apply mandatory tags
        Tags.of(resource).add("Enterprise", self.project_config.enterprise)
        Tags.of(resource).add("Project", self.project_config.project_name)
        Tags.of(resource).add("Environment", self.project_config.environment.value)
        Tags.of(resource).add("Name", name)
        Tags.of(resource).add("Service", service_name)
        Tags.of(resource).add("Owner", self.project_config.author)
        
        # Apply additional tags if provided and resource supports them
        if additional_tags:
            for key, value in additional_tags.items():
                if value:  # Only add tags with non-empty values
                    # Ensure enum values are converted to strings
                    if hasattr(value, 'value'):
                        value = value.value
                    Tags.of(resource).add(key, str(value))
    
    def import_secret(self, secret_name: str) -> secretsmanager.Secret:
        """Import an existing secret"""
        return secretsmanager.Secret.from_secret_name_v2(
            self.stack, secret_name, secret_name
        )

    def build_secret(self, config: SecretConfig) -> secretsmanager.Secret:
        """Create a new secret with standard configuration"""
        # Use the secret name directly without name transformation to match extract_data.py convention
        secret_name = config.secret_name
        
        # Convert string secret value to SecretValue if needed
        if isinstance(config.secret_value, str):
            secret_value = SecretValue.unsafe_plain_text(config.secret_value)
        else:
            secret_value = config.secret_value
            
        secret = secretsmanager.Secret(
            self.stack, secret_name.replace("/", "_").replace("-", "_"),  # CDK construct ID
            secret_name=secret_name,
            secret_string_value=secret_value
        )
        self.tag_resource(secret, secret_name, "AWS Secrets Manager")
        return secret
    
    def import_dynamodb_table(self, table_name: str) -> dynamodb.Table:
        """Import an existing DynamoDB table"""
        return dynamodb.Table.from_table_name(
            self.stack, table_name, table_name
        )

    def build_lambda_rest_api(self, config: LambdaRestApiConfig) -> apigw.LambdaRestApi:
        """Create a Lambda function with standardized configuration"""
        rest_api_name = self.name_builder.build(Services.API_GATEWAY, config.rest_api_name)
        
        api = apigw.LambdaRestApi(  
            self.stack, rest_api_name,
            rest_api_name=rest_api_name, 
            description=config.description,
            handler=config.handler,
            deploy_options=config.deploy_options,
            default_cors_preflight_options=config.default_cors_preflight_options,
            default_method_options=config.default_method_options,
            endpoint_types=config.endpoint_types,
            cloud_watch_role=config.cloud_watch_role,
            proxy=config.proxy,
        )
        
        self.tag_resource(api, rest_api_name, "AWS API Gateway")        
        return api

    def build_sqs_queue(self, config: SQSConfig) -> sqs.Queue:
        """Create a new SQS queue with standard configuration"""
        queue_name = self.name_builder.build(Services.SQS, config.queue_name)
        queue = sqs.Queue(
            self.stack, queue_name,
            queue_name=queue_name,
            visibility_timeout=config.visibility_timeout,
            retention_period=config.retention_period,
            fifo=config.fifo,
            content_based_deduplication=config.content_based_deduplication,
            removal_policy=config.removal_policy
        )
        self.tag_resource(queue, queue_name, "AWS SQS")
        return queue

    def build_s3_bucket(self, config: S3Config) -> s3.Bucket:
        """Create a new S3 bucket with standard configuration"""
        bucket_name = self.name_builder.build(Services.S3_BUCKET, config.bucket_name)
        bucket = s3.Bucket(
            self.stack, bucket_name,
            bucket_name=bucket_name,
            block_public_access=config.block_public_access,
            versioned=config.versioned,
            removal_policy=config.removal_policy
        )
        self.tag_resource(bucket, bucket_name, "AWS S3")
        return bucket
    
    def import_s3_bucket(self, bucket_name: str) -> s3.Bucket:
        """Import an existing S3 bucket"""
        return s3.Bucket.from_bucket_name(
            self.stack, bucket_name, bucket_name
        )
    
    def build_sns_topic(self, config: SNSTopicConfig) -> sns.Topic:
        """Create a SNS topic with standard configuration"""
        topic_name = self.name_builder.build(Services.SNS_TOPIC, config.topic_name)
        
        topic = sns.Topic(
            self.stack, topic_name,
            topic_name=topic_name
        )
        
        self.tag_resource(topic, topic_name, "AWS SNS")
        return topic
    
    def import_sns_topic(self, topic_name: str) -> sns.Topic:
        """Import an existing SNS topic"""        
        return sns.Topic.from_topic_arn(
            self.stack, topic_name, f"arn:aws:sns:{self.stack.region}:{self.stack.account}:{topic_name}"
        )   
    
    def build_glue_job(self, config: GlueJobConfig) -> glue.Job:
        """Create a Glue ETL job with standard configuration"""
        job_name = self.name_builder.build(Services.GLUE_JOB, config.job_name)

        job_kwargs = dict(
            job_name=job_name,
            executable=config.executable,
            connections=config.connections,
            default_arguments=config.default_arguments,
            worker_type=config.worker_type,
            worker_count=config.worker_count,
            continuous_logging=config.continuous_logging,
            timeout=config.timeout,
            max_concurrent_runs=config.max_concurrent_runs,
            role=config.role
        )

        # Only set max_capacity if present (for PythonShell jobs)
        if getattr(config, 'max_capacity', None) is not None:
            job_kwargs['max_capacity'] = config.max_capacity

        job = glue.Job(self.stack, job_name, **job_kwargs)
        
        # Extract any additional tags from the config
        additional_tags = getattr(config, 'tags', {}) if hasattr(config, 'tags') else {}
        
        self.tag_resource(job, job_name, "AWS Glue", additional_tags)
        return job
    
    #def build_glue_job_shell(self, config: GlueJobPythonShellConfig) -> glue.PythonShellJob:
    #    """Create a Glue ETL job with standard configuration"""
    #    job_name = self.name_builder.build(Services.GLUE_JOB, config.job_name)
    #    
    #    job = glue.PythonShellJob(
    #        self.stack, job_name,
    #        job_name=job_name,
    #        script=config.script,
    #        python_version=config.python_version,
    #        glue_version=config.glue_version,
    #        description=config.description,
    #        max_capacity=config.max_capacity,
    #        role=config.role,
    #        continuous_logging=config.continuous_logging,
    #        worker_type=config.worker_type,
    #        max_concurrent_runs=config.max_concurrent_runs,
    #        timeout=config.timeout,
    #        number_of_workers=config.number_of_workers,
    #        max_retries=config.max_retries            
    #    )
    #    
    #    self.tag_resource(job, job_name, "AWS Glue")
    #    return job

    def import_glue_job(self, job_name: str) -> glue.Job:
        """Import an existing Glue job"""
        job = glue.Job.from_job_name(
            self.stack, job_name, job_name
        )
    
    def build_step_function(self, config: StepFunctionConfig) -> sf.StateMachine:
        """Create a Step Functions state machine with standard configuration"""
        state_machine_name = self.name_builder.build(Services.STEP_FUNCTION, config.name)
        
        # Create the StateMachine - role must be provided if disable_auto_permissions is True
        state_machine = sf.StateMachine(
            self.stack, state_machine_name,
            state_machine_name=state_machine_name,
            definition=config.definition,
            definition_body=config.definition_body,
            role=config.role,
            timeout=config.timeout
        )
        
        # If disable_auto_permissions is True and we have a role, 
        # we prevent CDK from auto-granting additional permissions by ensuring 
        # the role already has the necessary permissions
        if config.disable_auto_permissions and config.role:
            # The role should already have the necessary permissions
            # This is just a marker that we don't want CDK to auto-grant
            pass
        
        # Extract any additional tags from the config
        additional_tags = getattr(config, 'tags', {}) if hasattr(config, 'tags') else {}
        
        self.tag_resource(state_machine, state_machine_name, "AWS Step Functions", additional_tags)
        return state_machine
    
    def deploy_s3_bucket(self, config: S3DeploymentConfig) -> s3_deployment.BucketDeployment:
        """Create a new S3 bucket with standard configuration"""
        bucket_deployment = s3_deployment.BucketDeployment(
            self.stack, config.name,
            sources=config.sources,
            destination_bucket=config.destination_bucket,
            destination_key_prefix=config.destination_key_prefix,
            prune=config.prune
        )
        
        return bucket_deployment
    

    def build_role(self, config: RoleConfig) -> iam.Role:
        """Create a new IAM role with standard configuration"""
        role_name = self.name_builder.build(Services.IAM_ROLE, config.role_name)
        
        role = iam.Role(
            self.stack, role_name,
            role_name=role_name,
            assumed_by=config.assumed_by,
            managed_policies=config.managed_policies,
            inline_policies=config.inline_policies,
            permissions_boundary=config.permissions_boundary,
            description=config.description,
            max_session_duration=config.max_session_duration
        )

        return role
        
    def build_extract_role(self, role_name: str, resources: Dict[str, List[str]], tags: Dict[str, str] = None) -> iam.Role:
        """Create a specialized role for extract jobs with minimum required permissions"""
        config = GlueRoleConfig(
            role_name=role_name,
            additional_policies=PolicyUtils.S3_FULL + PolicyUtils.DYNAMODB_WRITE + PolicyUtils.SNS_PUBLISH + PolicyUtils.SECRET_MANAGER_READ,
            resource_arns=resources,
            tags=tags,
            description="Role for extract Glue jobs with minimum required permissions"
        )
        return self.build_glue_role(config)
    
    def build_light_transform_role(self, role_name: str, resources: Dict[str, List[str]], tags: Dict[str, str] = None) -> iam.Role:
        """Create a specialized role for light transform jobs with minimum required permissions"""
        config = GlueRoleConfig(
            role_name=role_name,
            additional_policies=PolicyUtils.S3_FULL + PolicyUtils.DYNAMODB_WRITE + PolicyUtils.SNS_PUBLISH,
            resource_arns=resources,
            tags=tags,
            description="Role for light transform Glue jobs with minimum required permissions"
        )
        return self.build_glue_role(config)
    
    def build_crawler_role(self, role_name: str, resources: Dict[str, List[str]], tags: Dict[str, str] = None) -> iam.Role:
        """Create a specialized role for crawler jobs with minimum required permissions"""
        config = GlueRoleConfig(
            role_name=role_name,
            additional_policies=PolicyUtils.S3_FULL + PolicyUtils.GLUE_CATALOG_FULL + PolicyUtils.GLUE_CRAWLER_EXECUTE + PolicyUtils.DYNAMODB_WRITE + PolicyUtils.SNS_PUBLISH + PolicyUtils.LAKE_FORMATION_FULL + PolicyUtils.IAM_PASS_ROLE,
            resource_arns=resources,
            tags=tags,
            description="Role for crawler Glue jobs with full S3, Lake Formation, LF-Tag, and IAM PassRole permissions"
        )
        return self.build_glue_role(config)
    
    def build_step_function_role(self, role_name: str, resources: Dict[str, List[str]], tags: Dict[str, str] = None) -> iam.Role:
        """Create a specialized role for Step Functions with minimum required permissions"""
        # Create basic logging policy with scoped resources
        logs_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=PolicyUtils.LOGS_ADMIN,
            resources=[
                # Scope log resources to specific role-related log groups
                f"arn:aws:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:log-group:/aws/states/{role_name}*:*",
                f"arn:aws:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:log-group:/aws/vendedlogs/states/{role_name}*:*"
            ]
        )
        
        # Add EventBridge permissions for Step Functions managed rules
        eventbridge_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=PolicyUtils.EVENTBRIDGE_MANAGE,
            resources=[
                f"arn:aws:events:{Aws.REGION}:{Aws.ACCOUNT_ID}:rule/*"
            ]
        )
        
        # Create inline policy document
        policy_doc = iam.PolicyDocument(
            statements=[logs_policy, eventbridge_policy]
        )
        
        # Add specific resource permissions for Glue jobs and SNS
        if resources:
            if 'glue' in resources and resources['glue']:
                policy_doc.add_statements(
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=PolicyUtils.GLUE_JOB_EXECUTE,
                        resources=resources['glue']
                    )
                )
            
            if 'sns' in resources and resources['sns']:
                policy_doc.add_statements(
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=PolicyUtils.SNS_PUBLISH,
                        resources=resources['sns']
                    )
                )
                
            if 'states' in resources and resources['states']:
                policy_doc.add_statements(
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=PolicyUtils.STEP_FUNCTIONS_EXECUTE,
                        resources=resources['states']
                    )
                )
                
            if 'lambda' in resources and resources['lambda']:
                policy_doc.add_statements(
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=PolicyUtils.LAMBDA_INVOKE,
                        resources=resources['lambda']
                    )
                )
        
        # Create role config
        config = StepFunctionRoleConfig(
            role_name=role_name,
            inline_policies={
                "StepFunctionMinimalPolicy": policy_doc
            },
            tags=tags,
            description="Role for Step Functions with minimum required permissions"
        )
        
        # Build the role
        role_name_formatted = self.name_builder.build(Services.IAM_ROLE, config.role_name)
        
        role = iam.Role(
            self.stack, role_name_formatted,
            role_name=role_name_formatted,
            assumed_by=config.assumed_by,
            managed_policies=config.managed_policies,
            inline_policies=config.inline_policies,
            description=config.description
        )
        
        # Apply tags if provided
        if config.tags:
            for key, value in config.tags.items():
                if value:  # Only add non-empty tags
                    Tags.of(role).add(key, value)
                    
        # Apply standard tags
        self.tag_resource(role, role_name_formatted, "AWS IAM Role")
        
        return role
    
    def build_glue_connection(self, config: GlueConnectionConfig) -> glue.Connection:
        """Create a Glue connection with standard configuration"""
        from aws_cdk import aws_ec2 as ec2
        
        connection_name = self.name_builder.build(Services.GLUE_CONNECTION, config.connection_name)
        
        # Create construct ID based on the connection name
        construct_id = f"GlueConnection{config.connection_name.replace('-', '').replace('_', '').title()}"
        
        # Import existing VPC resources with generic construct IDs
        subnet = ec2.Subnet.from_subnet_attributes(
            self.stack, f"{construct_id}Subnet",
            subnet_id=config.subnet_id,
            availability_zone=config.availability_zone or "us-east-2a"
        )
        
        security_group = ec2.SecurityGroup.from_security_group_id(
            self.stack, f"{construct_id}SG",
            security_group_id=config.security_group_id
        )
        
        # Create the Glue connection
        connection = glue.Connection(
            self.stack, construct_id,
            connection_name=connection_name,
            type=glue.ConnectionType.NETWORK,
            description=config.description or f"VPC connection for {config.connection_name}",
            subnet=subnet,
            security_groups=[security_group]
        )
        
        self.tag_resource(connection, connection_name, "AWS Glue", config.tags)
        return connection
        
    def build_glue_jdbc_connection(self, config: GlueJdbcConnectionConfig) -> glue.Connection:
        """Create a Glue JDBC connection with standard configuration"""
        from aws_cdk import aws_ec2 as ec2
        
        connection_name = self.name_builder.build(Services.GLUE_CONNECTION, config.connection_name)
        
        # Create construct ID based on the connection name
        construct_id = f"GlueJdbcConnection{config.connection_name.replace('-', '').replace('_', '').title()}"
        
        # Import existing VPC resources with generic construct IDs
        subnet = ec2.Subnet.from_subnet_attributes(
            self.stack, f"{construct_id}Subnet",
            subnet_id=config.subnet_id,
            availability_zone=config.availability_zone or "us-east-2a"
        )
        
        security_group = ec2.SecurityGroup.from_security_group_id(
            self.stack, f"{construct_id}SG",
            security_group_id=config.security_group_id
        )
        
        # Create the Glue JDBC connection
        connection = glue.Connection(
            self.stack, construct_id,
            connection_name=connection_name,
            type=glue.ConnectionType.JDBC,
            description=config.description or f"JDBC connection for {config.connection_name}",
            subnet=subnet,
            security_groups=[security_group],
            properties={
                "JDBC_CONNECTION_URL": config.jdbc_url,
                "USERNAME": config.username,
                "PASSWORD": config.password
            }
        )
        
        self.tag_resource(connection, connection_name, "AWS Glue", config.tags)
        return connection
        
    def build_glue_role(self, config: GlueRoleConfig) -> iam.Role:
        """Create a new IAM role for Glue jobs with minimum required permissions"""
        role_name = self.name_builder.build(Services.IAM_ROLE, config.role_name)
        
        # Start with base role configuration
        role = iam.Role(
            self.stack, role_name,
            role_name=role_name,
            assumed_by=config.assumed_by,
            managed_policies=config.managed_policies,
            inline_policies=config.inline_policies,
            description=config.description or f"Role for {config.role_name} Glue jobs"
        )
        
        # Add additional policies based on resource ARNs
        if config.additional_policies and config.resource_arns:
            policy_statements = []
            
            # Create policy statements for each resource type
            for resource_type, arns in config.resource_arns.items():
                if resource_type == 's3' and any(p for p in config.additional_policies 
                                               if p in PolicyUtils.S3_FULL):
                    # Filter S3 permissions
                    s3_permissions = [p for p in config.additional_policies 
                                     if p in PolicyUtils.S3_FULL]
                    if s3_permissions:
                        policy_statements.append(
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=s3_permissions,
                                resources=arns
                            )
                        )
                
                elif resource_type == 'dynamodb' and any(p for p in config.additional_policies 
                                                       if p in PolicyUtils.DYNAMODB_FULL):
                    # Filter DynamoDB permissions
                    dynamodb_permissions = [p for p in config.additional_policies 
                                         if p in PolicyUtils.DYNAMODB_FULL]
                    if dynamodb_permissions:
                        policy_statements.append(
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=dynamodb_permissions,
                                resources=arns
                            )
                        )
                
                elif resource_type == 'sns' and any(p for p in config.additional_policies 
                                                  if p in PolicyUtils.SNS_FULL):
                    # Filter SNS permissions
                    sns_permissions = [p for p in config.additional_policies 
                                     if p in PolicyUtils.SNS_FULL]
                    if sns_permissions:
                        policy_statements.append(
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=sns_permissions,
                                resources=arns
                            )
                        )
                        
                elif resource_type == 'glue' and any(p for p in config.additional_policies 
                                                   if p in (PolicyUtils.GLUE_CATALOG_FULL + PolicyUtils.GLUE_CRAWLER_EXECUTE + PolicyUtils.GLUE_JOB_EXECUTE)):
                    # Filter Glue catalog permissions
                    glue_permissions = [p for p in config.additional_policies 
                                      if p in (PolicyUtils.GLUE_CATALOG_FULL + PolicyUtils.GLUE_CRAWLER_EXECUTE + PolicyUtils.GLUE_JOB_EXECUTE)]
                    if glue_permissions:
                        policy_statements.append(
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=glue_permissions,
                                resources=arns
                            )
                        )
                        
                elif resource_type == 'lakeformation' and any(p for p in config.additional_policies 
                                                            if p in PolicyUtils.LAKE_FORMATION_FULL):
                    # Filter Lake Formation permissions (includes access, tag admin, and full permissions)
                    lf_permissions = [p for p in config.additional_policies 
                                    if p in PolicyUtils.LAKE_FORMATION_FULL]
                    if lf_permissions:
                        policy_statements.append(
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=lf_permissions,
                                resources=arns
                            )
                        )

                elif resource_type == 'secret' and any(p for p in config.additional_policies 
                                                       if p in PolicyUtils.SECRET_MANAGER_READ):
                    # Filter Secrets Manager permissions
                    secret_permissions = [p for p in config.additional_policies 
                                    if p in PolicyUtils.SECRET_MANAGER_READ]
                    
                    if secret_permissions:
                        policy_statements.append(
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=secret_permissions,
                                resources=arns
                            )
                        )
                        
                elif resource_type == 'iam' and any(p for p in config.additional_policies 
                                                   if p in (PolicyUtils.IAM_PASS_ROLE + PolicyUtils.IAM_GET_ROLE + PolicyUtils.IAM_ROLE_MANAGEMENT)):
                    # Filter IAM permissions
                    iam_permissions = [p for p in config.additional_policies 
                                     if p in (PolicyUtils.IAM_PASS_ROLE + PolicyUtils.IAM_GET_ROLE + PolicyUtils.IAM_ROLE_MANAGEMENT)]
                    if iam_permissions:
                        policy_statements.append(
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=iam_permissions,
                                resources=arns
                            )
                        )
            
            # Add the inline policy if we have statements
            if policy_statements:
                # We don't need to add a policy with "*" resource, just add individual statements
                # with properly scoped resources
                
                # Add each refined statement
                for statement in policy_statements:
                    role.add_to_policy(statement)
        
        # Apply tags if provided
        if config.tags:
            for key, value in config.tags.items():
                if value:  # Only add non-empty tags
                    Tags.of(role).add(key, value)
                    
        # Apply standard tags
        self.tag_resource(role, role_name, "AWS IAM Role")
        
        return role
        
    ##################################################################
     
    def import_api_gateway(self, config: ApiGatewayConfig) -> apigw.RestApi:
        """Import an existing API Gateway"""
        api_name = self.name_builder.build(Services.API_GATEWAY, config.name)
        return apigw.RestApi.from_rest_api_id(
            self.stack, api_name, api_name
        )

    def build_api_gateway(self, config: ApiGatewayConfig) -> apigw.RestApi:
        """Create a new API Gateway with standard configuration"""
        api_name = self.name_builder.build(Services.API_GATEWAY, config.name)
        
        api = apigw.RestApi(
            self.stack, api_name,
            rest_api_name=api_name,
            description=config.description,
            endpoint_types=config.endpoint_types,
            deploy=config.deploy,
            policy=config.policy,
            binary_media_types=config.binary_media_types,
            minimum_compression_size=config.minimum_compression_size,
        )
        
        self.tag_resource(api, api_name, "AWS API Gateway")
        return api
     
    def build_api_gateway_deployment(self, config: ApiGatewayDeploymentConfig) -> apigw.Deployment:
        """Create a new API Gateway deployment with standard configuration"""         
        deployment = apigw.Deployment(
            self.stack, config.deployment_name,
            api=config.api,
            description=config.description
        )        
        self.tag_resource(deployment, config.deployment_name, "AWS API Gateway")
        return deployment

    def build_api_gateway_stage(self, config: ApiGatewayStageConfig) -> apigw.Stage:
        """Create a new API Gateway stage with standard configuration"""
         
        stage = apigw.Stage(
            self.stack, config.stage_name,
            deployment=config.deployment,
            stage_name=config.stage_name,
            data_trace_enabled=config.data_trace_enabled,
            logging_level=config.logging_level
        )        
        self.tag_resource(stage, config.stage_name, "AWS API Gateway")
        return stage

    def build_dms_endpoint(self, config: DMSEndpointConfig) -> dms.CfnEndpoint:
        """Create a DMS endpoint with standard configuration"""
        endpoint_name = self.name_builder.build(Services.DMS_ENDPOINT, config.name)
        
        endpoint = dms.CfnEndpoint(
            self.stack, endpoint_name,
            endpoint_name=endpoint_name,
            engine_name=config.engine_name,
            username=config.username,
            password=config.password,
            server_name=config.server_name,
            port=config.port,
            database_name=config.database_name,
            s3_settings=config.s3_settings,
            kms_settings=config.kms_settings,
            tags=config.tags
        )
        
        self.tag_resource(endpoint, endpoint_name, "AWS DMS")
        return endpoint

    def build_eventbridge_scheduler(self, config: EventBridgeSchedulerConfig) -> scheduler.CfnSchedule:
        """Create an EventBridge Scheduler with standardized configuration"""
        schedule_name = self.name_builder.build(Services.EVENT_BRIDGE_SCHEDULER, config.schedule_name)
        
        # Build the target configuration
        target_config = scheduler.CfnSchedule.TargetProperty(
            arn=config.target_arn,
            role_arn=config.target_role_arn,
            input=config.target_input,
            retry_policy=scheduler.CfnSchedule.RetryPolicyProperty(
                maximum_retry_attempts=config.target_retry_policy_maximum_retry_attempts,
                maximum_event_age_in_seconds=config.target_retry_policy_maximum_event_age_in_seconds
            )
        )
        
        # Build flexible time window configuration
        if config.flexible_time_window_mode == "FLEXIBLE":
            flexible_time_window = scheduler.CfnSchedule.FlexibleTimeWindowProperty(
                mode=config.flexible_time_window_mode,
                maximum_window_in_minutes=config.flexible_time_window_maximum_window_in_minutes or 15
            )
        else:
            flexible_time_window = scheduler.CfnSchedule.FlexibleTimeWindowProperty(
                mode="OFF"
            )
        
        schedule = scheduler.CfnSchedule(
            self.stack, schedule_name,
            name=schedule_name,
            schedule_expression=config.schedule_expression,
            schedule_expression_timezone=config.timezone,
            target=target_config,
            flexible_time_window=flexible_time_window,
            description=config.description,
            group_name=config.group_name,
            state=config.state
        )
        
        # Apply tags if provided
        if config.tags:
            for key, value in config.tags.items():
                if value:  # Only add non-empty tags
                    Tags.of(schedule).add(key, value)
        
        self.tag_resource(schedule, schedule_name, "AWS EventBridge Scheduler")
        return schedule

    def build_appflow_flow(self, config: AppflowConfig) -> appflow.CfnFlow:
        """Create an Appflow flow with standardized configuration"""
        flow_name = self.name_builder.build(Services.APPFLOW, config.flow_name)
        
        flow = appflow.CfnFlow(
            self.stack, flow_name,
            flow_name=flow_name,
            source_flow_config=config.source_flow_config,
            destination_flow_config_list=config.destination_flow_config_list,
            tasks=config.tasks,
            trigger_config=config.trigger_config,
            description=config.description,
            flow_status=config.flow_status,
        )

        if config.tags:
            for key, value in config.tags.items():
                if value:  # Only add non-empty tags
                    Tags.of(flow).add(key, value)
        
        self.tag_resource(flow, flow_name, "AWS AppFlow")
        return flow
    
    def build_eventbridge_rule(self, config: EventBridgeRuleConfig) -> events.Rule:
        """
        Create an EventBridge rule with configurable targets
        
        Supports multiple target types:
        - Lambda functions
        - Step Functions
        - SQS queues
        - SNS topics
        - Custom ARN targets
        
        Example:
            config = EventBridgeRuleConfig(
                rule_name="multi-target-rule",
                event_pattern=events.EventPattern(
                    source=["aws.s3"],
                    detail_type=["Object Created"]
                ),
                targets=[
                    EventBridgeTargetConfig(
                        lambda_function=my_lambda,
                        retry_attempts=3
                    ),
                    EventBridgeTargetConfig(
                        sqs_queue=my_queue
                    )
                ]
            )
        """
        rule_name = self.name_builder.build(Services.EVENT_BRIDGE_RULE, config.rule_name)
        
        # Handle event_pattern (can be dict or EventPattern object)
        if isinstance(config.event_pattern, dict):
            event_pattern_obj = events.EventPattern(**config.event_pattern)
        else:
            event_pattern_obj = config.event_pattern
        
        # Create the rule
        rule = events.Rule(
            self.stack, rule_name,
            rule_name=rule_name,
            description=config.description,
            event_pattern=event_pattern_obj,
            schedule=events.Schedule.expression(config.schedule_expression) if config.schedule_expression else None,
            enabled=config.enabled,
            event_bus=events.EventBus.from_event_bus_name(
                self.stack, 
                f"{rule_name}-bus",
                config.event_bus_name
            ) if config.event_bus_name else None
        )
        
        # Add targets
        for idx, target_config in enumerate(config.targets):
            self._add_target_to_rule(rule, target_config, idx)
        
        # Apply tags
        self.tag_resource(rule, rule_name, "AWS EventBridge Rule", config.tags)
        
        return rule
    
    def _add_target_to_rule(
        self, 
        rule: events.Rule, 
        target_config: EventBridgeTargetConfig,
        index: int
    ) -> None:
        """Internal method to add a target to an EventBridge rule"""
        
        # Common target properties
        common_props = {
            "retry_attempts": target_config.retry_attempts,
            "max_event_age": target_config.max_event_age,
        }
        
        if target_config.dead_letter_queue:
            common_props["dead_letter_queue"] = target_config.dead_letter_queue
        
        # Lambda target
        if target_config.lambda_function:
            rule.add_target(
                targets.LambdaFunction(
                    target_config.lambda_function,
                    event=target_config.input_transformer,
                    **common_props
                )
            )
        
        # Step Function target
        elif target_config.state_machine:
            sf_target_props = {
                "input": target_config.input_transformer,
                **common_props
            }
            
            if target_config.state_machine_role:
                sf_target_props["role"] = target_config.state_machine_role
            
            rule.add_target(
                targets.SfnStateMachine(
                    target_config.state_machine,
                    **sf_target_props
                )
            )
        
        # SQS target
        elif target_config.sqs_queue:
            sqs_props = {**common_props}
            
            if target_config.message_group_id:
                sqs_props["message_group_id"] = target_config.message_group_id
            
            if target_config.input_transformer:
                sqs_props["message"] = target_config.input_transformer
            
            rule.add_target(
                targets.SqsQueue(
                    target_config.sqs_queue,
                    **sqs_props
                )
            )
        
        # SNS target
        elif target_config.sns_topic:
            sns_props = {**common_props}
            
            if target_config.input_transformer:
                sns_props["message"] = target_config.input_transformer
            
            rule.add_target(
                targets.SnsTopic(
                    target_config.sns_topic,
                    **sns_props
                )
            )
        
        # Generic ARN target
        elif target_config.arn:
            # For custom targets not covered by CDK constructs
            from aws_cdk.aws_events import CfnRule
            
            cfn_rule = rule.node.default_child
            if isinstance(cfn_rule, CfnRule):
                target_property = CfnRule.TargetProperty(
                    arn=target_config.arn,
                    id=f"Target{index}",
                    retry_policy=CfnRule.RetryPolicyProperty(
                        maximum_retry_attempts=target_config.retry_attempts,
                        maximum_event_age_in_seconds=target_config.max_event_age.to_seconds()
                    ) if target_config.retry_attempts > 0 else None,
                    dead_letter_config=CfnRule.DeadLetterConfigProperty(
                        arn=target_config.dead_letter_queue.queue_arn
                    ) if target_config.dead_letter_queue else None
                )
                
                # Add to existing targets
                existing_targets = cfn_rule.targets or []
                cfn_rule.targets = existing_targets + [target_property]