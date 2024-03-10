import os.path

from aws_cdk_.aws_s3_assets import Asset as S3asset

from aws_cdk import (
    # Duration,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_rds as rds,
    # aws_sqs as sqs,
)
from constructs import Construct

dirname = os.path.dirname(__file__)

class CdkLabWebServerStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, vpc: ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        cdk_lab_vpc = ec2.Vpc(self, "cdk_lab_vpc", 
                    ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
                    subnet_configuration=[ec2.SubnetConfiguration(name="PublicSubnet01",subnet_type=ec2.SubnetType.PUBLIC)])
                    
                    
        InstanceRole = iam.Role(self, "InstanceSSM", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
    
        InstanceRole.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
    
        cdk_lab_web_instance = ec2.Instance(self, "cdk_lab_web_instance", 
                    vpc=cdk_lab_vpc, 
                    instance_type = ec2.InstanceType("t2.micro"),
                    machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
                    role=InstanceRole)
    
        webinitscriptasset = S3asset(self, "Asset", path=os.path.join(dirname, "configure.sh"))
        asset_path = cdk_lab_web_instance.user_data.add_s3_download_command(
            bucket=webinitscriptasset.bucket,
            bucket_key=webinitscriptasset.s3_object_key
            )
            
        cdk_lab_web_instance.user_data.add_execute_file_command(
            file_path=asset_path
            )
        webinitscriptasset.grant_read(cdk_lab_web_instance.role)
        
        cdk_lab_web_instance.connections.allow_from_any_ipv4(ec2.Port.tcp(80))
        
        # Create RDS Instance
        rds_instance = rds.DatabaseInstance(
            self, "MyDatabase",
            engine=rds.DatabaseInstanceEngine.mysql(
                version=rds.MysqlEngineVersion.VER_8_0
            ),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
                vpc=vpc,
                vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE),
                security_groups=[ec2.SecurityGroup.from_security_group_id(
                    self, "RdsSecurityGroup",
                    vpc.vpc_default_security_group
            )]
        )

        # Allow traffic from EC2 Instance to RDS
        rds_instance.connections.allow_from(
            cdk_lab_web_instance.connections,
            ec2.Port.tcp(3306),
            "Allow inbound MySQL"
        )
