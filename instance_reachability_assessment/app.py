"""
app.py
This lambda function is used to verify connectivity between an internet gateway a
nd EC2 instances using Reachability Analyzer.  This function is triggered by
Amazon EventBridge as a result of a security group change in a VPC.
"""
from datetime import datetime, timezone
import logging
import time
import os
import boto3
import botocore

security_group_events = ["AuthorizeSecurityGroupIngress",
                         "AuthorizeSecurityGroupEngress",
                         "RevokeSecurityGroupIngress",
                         "RevokeSecurityGroupEgress"]

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def create_boto3_session():
    """
    Creates boto3 session.

    Returns:
        Boto3 session object
    """
    session = boto3.session.Session()
    return session


def get_security_group_id(event):
    """
    Pulls the security group ID from the event object passed to the lambda from EventBridge.

    Args:
        event: Event object passed to the lambda from EventBridge

    Returns:
        string: Security group ID
    """
    return event.get("detail").get("requestParameters").get("groupId")


def check_security_group_event_name(event):
    """
    Verifies the event type from the event object passed to the lambda
    is a security group change event.
    Args:
        event: Event object passed to the lambda from EventBridge

    Returns:
        bool: return True if eventName is security group change event type
    """
    return event.get("detail").get("eventName") in security_group_events


def get_affected_ec2_instaces(ec2_session, security_group_id):
    """
    Finds all EC2 instances which have the security group argument attached.
    Args:
        ec2_session (botocore.session.Session): Boto3 session object for EC2
        security_group_id (string): security group id extracted from lambda event

    Returns:
        array of string: instance IDs as array of string
    """
    instances = ec2_session.describe_instances(
        Filters=[
            {
                'Name': 'network-interface.group-id',
                'Values': [
                    security_group_id
                ]
            }
        ],
        MaxResults=100
    )

    affected_instances = []
    for reservation in instances.get('Reservations'):
        for instance in reservation.get('Instances'):
            affected_instances.append(instance.get("InstanceId"))

    return affected_instances


def get_affected_reachability_analyzer_paths(ec2_session, affected_instances):
    """
    Discovers reachability analyzer paths which are sourced from an IGW
    and destined to one of the affected_instances.
    Args:
        ec2_session (botocore.session.Session): Boto3 session object for EC2
        affected_instances (array of strings): List of affected EC2 instances

    Returns:
        An array of objects:
        {
            instance_id: string,
            network_insights_path_id: string
        }
    """
    impacted_network_insights_paths = []
    network_insights_paths = ec2_session.describe_network_insights_paths()

    if (
        network_insights_paths.get('NetworkInsightsPaths') is None or
        len(network_insights_paths.get('NetworkInsightsPaths')) == 0
    ):
        return impacted_network_insights_paths
    for instance_id in affected_instances:
        for network_insight_path in network_insights_paths.get(
                'NetworkInsightsPaths'):
            if (
                network_insight_path.get('Destination') == instance_id and
                network_insight_path.get('Source').startswith('igw-')
            ):
                # Add path ID to affected_paths
                impacted_network_insights_paths.append({
                    'instance_id': instance_id,
                    'network_insights_path_id': network_insight_path.get('NetworkInsightsPathId'),
                })

    return impacted_network_insights_paths


def start_network_insights_analysis(ec2_session, network_insights_paths):
    """
    Starts Reachability Analyzer analysis based on a list of network insights paths.
    Args:
        ec2_session (botocore.session.Session): Boto3 session object for EC2
        network_insights_paths (
            {
                instance_id: string,
                network_insights_path_id: string
            }
        ): Array of network insights paths

    Returns:
        An array of objects:
        {
            instance_id: string,
            network_insights_path_id: string,
            network_insights_analysis_id: string
            status: string
        }

    Raises:
        RuntimeError: Network Insights Path could not be started.
    """
    for index, network_insights_path in enumerate(network_insights_paths):
        response = ec2_session.start_network_insights_analysis(
            NetworkInsightsPathId=network_insights_path['network_insights_path_id']
        )

        if response.get('NetworkInsightsAnalysis').get('Status') == 'running':
            network_insights_paths[index].update(
                {
                    'status': response.get('NetworkInsightsAnalysis').get('Status'),
                    'network_insights_analysis_id': response
                    .get('NetworkInsightsAnalysis')
                    .get('NetworkInsightsAnalysisId')
                }
            )
        else:
            logger.error(
                "Network analysis could not be started for path: %s and instance %s",
                network_insights_path.get('network_insights_path_id'),
                network_insights_path.get('instance_id')
            )

    if not any(network_insights_path for network_insights_path
               in network_insights_paths
               if network_insights_path.get('status') == 'running'):
        instance_ids = list(map(lambda path: path.get(
            'instance_id'), network_insights_paths))
        raise RuntimeError(
            f'Failed to start Network Insights analysis for any affected instances: {instance_ids}'
        )

    return list(
        filter(lambda path: (
            path.get('status') is not None
            and path.get('status') == 'running'
        ),
            network_insights_paths)
    )


def get_network_insights_results(ec2_session, network_insights_paths, context):
    """
    Polls Reachability Analyzer for results of analyses. Analyses
    specified by the network_insights_paths arra
    Args:
        ec2_session (botocore.session.Session): Boto3 session object for EC2
        network_insights_paths (
            {
                instance_id: string,
                network_insights_path_id: string
                network_insights_analysis_id: string
                status: string
            }
        ): Array of network insights paths

    Returns:
        An array of objects:
        {
            instance_id: string,
            network_insights_path_id: string
            network_insights_analysis_id: string
            status: string
            analysis_result: bool
        }
    """
    completed_analyses = 0

    while (
        completed_analyses < len(network_insights_paths) and
        context.get_remaining_time_in_millis() / 1000 >= 2
    ):
        for network_insights_path in network_insights_paths:
            if (
                network_insights_path.get('status') == 'succeeded' or
                network_insights_path.get('status') == 'skip'
            ):
                continue

            if context.get_remaining_time_in_millis() / 1000 < 2:
                break

            try:
                analysis = ec2_session.describe_network_insights_analyses(
                    NetworkInsightsAnalysisIds=[network_insights_path.get(
                        'network_insights_analysis_id')]
                )

                if not len(analysis.get('NetworkInsightsAnalyses')) > 0:
                    logger.error(
                        "No analysis found for path: %s and instance %s",
                        network_insights_path.get('network_insights_path_id'),
                        network_insights_path.get('instance_id')
                    )
                    network_insights_path.update({
                        'status': 'skip'
                    })
                    completed_analyses += 1
                    continue

                if analysis.get('NetworkInsightsAnalyses')[0].get('Status') == 'succeeded':
                    completed_analyses += 1
                    network_insights_path.update({
                        'status': analysis.get('NetworkInsightsAnalyses')[0].get('Status'),
                        'analysis_result': analysis
                        .get('NetworkInsightsAnalyses')[0]
                        .get('NetworkPathFound')
                    })

            except botocore.exceptions.ClientError:
                logger.error(
                    "No analysis found for path: %s and instance %s",
                    network_insights_path.get('network_insights_path_id'),
                    network_insights_path.get('instance_id')
                )
                network_insights_path.update({
                    'status': 'skip'
                })
                completed_analyses += 1
                continue

        if context.get_remaining_time_in_millis() / 1000 >= 2:
            if not (
                all(network_insights_path.get('status') == 'succeeded' or network_insights_path.get(
                    'status') == 'skip' for network_insights_path in network_insights_paths)
            ):
                logger.info('Sleeping for 3 seconds.')
                time.sleep(3)
        else:
            break

    return network_insights_paths


def send_sns_notification(failed_paths, unknown_status_paths,
                          sns_session, sns_topic_arn, security_group_id):
    """
    Publishes all failed or unknown instances which were affected by
    the security group change to SNS.
    Args:
        failed_paths (
            {
                instance_id: string,
                network_insights_path_id: string
                network_insights_analysis_id: string
                status: string
                analysis_result: bool
            }
        ): Array of network insights paths
        unknown_status_paths (
            {
                instance_id: string,
                network_insights_path_id: string
                network_insights_analysis_id: string
                status: string
                analysis_result: bool
            }
        ): Array of network insights paths
        sns_session (botocore.session.Session): SNS boto3 session object
        sns_topic_arn (string): Topic ARN for SNS
        security_group_id (string): Security group ID string

    Returns:
        void
    """
    message = ""
    if len(failed_paths) > 0:
        instance_ids = ', '.join(
            list({failed_path.get('instance_id')
                  for failed_path in failed_paths})
        )
        message += f"The following instances: {instance_ids} "
        message += "did not pass reachability assessment after security group "
        message += f"{security_group_id} was updated.\n\n"

    if len(unknown_status_paths) > 0:
        instance_ids = ', '.join(
            list(
                {unknown_status_path.get('instance_id')
                 for unknown_status_path in unknown_status_paths}
            )
        )
        message += f"The following instances: {instance_ids} "
        message += "did not complete reachability assessment after security group "
        message += f"{security_group_id} was updated."

    if message != "":
        sns_session.publish(TopicArn=sns_topic_arn, Message=message)

    return


def lambda_handler(event, context):
    """
    Handler function for the lambda. Triggered by EventBridge.
    Args:
        event: Event object passed to the lambda from EventBridge
        context: Context object passed to the lambda

    Returns:
        num: Returns 0 for successful execution
    """
    logger.info(event)
    logger.info("Creating ec2 session.")
    session = create_boto3_session()
    ec2 = session.client('ec2', region_name=os.environ.get('AWS_REGION'))

    logger.info("Gathering impacted security group ID")
    security_group_id = get_security_group_id(event)

    logger.info("Verifying securty group event applies to this lambda")
    if not check_security_group_event_name(event):
        logger.info(
            "Security group event does not apply to this lambda. Exiting."
        )
        return 0

    logger.info(
        "Determining EC2 instances with security group %s attached.",
        security_group_id
    )
    affected_ec2_instances = get_affected_ec2_instaces(ec2, security_group_id)
    if len(affected_ec2_instances) == 0:
        logger.info(
            "No instances affected by this security group change. Exiting."
        )
        return 0
    logger.info("Affected ec2 instances: %s", affected_ec2_instances)

    network_insights_paths = get_affected_reachability_analyzer_paths(
        ec2, affected_ec2_instances)
    if len(network_insights_paths) == 0:
        logger.info("No network insight paths exist for any affected instances or "
                    "the security group event does not impact reachability. Exiting gracefully.")
        return 0

    logger.info("Starting network insights analysis for affected instances.")
    network_insights_paths = start_network_insights_analysis(
        ec2,
        network_insights_paths
    )

    logger.info("Fetching network insights results...")
    network_insights_paths = get_network_insights_results(
        ec2,
        network_insights_paths, context
    )

    failed_paths = list(
        filter(
            lambda path: (
                path.get('analysis_result') is False
            ),
            network_insights_paths
        )
    )

    unknown_status_paths = list(
        filter(
            lambda path: (
                path.get('status') == 'running'
                or path.get('status') == 'skip'
                or path.get('status') is None
            ),
            network_insights_paths
        )
    )

    if len(failed_paths) > 0 or len(unknown_status_paths) > 0:
        logger.info("Sending SNS notifications for instances which "
                    "failed or did not complete reachability assessment.")

        sns = session.client('sns')
        assert ('SNS_TOPIC_ARN' in os.environ), (
            'SNS Topic ARN is missing in environment variables. Publishing SNS Messages will fail.'
        )

        send_sns_notification(
            failed_paths,
            unknown_status_paths,
            sns,
            os.environ.get('SNS_TOPIC_ARN'),
            security_group_id
        )
        return 0

    logger.info("All instances passed reachability assessment. "
                "Exiting gracefully.")
    return 0
