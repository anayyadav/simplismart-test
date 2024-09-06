import argparse
import json
import logging
import re
import time
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Set up logging
logging.basicConfig(
    filename='deployment_script.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config(config_file):
    """
    Load the configuration from a JSON file.
    
    :param config_file: Path to the configuration file.
    :return: Configuration data as a dictionary or None if loading fails.
    """
    try:
        with open(config_file, 'r') as file:
            config_data = json.load(file)
        logger.info("Configuration file loaded successfully.")
        return config_data
    except Exception as e:
        logger.error(f"Failed to load configuration file: {e}")
        print("Error: Could not load the configuration file. Ensure the file exists and is in correct JSON format.")
        return None


def validate_config(config_data):
    """
    Validate the configuration data to ensure all inputs are correct.
    
    :param config_data: Configuration data as a dictionary.
    :return: True if validation is successful, False otherwise.
    """
    # Validate namespace format
    if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', config_data.get('namespace', '')):
        logger.error("Invalid namespace format.")
        print("Error: Invalid namespace format. It must be lowercase and can contain hyphens.")
        return False

    # Validate deployment name format
    if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', config_data.get('deployment_name', '')):
        logger.error("Invalid deployment name format.")
        print("Error: Invalid deployment name format. It must be lowercase and can contain hyphens.")
        return False

    # Validate image format
    if not re.match(r'^([\w\-\.]+/)?[\w\-\.]+:[\w\-\.]+$', config_data.get('image', '')):
        logger.error("Invalid image format.")
        print("Error: Invalid image format. It should be in the format 'repository/image:tag'.")
        return False

    # Validate CPU and Memory requests and limits
    cpu_memory_pattern = re.compile(r'^\d+m?$')  # Matches '100m', '500m', etc.
    memory_pattern = re.compile(r'^\d+Mi$')     # Matches '256Mi', '512Mi', etc.
    
    cpu_request_valid = cpu_memory_pattern.match(config_data.get('cpu_request', ''))
    cpu_limit_valid = cpu_memory_pattern.match(config_data.get('cpu_limit', ''))
    memory_request_valid = memory_pattern.match(config_data.get('memory_request', ''))
    memory_limit_valid = memory_pattern.match(config_data.get('memory_limit', ''))

    if not (cpu_request_valid and cpu_limit_valid and memory_request_valid and memory_limit_valid):
        logger.error("Invalid CPU or memory request/limit format.")
        print("Error: Invalid CPU or memory request/limit format. They should be in the format '100m' or '128Mi'.")
        return False

    # Validate port number
    if not (isinstance(config_data.get('port', None), int) and 1 <= config_data['port'] <= 65535):
        logger.error("Invalid port value.")
        print("Error: Port value must be an integer between 1 and 65535.")
        return False

    # Validate HPA values
    if not (isinstance(config_data.get('min_replicas', None), int) and
            isinstance(config_data.get('max_replicas', None), int) and
            0 <= config_data['min_replicas'] <= config_data['max_replicas']):
        logger.error("Invalid HPA replicas values.")
        print("Error: Min replicas and max replicas must be integers and min replicas should not be greater than max replicas.")
        return False

    # Validate PDB min available value
    if not isinstance(config_data.get('pdb_min_available', ''), str):
        logger.error("Invalid Pod Disruption Budget value.")
        print("Error: PDB min available should be a valid string.")
        return False

    # Validate JSON formats for node selector, node affinity, and tolerations
    try:
        # Validate node selector
        node_selector = config_data.get('node_selector', {})
        if not isinstance(node_selector, dict):
            raise ValueError("Node selector must be a dictionary.")

        # Validate node affinity
        node_affinity = config_data.get('node_affinity', [])
        if not isinstance(node_affinity, list):
            raise ValueError("Node affinity must be a list.")
        for term in node_affinity:
            if not all(key in term for key in ('key', 'operator', 'values')):
                raise ValueError("Invalid node affinity term.")
            if not isinstance(term.get('values'), list):
                raise ValueError("Node affinity values must be a list.")

        # Validate pod anti-affinity
        pod_anti_affinity = config_data.get('pod_anti_affinity', [])
        if not isinstance(pod_anti_affinity, list):
            raise ValueError("Pod anti-affinity must be a list.")
        for term in pod_anti_affinity:
            if not all(key in term for key in ('label_selector', 'topology_key')):
                raise ValueError("Invalid pod anti-affinity term.")
            if not isinstance(term.get('label_selector'), dict):
                raise ValueError("Pod anti-affinity label_selector must be a dictionary.")
            if not isinstance(term.get('topology_key'), str):
                raise ValueError("Pod anti-affinity topology_key must be a string.")

        # Validate tolerations
        tolerations = config_data.get('tolerations', [])
        if not isinstance(tolerations, list):
            raise ValueError("Tolerations must be a list.")
        for toleration in tolerations:
            if not all(key in toleration for key in ('key', 'operator', 'value', 'effect')):
                raise ValueError("Invalid toleration term.")
            if not isinstance(toleration.get('key'), str):
                raise ValueError("Toleration key must be a string.")
            if not isinstance(toleration.get('operator'), str):
                raise ValueError("Toleration operator must be a string.")
            if not isinstance(toleration.get('value'), str):
                raise ValueError("Toleration value must be a string.")
            if not isinstance(toleration.get('effect'), str):
                raise ValueError("Toleration effect must be a string.")

    except ValueError as e:
        logger.error(f"Value error: {e}")
        print("Error: Invalid value in node affinity, pod anti-affinity, or tolerations.")
        return False

    return True

def initialize_cluster():
    """
    Initialize the Kubernetes cluster connection.
    """
    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()
        v1.get_api_resources()  # Test cluster connection
        logger.info("Cluster connected successfully.")
    except ApiException as e:
        logger.error(f"API exception: {e}")
        print("Error: Kubernetes API exception. Check your kubeconfig file and cluster connection.")
    except Exception as e:
        logger.error(f"Failed to initialize cluster: {e}")
        print("Error: Could not initialize the Kubernetes cluster. Check your kubeconfig file and cluster connection.")

def create_deployment(config_data):
    """
    Create a deployment, service, and HPA in the Kubernetes cluster based on the provided configuration.
    
    :param config_data: Configuration data as a dictionary.
    """
    if not validate_config(config_data):
        return

    try:
        config.load_kube_config()
    except Exception as e:
        logger.error(f"Failed to load kubeconfig: {e}")
        print("Error: Could not load kubeconfig. Ensure the file is correct and accessible.")
        return

    try:
        node_selector_dict = config_data['node_selector'] if config_data['node_selector'] else {}
    except json.JSONDecodeError as e:
        logger.error(f"Node selector JSON parsing error: {e}")
        print("Error: Invalid JSON format for node selector.")
        return

    try:
        node_affinity_obj = None
        if config_data.get('node_affinity'):
            node_affinity_obj = client.V1NodeAffinity(
                required_during_scheduling_ignored_during_execution=client.V1NodeSelector(
                    node_selector_terms=[
                        client.V1NodeSelectorTerm(
                            match_expressions=[
                                client.V1NodeSelectorRequirement(
                                    key=term['key'],
                                    operator=term['operator'],
                                    values=term['values']
                                ) for term in config_data['node_affinity']
                            ]
                        )
                    ]
                )
            )
    except Exception as e:
        logger.error(f"Node affinity processing error: {e}")
        print("Error: Failed to process node affinity settings.")
        return

    try:
        pod_anti_affinity_obj = None
        if config_data.get('pod_anti_affinity'):
            pod_anti_affinity_obj = client.V1PodAntiAffinity(
                preferred_during_scheduling_ignored_during_execution=[
                    client.V1WeightedPodAffinityTerm(
                        weight=term.get('weight', 1),
                        pod_affinity_term=client.V1PodAffinityTerm(
                            label_selector=client.V1LabelSelector(
                                match_labels=term['label_selector'].get('match_labels', {})
                            ),
                            topology_key=term.get('topology_key', 'kubernetes.io/hostname')
                        )
                    ) for term in config_data['pod_anti_affinity']
                ]
            )
    except Exception as e:
        logger.error(f"Pod anti-affinity processing error: {e}")
        print("Error: Failed to process pod anti-affinity settings.")
        return

    try:
        tolerations_objs = [
            client.V1Toleration(
                key=toleration['key'],
                operator=toleration.get('operator', 'Equal'),
                value=toleration['value'],
                effect=toleration['effect'],
                toleration_seconds=toleration.get('toleration_seconds')
            ) for toleration in config_data['tolerations']
        ] if config_data.get('tolerations') else []
    except Exception as e:
        logger.error(f"Tolerations processing error: {e}")
        print("Error: Failed to process tolerations settings.")
        return

    try:
        affinity = client.V1Affinity(
            node_affinity=node_affinity_obj,
            pod_anti_affinity=pod_anti_affinity_obj
        )

        container = client.V1Container(
            name=config_data['deployment_name'],
            image=config_data['image'],
            ports=[client.V1ContainerPort(container_port=config_data['port'])],
            resources=client.V1ResourceRequirements(
                requests={
                    "cpu": config_data['cpu_request'],
                    "memory": config_data['memory_request']
                },
                limits={
                    "cpu": config_data['cpu_limit'],
                    "memory": config_data['memory_limit']
                }
            ),
            security_context=client.V1SecurityContext(
                allow_privilege_escalation=False
            ),
            readiness_probe=client.V1Probe(
                http_get=client.V1HTTPGetAction(
                    path="/",
                    port=config_data['port']
                ),
                initial_delay_seconds=30
            ),
            liveness_probe=client.V1Probe(
                http_get=client.V1HTTPGetAction(
                    path="/",
                    port=config_data['port']
                ),
                initial_delay_seconds=30
            )
        )

        deployment = client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(name=config_data['deployment_name']),
            spec=client.V1DeploymentSpec(
                replicas=1,
                selector=client.V1LabelSelector(
                    match_labels={"app": config_data['deployment_name']}
                ),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": config_data['deployment_name']}),
                    spec=client.V1PodSpec(
                        containers=[container],
                        node_selector=node_selector_dict,
                        affinity=affinity,
                        tolerations=tolerations_objs,
                        termination_grace_period_seconds=config_data['termination_grace_period']
                    )
                )
            )
        )

        k8s_apps_v1 = client.AppsV1Api()
        k8s_apps_v1.create_namespaced_deployment(namespace=config_data['namespace'], body=deployment)
        logger.info(f"Deployment '{config_data['deployment_name']}' created in namespace '{config_data['namespace']}'.")

        service = client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=client.V1ObjectMeta(name=config_data['deployment_name']),
            spec=client.V1ServiceSpec(
                selector={"app": config_data['deployment_name']},
                ports=[client.V1ServicePort(port=config_data['port'], target_port=config_data['port'])]
            )
        )
        k8s_core_v1 = client.CoreV1Api()
        k8s_core_v1.create_namespaced_service(namespace=config_data['namespace'], body=service)
        logger.info(f"Service '{config_data['deployment_name']}' created in namespace '{config_data['namespace']}'.")

        autoscaling_v1 = client.AutoscalingV1Api()
        hpa = client.V1HorizontalPodAutoscaler(
            api_version="autoscaling/v1",
            kind="HorizontalPodAutoscaler",
            metadata=client.V1ObjectMeta(name=f"{config_data['deployment_name']}-hpa"),
            spec=client.V1HorizontalPodAutoscalerSpec(
                scale_target_ref=client.V1CrossVersionObjectReference(
                    api_version="apps/v1",
                    kind="Deployment",
                    name=config_data['deployment_name']
                ),
                min_replicas=config_data['min_replicas'],
                max_replicas=config_data['max_replicas'],
                target_cpu_utilization_percentage=config_data['target_cpu_utilization']
            )
        )
        autoscaling_v1.create_namespaced_horizontal_pod_autoscaler(namespace=config_data['namespace'], body=hpa)
        logger.info(f"Horizontal Pod Autoscaler '{config_data['deployment_name']}-hpa' created in namespace '{config_data['namespace']}'.")

        policy_v1 = client.PolicyV1Api()
        pdb = client.V1PodDisruptionBudget(
            metadata=client.V1ObjectMeta(name=f"{config_data['deployment_name']}-pdb"),
            spec=client.V1PodDisruptionBudgetSpec(
                min_available=config_data['pdb_min_available'],
                selector=client.V1LabelSelector(
                    match_labels={"app": config_data['deployment_name']}
                )
            )
        )
        policy_v1.create_namespaced_pod_disruption_budget(namespace=config_data['namespace'], body=pdb)
        logger.info(f"Pod Disruption Budget '{config_data['deployment_name']}-pdb' created in namespace '{config_data['namespace']}'.")

    except ApiException as e:
        logger.error(f"API exception: {e}")
        print("Error: Kubernetes API exception. Check the logs for details.")
    except Exception as e:
        logger.error(f"Failed to create deployment: {e}")
        print("Error: Deployment creation failed. Check the logs for details.")

def get_deployment_status(namespace, deployment_name):
    """
    Get the status of the specified deployment.
    
    :param namespace: Kubernetes namespace.
    :param deployment_name: Name of the deployment.
    :return: Deployment status as a dictionary.
    """
    try:
        config.load_kube_config()
        apps_v1 = client.AppsV1Api()
        deployment = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
        status = {
            'name': deployment.metadata.name,
            'replicas': deployment.status.replicas,
            'ready_replicas': deployment.status.ready_replicas,
            'updated_replicas': deployment.status.updated_replicas,
            'available_replicas': deployment.status.available_replicas
        }
        logger.info(f"Deployment status: {status}")
        return status
    except ApiException as e:
        logger.error(f"API exception: {e}")
        print(f"Error: {e}")
    except Exception as e:
        logger.error(f"Failed to get deployment status: {e}")
        print(f"Error: {e}")

def get_pod_status(namespace, pod_selector):
    """
    Get the status of the pods matching the specified selector.
    
    :param namespace: Kubernetes namespace.
    :param pod_selector: Selector to filter the pods.
    :return: List of pod statuses.
    """
    try:
        config.load_kube_config()
        core_v1 = client.CoreV1Api()
        pods = core_v1.list_namespaced_pod(namespace=namespace, label_selector=pod_selector)
        pod_statuses = [{'name': pod.metadata.name, 'status': pod.status.phase} for pod in pods.items]
        logger.info(f"Pod statuses: {pod_statuses}")
        return pod_statuses
    except ApiException as e:
        logger.error(f"API exception: {e}")
        print(f"Error: {e}")
    except Exception as e:
        logger.error(f"Failed to get pod status: {e}")
        print(f"Error: {e}")

def get_service_status(namespace, service_name):
    """
    Get the status of the specified service.
    
    :param namespace: Kubernetes namespace.
    :param service_name: Name of the service.
    :return: Service status as a dictionary.
    """
    try:
        config.load_kube_config()
        core_v1 = client.CoreV1Api()
        service = core_v1.read_namespaced_service(name=service_name, namespace=namespace)
        status = {
            'name': service.metadata.name,
            'type': service.spec.type,
            'cluster_ip': service.spec.cluster_ip,
            'external_ips': service.spec.external_ips,
            'ports': [{'port': port.port, 'target_port': port.target_port} for port in service.spec.ports]
        }
        logger.info(f"Service status: {status}")
        return status
    except ApiException as e:
        logger.error(f"API exception: {e}")
        print(f"Error: {e}")
    except Exception as e:
        logger.error(f"Failed to get service status: {e}")
        print(f"Error: {e}")

def get_deployment_status(deployment_name, namespace="default"):
    config.load_kube_config()
    # Create an API client for the apps/v1 API
    apps_v1 = client.AppsV1Api()

    try:
        # Get the deployment status
        deployment = apps_v1.read_namespaced_deployment_status(name=deployment_name, namespace=namespace)
        status = deployment.status
        print(f"Deployment '{deployment_name}' in namespace '{namespace}' has {status.available_replicas} available replicas out of {status.replicas} desired replicas.")
    except ApiException as e:
        print(f"Error fetching deployment status: {e}")
        
def main():
    """
    Main function to parse arguments and run the deployment automation script.
    """
    parser = argparse.ArgumentParser(description="Kubernetes Deployment Automation")
    parser.add_argument('--config-file', type=str, required=True, help="Path to the configuration JSON file.")
    parser.add_argument('--check-status', action='store_true', help="Check the status of the deployment after creation.")
    args = parser.parse_args()


    if args.config_file:
        config_data = load_config(args.config_file)
        if not config_data:
            return
        if not validate_config(config_data):
            return
        
        initialize_cluster()
        create_deployment(config_data)

    time.sleep(30)
    if args.check_status:
        deployment_name = input("Enter the deployment name: ")
        namespace = input("Enter the namespace: ")
        get_deployment_status(deployment_name, namespace)


if __name__ == "__main__":
    main()
