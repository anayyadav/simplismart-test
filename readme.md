# Kubernetes Deployment Automation Script

## Overview

This script automates the deployment process on a Kubernetes cluster. It includes functionalities for initializing the cluster, creating deployments, and retrieving health statuses. The script utilizes the Kubernetes Python client library.

## Prerequisites

Before running the script, ensure you have the following:

1. **Kubernetes Cluster**:
   - Access to a Kubernetes cluster.
   - A `kubeconfig` file with the necessary credentials and configuration to interact with the cluster.

2. **Python Environment**:
   - Python 3.6 or higher installed on your system.

3. **kubectl**:
   - `kubectl` should be installed and configured to interact with your Kubernetes cluster.
   - [Install kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

## Dependencies

The script requires the `kubernetes` Python library. Install the dependencies using `pip`:

```bash
pip install kubernetes
```


## Script Usage

To use the Kubernetes Deployment Automation Script, follow these steps:

1. **Save the Script**:
   - Save the provided Python script to a file named `deploy_k8s.py`.

2. **Create a Configuration File**:
   - Prepare a JSON configuration file with the necessary details. Save it as `config.json` (or another name of your choice).

3. **Run the Script**:
   - Open your terminal or command prompt.
   - Execute the script using Python with the path to your configuration file as an argument:

     ```bash
     python deploy_k8s.py --config-file /path/to/config.json --check-status
     ```

   - Replace `/path/to/config.json` with the actual path to your configuration file.
   - Enter the deployment name
   - Enter the namespace

4. **Monitor the Execution**:
   - The script will output logs and results to `deployment_script.log`. Check this log file for detailed information on the operations performed and to troubleshoot any issues that may arise.

5. **Verify Deployment**:
   - After the script completes, verify the deployment in your Kubernetes cluster using `kubectl` commands or the Kubernetes dashboard.

Example command:

```bash
python deploy_k8s.py --config-file config.json

## Error Handling

The script includes error handling mechanisms to manage potential issues during execution. Below are common errors you may encounter and their possible resolutions:

1. **Configuration File Issues**:
   - **Error**: Invalid JSON format or missing fields.
   - **Resolution**: Ensure the JSON configuration file is correctly formatted and includes all required fields. The script will log specific errors related to configuration file issues. Use a JSON validator to check the file's syntax.

2. **Kubernetes Cluster Connectivity**:
   - **Error**: Unable to connect to the Kubernetes cluster.
   - **Resolution**: Verify that your `kubeconfig` file is correctly configured and that you have access to the cluster. Check your network connectivity and cluster status.

3. **API Exceptions**:
   - **Error**: API request failures or exceptions.
   - **Resolution**: Review the `deployment_script.log` for detailed error messages. Ensure that your Kubernetes API server is reachable and that your user account has the necessary permissions to perform the requested actions.

4. **Deployment Creation Failures**:
   - **Error**: Errors during the creation of deployments, services, or other Kubernetes resources.
   - **Resolution**: Check the provided configuration details for correctness. Ensure that the image exists and is accessible, and that resource limits and requests are specified correctly. Verify that any specified node selectors or affinity rules are valid.

5. **Logging and Troubleshooting**:
   - **Resolution**: All operations and errors are logged to `deployment_script.log`. Review this log file to understand what went wrong and to get insights into potential issues. The log will provide detailed information on script execution and errors encountered.

By following these guidelines and checking the log files, you can diagnose and resolve issues that arise during script execution.
