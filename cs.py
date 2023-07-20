import subprocess
from kubernetes import client, config
from prometheus_client import start_http_server, Counter


# Load Kubernetes configuration
config.load_kube_config()

# Create Kubernetes API client
api_client = client.CoreV1Api()

# Prometheus metrics
vulnerabilities_found = Counter('vulnerabilities_found', 'Number of vulnerabilities found', ['image'])


def scan_container_images(namespace):
    # Get all pod names in the specified namespace
    pods = api_client.list_namespaced_pod(namespace)

    for pod in pods.items:
        # Get container images from pod
        container_images = [container.image for container in pod.spec.containers]

        # Scan each container image using Trivy
        for image in container_images:
            try:
                # Run Trivy scan command
                scan_command = ['trivy', 'image', image]
                scan_result = subprocess.run(scan_command, capture_output=True, text=True, check=True)

                # Process Trivy scan output
                vulnerabilities = scan_result.stdout.splitlines()
                for vulnerability in vulnerabilities:
                    vulnerabilities_found.labels(image=image).inc()
                    print(f"Image: {image}, Vulnerability: {vulnerability}")
            except subprocess.CalledProcessError as e:
                print(f"Error scanning image {image}: {e.stderr}")


if __name__ == '__main__':
    # Example usage: Scan container images in "default" namespace
    scan_container_images("default")

    # Start Prometheus metrics server on port 8000
    start_http_server(8000)
