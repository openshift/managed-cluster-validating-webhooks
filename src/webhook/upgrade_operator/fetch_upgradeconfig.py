import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Use KUBECONFIG from pod else consume from local ~/.kube/config
if 'KUBERNETES_PORT' in os.environ:
    config.load_incluster_config()
else:
    config.load_kube_config()


def get_upgradeconfig_cr():
    custom_api = client.CustomObjectsApi()
    try:
        ugpradeconfig_resource = custom_api.list_cluster_custom_object(
            'upgrade.managed.openshift.io', 'v1alpha1', 'upgradeconfigs')
        return ugpradeconfig_resource
    except ApiException as e:
        print(
            "Exception in fetching upgrade.managed.openshift.io/v1alpha1 resource: %s\n" % e)
