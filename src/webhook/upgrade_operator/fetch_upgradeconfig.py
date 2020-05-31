from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config.config_exception import ConfigException


def kube_auth():
    # Use ~/.kube/config for authentication if script run directly
    if __name__ == "__main__":
        try:
            config.load_kube_config()
            return True
        except ConfigException as c:
            print("ConfigException in load_kube_config() : %s\n" % c)
            return False

    # Use serviceaccount token to authenticate.
    else:
        try:
            config.load_incluster_config()
            return True
        except ConfigException as c:
            print("ConfigException in load_incluster_config() : %s\n" % c)
            return False


def get_upgradeconfig_cr():
    if kube_auth():
        custom_api = client.CustomObjectsApi()
        try:
            ugpradeconfig_resource = custom_api.list_cluster_custom_object(
                'upgrade.managed.openshift.io', 'v1alpha1', 'upgradeconfigs')
            return ugpradeconfig_resource
        except ApiException as e:
            print(
                "Exception in fetching upgrade.managed.openshift.io/v1alpha1 resource: %s\n" % e)
            return None


if __name__ == "__main__":
    get_upgradeconfig_cr()
