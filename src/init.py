#!/usr/bin/env python3

# Update the ValidatingWebhookConfiguration with the contents of the Service CA.

from kubernetes import client, config
import os
import argparse
import copy
import base64

parser = argparse.ArgumentParser(description="Options to Program")
parser.add_argument('-a', default="managed.openshift.io/inject-cabundle-from", dest='annotation_name', help='What is the annotation that has a reference to a namespace/configmap for the caBundle. The cert must be stored in pem format in a key called service-ca.crt')
parsed = parser.parse_args()

config.load_incluster_config()
admission_client = client.AdmissionregistrationV1beta1Api()
cm_client = client.CoreV1Api()


def get_cert_from_configmap(client, namespace, configmap_name, key="service-ca.crt"):
  try:
    o = client.read_namespaced_config_map(configmap_name, namespace)
    if key in o.data:
      return o.data[key].rstrip()
  except:
    return None
  return None


def encode_cert(cert):
  return base64.b64encode(cert.encode("UTF-8")).decode("UTF-8")


def get_validating_webhook_configuration_objects_with_annotation(client, annotation):
  ret = []
  for o in client.list_validating_webhook_configuration().items:
    if o.metadata.annotations is not None and annotation in o.metadata.annotations:
      ret.append(o)
  return ret


for vwc in get_validating_webhook_configuration_objects_with_annotation(admission_client, parsed.annotation_name):
  ns, cm_name = vwc.metadata.annotations[parsed.annotation_name].split('/')
  cert = get_cert_from_configmap(cm_client, ns, cm_name)
  if cert is None:
    print("WARNING: Skipping validatingwebhookconfiguration/{}: Couldn't find a cert from {}/{} ConfigMap. \n".format(vwc.metadata.name, ns, cm_name))
    continue
  encoded_cert = encode_cert(cert)
  new_vwc = copy.deepcopy(vwc)
  for hook in new_vwc.webhooks:
    if hook.client_config.service is not None and hook.client_config.ca_bundle is not encoded_cert:
      hook.client_config.ca_bundle = encoded_cert
      print("validatingwebhookconfiguration/{}: Injecting caBundle from {}/{}, for hook name {}, to service/{}/{}\n".format(new_vwc.metadata.name, ns, cm_name, hook.name, hook.client_config.service.namespace, hook.client_config.service.name))
  try:
    result = admission_client.patch_validating_webhook_configuration(name=new_vwc.metadata.name, body=new_vwc)
  except Exception as err:
    print("ERROR: Couldn't save validatingwebhookconfiguration/{}: {}\n", new_vwc.metadata.name, err)
    os.exit(1)
