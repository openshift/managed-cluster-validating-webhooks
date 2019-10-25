#!/usr/bin/env python3

# Update the ValidatingWebhookConfiguration with the contents of the Service CA.

from kubernetes import client, config
import os
import argparse
import copy

parser = argparse.ArgumentParser(description="Options to Program")
parser.add_argument('-c', default="/service-ca/service-ca.crt", dest="servicecafile", help="Path to Service CA.crt")
#parser.add_argument('-c', default="/tmp/foo2.crt", dest="servicecafile", help="Path to Service CA.crt")
parser.add_argument('-m', default="sre-validate-webhook", dest='metadata_name', help='ValidatingWebhookConfiguration metadata name')
parser.add_argument('-M', default="validate.group.change", dest='webhook_name', help='Name of the webhook in the .webhooks[] list')
parsed = parser.parse_args()

config.load_incluster_config()
client = client.AdmissionregistrationV1beta1Api()


def get_cert(cacertfile):
  return open(cacertfile,"r").read()

def trim_cert(certdata):
  return certdata.replace("-----BEGIN CERTIFICATE-----\n","").replace("-----END CERTIFICATE-----\n","").replace("\n","")

def get_namespace():
  return open('/var/run/secrets/kubernetes.io/serviceaccount/namespace').read()

def get_validating_webhook_configuration_object(client, webhookcfgname):
  return client.read_validating_webhook_configuration(name=webhookcfgname)

namespace = get_namespace()
cert = trim_cert(get_cert(parsed.servicecafile))
#patch = create_patch(get_validating_webhook_configuration_object(client, parsed.metadata_name), parsed.webhook_name, b64cert.decode())
obj = get_validating_webhook_configuration_object(client, parsed.metadata_name)

patchedobj = copy.deepcopy(obj)
for hook in patchedobj.webhooks:
  if hook.name == parsed.webhook_name:
    hook.client_config.ca_bundle = cert

patchResult = client.patch_validating_webhook_configuration(name=patchedobj.metadata.name,body=patchedobj)
