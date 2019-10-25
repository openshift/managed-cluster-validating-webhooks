def validate_request_structure(request_json):
  """Validate the request structure.
  """
  valid = True

  doc_keys = request_json.keys()

  valid = valid & ("request" in doc_keys)
  request_keys = request_json['request'].keys()
  valid = valid & ("kind" in request_keys)
  valid = valid & ("resource" in request_keys)
  valid = valid & ("operation" in request_keys)
  valid = valid & ("object" in request_keys)

  user_keys = request_json['request']['userInfo'].keys()
  valid = valid & ("username" in user_keys)
  valid = valid & ("groups" in user_keys  )
  valid = valid & (type(request_json['request']['userInfo']['groups']) is list)
  valid = valid & ("extra" in user_keys)

  object_keys = request_json['request']['object'].keys()
  valid = valid & ("metadata" in object_keys)
  valid = valid & ("users" in object_keys)

  metadata_keys = request_json['request']['object']['metadata'].keys()
  valid = valid & ("name" in metadata_keys)
  valid = valid & ("creationTimestamp" in metadata_keys)
  valid = valid & ("uid" in metadata_keys)

  resource_keys = request_json['request']['resource'].keys()
  valid = valid & ("group" in resource_keys)
  valid = valid & ("version" in resource_keys)
  valid = valid & ("resource" in resource_keys)

  kind_keys = request_json['request']['kind'].keys()
  valid = valid & ("group" in kind_keys)
  valid = valid & ("version" in kind_keys)
  valid = valid & ("kind" in kind_keys)

  return valid