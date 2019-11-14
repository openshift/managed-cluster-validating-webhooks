def validate_request_structure(request_json):
  """Validate the request structure.
  """

  doc_keys = request_json.keys()

  if 'kind' not in doc_keys:
    return False
  if request_json['kind'] == "AdmissionReview":
    return True
  return False