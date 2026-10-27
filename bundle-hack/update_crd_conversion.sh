#!/usr/bin/env bash
# Since 1.0.0 all CRDs are served in v1 and the previous API versions are
# converted by the conversion webhook (/convert) of the operator managed
# webhook deployment. The upstream bundle points the conversion webhook to the
# upstream namespace and relies on cert-manager to inject the CA bundle. On
# OpenShift the operator runs in openshift-security-profiles and the serving
# certificate is issued by the service CA operator, which is also able to
# inject its CA bundle into CRD conversion webhooks.
set -euo pipefail

NAMESPACE="openshift-security-profiles"

echo "Pointing the CRD conversion webhooks to the ${NAMESPACE} namespace"
for crd in ../bundle/manifests/security-profiles-operator.x-k8s.io_*.yaml; do
  # CA bundle injection via the OpenShift service CA operator instead of cert-manager.
  sed -i 's#cert-manager.io/inject-ca-from: security-profiles-operator/webhook-cert#service.beta.openshift.io/inject-cabundle: "true"#' "${crd}"
  # The webhook service lives in the downstream operator namespace.
  sed -i "s#^\(\s*\)namespace: security-profiles-operator\$#\1namespace: ${NAMESPACE}#" "${crd}"

  if grep -q "cert-manager.io" "${crd}"; then
    echo "cert-manager reference left in ${crd}" >&2
    exit 1
  fi
done
