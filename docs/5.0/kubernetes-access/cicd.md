---
title: Teleport Kubernetes Access for CI/CD
description: Short Lived Certs CI/CD systems to Kubernetes RBAC with Teleport
---

# Short Lived Certs for CI/CD and Kubernetes

CI/CD tools like Jenkins can use short-lived certificates to talk to Kubernetes
API.

Non interactive local Teleport user, then exporting

```yaml
kind: role
version: v3
metadata:
  name: robot
spec:
  # allow section declares a list of resource/verb combinations that are
  # allowed for the users of this role. by default nothing is allowed.
  allow:
    logins: ['keep any value here']
    # a list of kubernetes groups to assign
    kubernetes_groups: ['system:masters']
---
kind: user
version: v3
metadata:
  name: jenkins
spec:
  roles:
  - robot
```

a kubeconfig using [`tctl auth sign`](cli-docs.md#tctl-auth-sign)

```bash
# Create a new local user for Jenkins
$ tctl users add jenkins
# Creates a token for 25hrs
$ tctl auth sign --user=jenkins --format=kubernetes --out=kubeconfig --ttl=25h

  The credentials have been written to kubeconfig

$ cat kubeconfig
  apiVersion: v1
  clusters:
  - cluster:
      certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZ....
# This kubeconfig can now be exported and will provide access to the automation tooling.

# Uses kubectl to get pods, using the provided kubeconfig.
$ kubectl --kubeconfig /path/to/kubeconfig get pods
```

!!! tip "Use short lived certificates"

    Short lived certificates expire in hours or minutes. You don't have to revoke
    them if the host gets compromised.
    Generate a new kubeconfig every hour using `tctl` or [API](../api-reference.md)
    and publish it to secrets storage, like [AWS](https://aws.amazon.com/secrets-manager/) or
    [GCP](https://cloud.google.com/secret-manager) secrets managers.
