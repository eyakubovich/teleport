---
title: Kubernetes Access Guide on GKE
description: How to set up and configure Teleport for Kubernetes access with SSO and RBAC on GKE
---

# Teleport Kubernetes Access on GKE

{!./docs/5.0/kubernetes-access/pitch.partial.md!}

### Prerequisites

* [Kubernetes](https://kubernetes.io) >= v1.14.0
* [Helm](https://helm.sh) >= v3.2.0

Verify that helm and kubernetes are installed and up to date.

```bash
$ helm version
version.BuildInfo{Version:"v3.4.2"}

$ kubectl version
Client Version: version.Info{Major:"1", Minor:"17+"}
Server Version: version.Info{Major:"1", Minor:"17+"}
```

### Install Teleport (Step 1 out of 3)

Let's start with a single-pod Teleport using persistent volume as a backend.

=== "Open Source"

    ```bash
    $ helm repo add teleport https://charts.releases.teleport.dev

    # Install a single node teleport cluster and provision a cert using ACME.
    # Set clusterName to unique hostname, for example teleport.example.com
    # Set acmeEmail to receive correspondence from Letsencrypt certificate authority.
    $ helm install teleport-cluster teleport-cluster --create-namespace --namespace=teleport-cluster \
    --set clusterName=${CLUSTER_NAME?} --set acme=true --set acmeEmail=${EMAIL?} \
    --set backend=gcs
    ```
    
=== "Enterprise"

    ```bash
    TBD
    ```
