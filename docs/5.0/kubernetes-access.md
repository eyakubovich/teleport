---
title: Getting Started with Kubernetes Access
description: How to set up and configure Teleport for Kubernetes access with SSO and RBAC
---

# Teleport Kubernetes Access

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
      --set clusterName=${CLUSTER_NAME?} --set acme=true --set acmeEmail=${EMAIL?}
    ```
    
=== "Enterprise"

    ```bash
    $ helm repo add teleport https://charts.releases.teleport.dev

    # Create a namespace for a deployment.
    $ kubectl create namespace teleport-cluster-ent

    # Get a license from Teleport and create a secret "license" in the namespace teleport-cluster-ent
    $ kubectl -n teleport-cluster-ent create secret generic license --from-file=license-enterprise.pem

    # Install Teleport
    $ helm install teleport-cluster-ent teleport-cluster --namespace=teleport-cluster-ent \
      --set clusterName=${CLUSTER_NAME?} --set acme=true --set acmeEmail=${EMAIL?} --set enterprise=true
    ```

Teleport's helm chart uses [external load balancer](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/)
to create public IP for Teleport.

=== "Open Source"

    ```bash
    # Set kubectl context to the namespace to set some typing
    $ kubectl config set-context --current --namespace=teleport-cluster
    
    # Service is up, load balancer is created
    $ kubectl get services
    NAME               TYPE           CLUSTER-IP   EXTERNAL-IP      PORT(S)                        AGE
    teleport-cluster   LoadBalancer   10.4.4.73    104.199.126.88   443:31204/TCP,3026:32690/TCP   89s
    
    # Save the pod IP. If the IP is not available, check the pod and load balancer status.
    $ MYIP=$(kubectl get services teleport-cluster -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    $ echo $MYIP
    192.168.2.1
    ```
        
=== "Enterprise"

    ```bash
    # Set kubectl context to the namespace to set some typing
    $ kubectl config set-context --current --namespace=teleport-cluster-ent
    
    # Service is up, load balancer is created
    $ kubectl get services
    NAME                   TYPE           CLUSTER-IP   EXTERNAL-IP      PORT(S)                        AGE
    teleport-cluster-ent   LoadBalancer   10.4.4.73    104.199.126.88   443:31204/TCP,3026:32690/TCP   89s
    
    # Save the pod IP. If the IP is not available, check the pod and load balancer status.
    $ MYIP=$(kubectl get services teleport-cluster-ent -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    $ echo $MYIP
    192.168.2.1
    ```

Set up two `A` DNS records - `tele.example.com` for UI and `*.tele.example.com`
for web apps using [application access](./application-access.md).

=== "Google DNS"

    ```bash
    $ MYZONE="myzone"
    $ MYDNS="tele.example.com"
    
    $ gcloud dns record-sets transaction start --zone="${MYZONE?}"
    $ gcloud dns record-sets transaction add ${MYIP?} --name="${MYDNS?}" --ttl="30" --type="A" --zone="${MYZONE?}"
    $ gcloud dns record-sets transaction add ${MYIP?} --name="*.${MYDNS?}" --ttl="30" --type="A" --zone="${MYZONE?}"
    $ gcloud dns record-sets transaction describe --zone="${MYZONE?}"
    $ gcloud dns record-sets transaction execute --zone="${MYZONE?}"
    ```

=== "AWS Route 53"

    ```bash
    # Tip for finding AWS zone id by the domain name.
    $ MYZONE_DNS="example.com"
    $ MYZONE=$(aws route53 list-hosted-zones-by-name --dns-name=${MYZONE_DNS?} | jq -r '.HostedZones[0].Id' | sed s_/hostedzone/__)

    $ MYDNS="tele.example.com"
    
    # Create a JSON file changeset for AWS.
    $ jq -n --arg ip ${MYIP?} --arg dns ${MYDNS?} '{"Comment": "Create records", "Changes": [
      {"Action": "CREATE", "ResourceRecordSet": {"Name": $dns, "Type": "A", "TTL": 300, "ResourceRecords": [{ "Value": $ip}]}},
      {"Action": "CREATE", "ResourceRecordSet": {"Name": ("*." + $dns), "Type": "A", "TTL": 300, "ResourceRecords": [{ "Value": $ip}]}}
      ]}' > myrecords.json

    # Review records before applying.
    $ cat myrecords.json | jq
    # Apply the records and capture change id
    $ CHANGEID=$(aws route53 change-resource-record-sets --hosted-zone-id ${MYZONE?} --change-batch file://myrecords.json | jq -r '.ChangeInfo.Id')

    # Verify that change has been applied
    $ aws route53 get-change --id ${CHANGEID?} | jq '.ChangeInfo.Status'
    "INSYNC"
    ```

The first request to Teleport's API will take a bit longer because it gets
a cert from [Letsencrypt](https://letsencrypt.org).
Teleport will respond back with a discovery info:

```bash
$ curl https://tele.example.com/webapi/ping

{"server_version":"5.0.0-dev","min_client_version":"3.0.0"}
```

### Create a local admin (Step 2 out of 3)

Local users are reliable fallback for cases when SSO provider is down.
Let's create a local admin `alice` who has access to Kubernetes group `system:masters`.

=== "Open Source"

    ```bash
    # To create a local user, we are going to run Teleport's admin tool tctl from the pod.
    $ POD=$(kubectl get po -l app=teleport-cluster -o jsonpath='{.items[0].metadata.name}')

    # Generate an invite link for the user.
    $ kubectl exec -ti ${POD?} tctl -- users add alice --k8s-groups="system:masters"
    
    User "alice" has been created but requires a password. Share this URL with the user to complete user setup, link is valid for 1h:
    https://tele.example.com:443/web/invite/random-token-id-goes-here
    
    NOTE: Make sure tele.example.com:443 points at a Teleport proxy which users can access.
    ```

=== "Enterprise"

    ```bash
    # To create a local user, we are going to run Teleport's admin tool tctl from the pod.
    $ POD=$(kubectl get po -l app=teleport-cluster-ent -o jsonpath='{.items[0].metadata.name}')

    # Generate an invite link for the user.
    $ kubectl exec -ti ${POD?} tctl -- users add alice --k8s-groups="system:masters"
    
    User "alice" has been created but requires a password. Share this URL with the user to complete user setup, link is valid for 1h:
    https://tele.example.com:443/web/invite/random-token-id-goes-here
    
    NOTE: Make sure tele.example.com:443 points at a Teleport proxy which users can access.
    ```

Let's install `tsh` and `tctl` on Linux.
For other install options, check out [install guide](./installation.md)

=== "Open Source"

    ```bash
    $ curl -L -O https://get.gravitational.com/teleport-v{{ teleport.version }}-linux-amd64-bin.tar.gz
    $ tar -xzf teleport-v{{ teleport.version }}-linux-amd64-bin.tar.gz
    $ sudo mv teleport/tsh /usr/local/bin/tsh
    $ sudo mv teleport/tctl /usr/local/bin/tctl
    ```

=== "Enterprise"

    ```bash
    $ curl -L -O https://get.gravitational.com/teleport-ent-v{{ teleport.version }}-linux-amd64-bin.tar.gz
    $ tar -xzf teleport-ent-v{{ teleport.version }}-linux-amd64-bin.tar.gz
    $ sudo mv teleport/tsh /usr/local/bin/tsh
    $ sudo mv teleport/tctl /usr/local/bin/tctl
    ```

Try `tsh login` with a local user. Use a custom `KUBECONFIG` to prevent override
of the default one in case if there is a problem.

```bash
$ KUBECONFIG=${HOME?}/teleport.yaml tsh login --proxy=tele.example.com:443 --user=alice
```

Teleport updated `KUBECONFIG` with a short-lived 12 hour certificate.

```bash
$ tsh kube ls

Kube Cluster Name Selected
----------------- --------
tele.example.com  *

# Once working, remove the KUBECONFIG= override to switch to teleport
$ KUBECONFIG=${HOME?}/teleport.yaml kubectl get -n teleport-cluster pods
NAME                                READY   STATUS    RESTARTS   AGE
teleport-cluster-6c9b88fd8f-glmhf   1/1     Running   0          127m
```

### SSO for Kubernetes (step 3 out of 3)

We are going to setup Github connector for OSS and Okta for Enterpise version.

=== "Open Source"
    Save the file below as `github.yaml` and update the fields. You will need to set up
    [Github OAuth 2.0 Connector](https://developer.github.com/apps/building-oauth-apps/creating-an-oauth-app/) app.
    Any member with the team `admin` in the organization `octocats` will be able to login
    as a Kubernetes group `system:masters`:

    ```yaml
    kind: github
    version: v3
    metadata:
      # connector name that will be used with `tsh --auth=github login`
      name: github
    spec:
      # client ID of Github OAuth app
      client_id: client-id
      # client secret of Github OAuth app
      client_secret: client-secret
      # This name will be shown on UI login screen
      display: Github
      # Change tele.example.com to your domain name
      redirect_url: https://tele.example.com:443/v1/webapi/github/callback
      # Map github teams to kubernetes groups
      teams_to_logins:
        - organization: octocats # Github organization name
          team: admin           # Github team name within that organization
          # list of Kubernetes groups this Github team is allowed to connect to
          kubernetes_groups: ["system:masters"]
          # keep this field as is for now
          logins: ["{% raw %}{{external.username}}{% endraw %}"]
    ```

=== "Enterprise"
    Follow [SAML Okta Guide](./enterprise/sso/ssh-okta.md#configure-okta) to create a SAML app.
    Check out [OIDC guides](./enterprise/sso/oidc.md#identity-providers) for OpenID Connect apps.
    Save the file below as `okta.yaml` and update the `acs` field.
    Any member in Okta group `okta-admin` will assume a builtin role `admin`.
    ```yaml
    kind: saml
    version: v2
    metadata:
      name: okta
    spec:
      acs: https://tele.example.com/v1/webapi/saml/acs
      attributes_to_roles:
      - {name: "groups", value: "okta-admin", roles: ["admin"]}
      entity_descriptor: |
        <?xml !!! Make sure to shift all lines in XML descriptor 
        with 4 spaces, otherwise things will not work
    ```

To create a connector, we are going to run Teleport's admin tool `tctl` from the pod.

=== "Open Source"

    ```bash
    # To create a Github connector, we are going to run Teleport's admin tool tctl from the pod.
    $ POD=$(kubectl get po -l app=teleport-cluster -o jsonpath='{.items[0].metadata.name}')

    $ kubectl exec -i ${POD?} tctl -- create -f < github.yaml
    authentication connector "github" has been created
    ```

=== "Enterprise"

    ```bash
    # To create an Okta connector, we are going to run Teleport's admin tool tctl from the pod.
    $ POD=$(kubectl get po -l app=teleport-cluster-ent -o jsonpath='{.items[0].metadata.name}')

    $ kubectl exec -i ${POD?} tctl -- create -f < okta.yaml
    authentication connector 'okta' has been created
    ```

Try `tsh login` with Github user. I am using a custom `KUBECONFIG` to prevent override
of the default one in case if there is a problem on the first try.

=== "Open Source"

    ```bash
    $ KUBECONFIG=${HOME?}/teleport.yaml tsh login --proxy=tele.example.com:443 --auth=github
    ```

=== "Enterprise"

    ```bash
    $ KUBECONFIG=${HOME?}/teleport.yaml tsh login --proxy=tele.example.com:443 --auth=okta
    ```

!!! warning

    If you are getting the login error like the one below, take a look at the audit log for details:

    ```bash
    kubectl exec -ti "${POD?}" -- tail -n 100 /var/lib/teleport/log/events.log

    {"error":"user \"alice\" does not belong to any teams configured in \"github\" connector","method":"github","attributes":{"octocats":["devs"]}}
    ```

![SSO Fail](../img/k8s/ssofail.png)

## Multiple Kubernetes Clusters

Teleport can act as unified access plane for multiple Kubernetes clusters.
We have set up Teleport cluster `tele.example.com` in [SSO and Kubernetes](#sso-and-audit-for-kubernetes-in-3-steps).

Let's start a lightweight agent in another Kubernetes cluster `cookie` and connect it to `tele.example.com`.
We would need a join token from `tele.example.com`:

=== "Open Source"

    ```bash
    # A trick to save the pod ID in tele.example.com
    $ POD=$(kubectl get po -l app=teleport-cluster -o jsonpath='{.items[0].metadata.name}')
    # Create a join token for the cluster cookie to authenticate
    $ TOKEN=$(kubectl exec -ti "${POD?}" -- tctl nodes add --roles=kube --ttl=10000h --format=json | jq -r '.[0]')
    echo $TOKEN
    ```
    
=== "Enterprise"

    ```bash
    # A trick to save the pod ID in tele.example.com
    $ POD=$(kubectl get po -l app=teleport-cluster-ent -o jsonpath='{.items[0].metadata.name}')
    # Create a join token for the cluster cookie to authenticate
    $ TOKEN=$(kubectl exec -ti "${POD?}" -- tctl nodes add --roles=kube --ttl=10000h --format=json | jq -r '.[0]')
    echo $TOKEN
    ```

Switch `kubectl` to the Kubernetes cluster `cookie` and run:

=== "Open Source"

    ```bash
    # Add teleport chart repository
    $ helm repo add teleport https://charts.releases.teleport.dev
    
    # Install Kubernetes agent. It dials back to the Teleport cluster tele.example.com.
    $ CLUSTER='cookie'
    $ PROXY='tele.example.com:443'
    $ helm install teleport-agent teleport-kube-agent --set kubeClusterName={CLUSTER?}\
        --set proxyAddr=${PROXY?} --set authToken=${TOKEN?} --create-namespace --namespace=teleport-agent
    ```

=== "Enterprise"

    ```bash
    $ helm repo add teleport https://charts.releases.teleport.dev
    
    # Install Kubernetes agent. It dials back to the Teleport cluster tele.example.com.
    $ CLUSTER='peanut'
    $ PROXY='tele.example.com:443'
    $ helm install teleport-agent teleport-kube-agent --set kubeClusterName={CLUSTER?}\
        --set proxyAddr=${PROXY?} --set authToken=${TOKEN?} --create-namespace --namespace=teleport-agent-ent
    ```

List connected clusters using `tsh kube ls` and switch between
them using `tsh kube login`:

```bash
$ tsh kube ls
Kube Cluster Name Selected 
----------------- -------- 
cookie
tele.example.com    *

# Kubeconfig now points to cookie cluster
$ tsh kube login cookie
Logged into kubernetes cluster "cookie"

# Kubectl comamnd executed on `cookie`, but is routed through `tele.example.com` cluster.
$ kubectl get pods
```

## Next Steps

Get to production with these guides:

* [Kubernetes Authentication and Authorization guide](./kubernetes-access/auth.md).
* [CI/CD guide](./kubernetes-access/cicd.md). 
* [Migrating to Kubernetes Access from versions before Teleport 5.0](./kubernetes-5.0-migration.md).
* [Kubernetes Access and Trusted clusters](./kubernetes-access/trustedclusters.md)
