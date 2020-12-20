## Teleport Kubernetes Service

By default, the Kubernetes integration is turned off in Teleport. The configuration
setting to enable the integration in the proxy service section in the `/etc/teleport.yaml`
config file, as shown below:

```yaml
# snippet from /etc/teleport.yaml on the Teleport proxy service:
kubernetes_service:
    enabled: yes
    public_addr: [k8s.example.com:3027]
    listen_addr: 0.0.0.0:3027
    kubeconfig_file: /secrets/kubeconfig
```
Let's take a closer look at the available Kubernetes settings:

- `public_addr` defines the publicly accessible address which Kubernetes API clients
  like `kubectl` will connect to. This address will be placed inside of kubeconfig on
  a client's machine when a client executes tsh login command to retrieve its certificate.
  If you intend to run multiple Teleport proxies behind a load balancer, this must
  be the load balancer's public address.

- `listen_addr` defines which network interface and port the Teleport proxy server
  should bind to. It defaults to port 3026 on all NICs.

## Setup

Connecting the Teleport proxy to Kubernetes.

Teleport Auth And Proxy can be ran anywhere (inside or outside of k8s). The Teleport
proxy must have `kube_listen_addr` set.

- Options for connecting k8s clusters:
    - `kubernetes_service` in a pod [Using our Helm Chart](https://github.com/gravitational/teleport/blob/master/examples/chart/teleport-kube-agent/README.md)
    - `kubernetes_service` elsewhere, with kubeconfig. Use [get-kubeconfig.sh](https://github.com/gravitational/teleport/blob/master/examples/k8s-auth/) for building kubeconfigs

There are two options for setting up Teleport to access Kubernetes:

### Option 1: Standalone Teleport "gateway" for multiple K8s Clusters

A single central Teleport Access Plane acting as "gateway". Multiple Kubernetes clusters
connect to it over reverse tunnels.

The root Teleport Cluster should be setup following our standard config, to make sure
clients can connect you must make sure that an invite token is set for the `kube`
service and proxy_addr has `kube_listen_addr` set.

```yaml
# Example Snippet for the Teleport Root Service
#...
auth_service:
  enabled: "yes"
  listen_addr: 0.0.0.0:3025
  tokens:
  - kube:866c6c114724a0fa4d4d73216afd99fb1a2d6bfde8e13a19
#...
proxy_service:
  public_addr: proxy.example.com:3080
  kube_listen_addr: 0.0.0.0:3027
```

To get quickly setup, we provide a Helm chart that'll connect to the above root cluster.

```bash
# Add Teleport Helm Repo
$ helm repo add teleport https://charts.releases.teleport.dev

# Installing the Helm Chart
helm install teleport-kube-agent teleport/teleport-kube-agent \
  --namespace teleport \
  --create-namespace \
  --set proxyAddr=proxy.example.com:3080 \
  --set authToken=$JOIN_TOKEN \
  --set kubeClusterName=$KUBERNETES_CLUSTER_NAME
```

| Things to set | Description |
|-|-|
| `proxyAddr` | The Address of the Teleport Root Service, using the proxy listening port |
| `authToken` | A static `kube` invite token |
| `kubeClusterName` | Kubernetes Cluster name (there is no easy way to automatically detect the name from the environment) |

### Option 2: Proxy running inside a k8s cluster.

Deploy Teleport Proxy service as a Kubernetes pod inside the Kubernetes cluster
you want the proxy to have access to.

```yaml
# snippet from /etc/teleport.yaml on the Teleport proxy service:
auth_service:
  cluster_name: example.com
  public_addr: auth.example.com:3025
# ..
proxy_service:
  public_addr: proxy.example.com:3080
  kube_listen_addr: 0.0.0.0:3026

kubernetes_service:
  enabled: yes
  listen_addr: 0.0.0.0:3027
  kube_cluster_name: kube.example.com
```

If you're using Helm, we provide a chart that you can use. Run these commands:

```bash
$ helm repo add teleport https://charts.releases.teleport.dev
$ helm install teleport teleport/teleport
```
You will still need a correctly configured `values.yaml` file for this to work. See
our [Helm Docs](https://github.com/gravitational/teleport/tree/master/examples/chart/teleport#introduction) for more information.

![teleport-kubernetes-inside](img/teleport-k8s-pod.svg)

