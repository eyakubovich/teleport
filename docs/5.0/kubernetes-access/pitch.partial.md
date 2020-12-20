Teleport provides a unified access plane for Kubernetes clusters.

* Users can login once using SSO and switch between clusters without relogins.
* Admins can use roles to implement policies like `developers must not access production` and require
dual authorization using [access workflows](./enteprise/workflow.md).
* Achieve compliance by capturing `kubectl` events and session recordings for `kubectl exec`.

## SSO and Audit in 3 steps

Set up single sign on, capture audit events and sessions with Teleport
running in a Kubernetes cluster.

<video muted playsinline controls>
  <source src="/img/videos/kubernetes-access/kubelogin.mp4" type="video/mp4" />
  <source src="/img/videos/kubernetes-access/kubelogin.webm" type="video/webm" />
Your browser does not support the video tag.
</video>
