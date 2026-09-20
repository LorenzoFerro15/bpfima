# BPFIMA Integration in Kubernetes
This file describes how the BPFIMA deployment works in Kubernetes and how it can be installed, managed and uninstalled on a cluster.

## Overview
The BPFIMA integration in Kubernetes is based on a Pod deployed on each Node as soon as it joins the cluster. This Pod allows installing and configuring BPFIMA in the cluster in a **declarative** and **centralized** way, issuing commands directly from the control plane. The architecture is designed to be highly **portable** and is supported on major Linux distributions (Fedora, Ubuntu, and Debian). The deployment is entirely **architecture-agnostic**, seamlessly supporting both x86_64 and ARM64 systems without requiring manual reconfiguration by the end user. This is achieved thanks to the multi-platform build of the custom Docker image, packaging the BFPIMA code and core dependencies ([Dockerfile](../Dockerfile)).

### The DaemonSet
The BPFIMA Pod is deployed in the cluster through a **DaemonSet**, which automatically provisions a replica of the Pod on each Node. It includes two init containers to prepare the environment, and two core containers.

The goal of the **first init container** is to compile and insert the BPFIMA kernel module, that will expose the *securityfs* interface. To this end, it executes the [build_kernel_module.sh](../scripts/init/build_kernel_module.sh) script, which performs the following operations:
1. It checks if the BPFIMA kernel module is already loaded, comparing the loaded version against the source code version provisioned in the docker image. If they match, it bypasses the build process, preserving the active hardware-anchored logs.
2. If compilation is necessary, the script verifies if the kernel headers and debug information packages are already installed on the system.
3. If not, it uses `nsenter` to break out of the container's namespace and execute helper scripts ([install_kernel_devel.sh](../scripts/init/install_kernel_devel.sh) and [install_debug_info.sh](../scripts/init/install_debug_info.sh)) directly on the host OS. These scripts dynamically determine the host kernel release and version and fetch the required dependencies.
4. Once compiled against the host headers, the script uses `insmod` to load the module into the kernel, passing the target TPM PCR index.

The **second init container** compiles the eBPF hooks and `bpfima-tool`, depositing them into a shared `emptyDir` volume.

Then, the Pod transitions to its persistent runtime state by launching two core containers. The **`bpfima-tool` container** acts as the low-level enforcer. It retrieves the compiled eBPF object files from the shared volume and executes `bpfima-tool` to load them into the kernel, pinning the maps and programs to the `/sys/fs/bpf` filesystem. It finally enters an infinite sleep loop to keep the container alive. In case of Pod restart or rollback, the eBPF programs are recompiled and atomically switched to allow for updates without introducing any monitoring blind spot.

The **second core container** executes the Go-based operator, which is in charge of dynamically updating the BPFIMA configuration through policies.

```
(1) First init container
+-------------------------------------------------------------+
|                          [User space]                       |
|         (Root)                                              |
|  +--------------------+                                     |
|  |  Init container 1  |                                     |
|  |   Kernel Module    |---------+                           |
|  |   Initialisation   |         | compile                   |
|  +--------------------+         | and insert                |
|      ^                          |                           |
|      | retrieve                 |    +------------+         |
|  +----------------+             |    | securityfs |         |
|  | Kernel Headers |             |    +------------+         |
|  | Debug Symbols  |             |        ^ expose           |
|  +----------------+             |        |                  |
|- - - - - - - - - - - - - - - - -|- - - - | - - - - - - - - -|
|                 [Kernel space]  v        |                  |
|                            +---------------+                |
|                            | Kernel Module |                |
|                            +---------------+                |
+-------------------------------------------------------------+

(2) Second init container
+-------------------------------------------------------------+
|                          [User space]                       |
|  +--------------------+                                     |
|  |  Init container 2  |                                     |
|  |   eBPF and User    |                                     |
|  | Space Progs Comp.  |                                     |
|  +--------------------+                                     |
|      |                                                      |
|      | compile            +------------+                    |
|      v and store          | securityfs |<---+               |
|   .---------.             +------------+    |               |
|  | Compiled  |                              | expose        |
|  | Artifacts |                              |               |
|   '---------'                               |               |
|- - - - - - - - - - - - - - - - - - - - - - -|- - - - - - - -|
|                         [Kernel space]      |               |
|                            +---------------+                |
|                            | Kernel Module |                |
|                            +---------------+                |
+-------------------------------------------------------------+

(3) Runtime containers
+-------------------------------------------------------------+
|                          [User space]                       |
|  +---------------+                  +---------------+       |
|  |  Container 1  |                  |  Container 2  |       |
|  |  bpfima-tool  |                  |  Controller   |       |
|  +---------------+                  +---------------+       |
|      ^       |  |                     |    |                |
|  get |       |  |                     |    | record         |
|      |       |  | pin                 |    | policy         |
|      v       |  +-----+               |    | change         |
|  .-------.   |        |               |    v                |
| |Compiled |  |        |      update   |  +----------+       |
| |Artifacts|  |        |  +------------+  |securityfs|       |
|  '-------'   |        |  |               +----------+       |
|              | load   |  |                   ^              |
|- - - - - - - | - - - -| -|- - - - - - - - - -|- - -  - - - -|
|              v        v  v [Kernel space]    | expose       |
|      +-----------+   +-----------+  +---------------+       |
|      |   eBPF    |   | eBPF Maps |  | Kernel Module |       |
|      | Programs  |   +-----------+  +---------------+       |
|      +-----------+                                          |
+-------------------------------------------------------------+
```

### The custom operator
The BPFIMA custom operator, scaffolded with [Kubebuilder](https://book.kubebuilder.io), is the orchestration engine that bridges the declarative Kubernetes API with the eBPF maps in the Linux kernel.

The Kubernetes API has been extended with a new type of resource, called **Policy**, by using a Custom Resource Definition (**CRD**). Users can configure the BPFIMA measuring scope creating new Policy Custom Resources (CRs). Specifically, they can codify the system's security rules into version-controllable YAML manifests and submit them using `kubectl`, identical to how they manage standard Pods or Deployments. Policies can target a specific set of nodes or the whole cluster. These resources allow defining:
- Selector: an optional Kubernetes label selector that dictates which nodes the policy should be applied to.
- Policy: encapsulates the core behaviour, including the activation switch, minimum size of files to track, maximum directory path depth, and desired logging verbosity.
- Filters and actions: configuration blocks that define which system events to ignore and how to handle captured events.
- Patterns: arrays that allow targeted evaluation of specific paths or cgroups.
- Hooks: specific options for the loaded eBPF probes, enabling administrators to selectively activate or deactivate specific LSM hooks based on the environment's security requirements.

The CRD leverages Kubernetes OpenAPI schema validation to enforce strict structural typing and bounds checking.
If a submitted manifest lacks mandatory fields or contains invalid values, the Kubernetes API Server immediately rejects the payload, ensuring that malformed configurations cannot compromise the host's security posture.

The BPFIMA **custom controller** monitors the creation, update or deletion of Policy CRs along with Node Labels updates. These events trigger the reconciliation loop, in which the controller performs the following operations:
- It evaluates the list of active Policy resources to select the single most appropriate configuration for the specific node on which it resides.
- It parses the selected CR and writes the new specifications directly into the target eBPF maps to dynamically update the kernel's enforcement engine.
- It triggers the N-ary Merkle tree extension with the cryptographic hash of the newly applied policy and anchors the configuration shift into the hardware TPM.

To resolve configuration conflicts when multiple CRs are deployed, the controller implements a deterministic selection algorithm, guaranteeing the idempotency of the reconciliation loop.
To achieve this, the framework enforces a strict hierarchical precedence:
- **Targeted Policies:** the controller first evaluates policies containing a node selector. If a policy's selector matches the local node's labels, it is chosen. If multiple targeted policies match the same node, the system selects the policy with the most recent creation timestamp. If a secondary tie-breaker is required, it chooses the first policy alphabetically by resource name.
- **Cluster-wide Policies:** if the local node possesses no labels, or if no targeted policies match, the controller falls back to evaluating global policies, which are those omitting a selector. It applies the same deterministic logic, selecting the most recently created cluster-wide policy, using the alphabetical tie-breaker if necessary.
- **Fallback Baseline:** if no valid Policy resources exist within the cluster, the controller safely applies the default hardcoded baseline configuration.

The custom controller requires explicit authorization to interact with the Kubernetes API server to monitor and reconcile the cluster state defined through the Kubernetes **Role-Based Access Control** (RBAC). These permissions are configured via a ClusterRole, granting the operator read-only access to the Node resources (to watch for label modifications) and to the Policy resources. The ClusterRole is bound to the controller's ServiceAccount (defining its identity) via the ClusterRoleBinding.


### The Helm Chart
To simplify the provisioning of the framework across a cluster, all resources are bundled inside a **[Helm Chart](https://helm.sh)**. Helm operates as the official package manager for Kubernetes, abstracting YAML manifests into reusable, version-controlled templates. Helm translates the chart into Kubernetes resources, deploying all the bundled manifests with a single command (`helm install`). The BPFIMA installation provisions the following core components:
- **CRD:** extends the Kubernetes API to recognize the Policy objects used to declare integrity rules.
- **DaemonSet:** ensures that the BPFIMA orchestration agents (init scripts, bpfima-tool and Go controller) are scheduled and run on every eligible node.
- **RBAC:** provisions the ServiceAccount, ClusterRole and ClusterRoleBinding necessary to grant the custom controller the privileges required to monitor the cluster state.

The following schema summarizes the different components and their interactions.

```
[HELM]
 +--------------------+   +-------------------------------------------------+   +------------------------+
 |     Policy CRD     |   |                       Node       [USER] [Labels]|   |        RBAC for        |
 +--------------------+   |  [HELM]                                 /       |   |    Custom Controller   |
 | - General settings |   | +--------------------------------------/------+ |   |                        |
 | - Filtering flags  |   | |                 BPFIMA Pod          /watches| |   |                        |
 | - Action flags     |   | |                                    /        | |   |  [HELM]                |
 | - Exclusion pttrns |   | | +-------------+  +-------------------+      | |   |  +--------------------+|
 | - Per hook config  |   | | | bpfima-tool |  | Custom Controller | <----|-|---|--|   ServiceAccount   ||
 | - Node selector    |   | | +-------------+  +-------------------+      | |   |  +--------------------+|
 +--------------------+   | +---------------------|-----|-----------------+ |   |             |          |
           |         +----------------------------+     | Updates           |   | [HELM]      v          |
    Defines schema   |    | +---------------------------|-----------------+ |   | +--------------------+ |
           |         |    | |      Kernel Space         v                 | |   | | ClusterRoleBinding | |
           |      Watches | |                     +-----------+           | |   | +--------------------+ |
           |         |    | | +---------------+   | eBPF Maps |           | |   |             ^          |
           |         |    | | | eBPF Programs |   +-----------+           | |   | [HELM]      |          |
  [USER]   v         v    | | +---------------+                           | |   | +--------------------+ |
 +--------------------+   | |                     +---------------+       | |   | |    ClusterRole     | |
 |     Policy CR      |<----|                     | Kernel Module |       | |   | +--------------------+ |
 +--------------------+   | |                     +---------------+       | |   +------------------------+
                          | +---------------------------------------------+ |
                          +-------------------------------------------------+

```
Helm also allows seamlessly managing frameworks **updates** and **uninstallation**. Specifically, the architecture incorporates an automated multiphase tear-down protocol triggered during the uninstallation phase leveraging Helm hooks (`post-uninstall` hook). This routine eliminates the instantiated Kubernetes resources for BPFIMA, explicitly removes the CRD, releases the host kernel modules and pinned eBPF resources structures.

## User Manual
### Installation
To install the framework, a functioning Kubernetes cluster is required; for testing purposes, a lightweight solution like [K3s](https://k3s.io) is sufficient. To deploy the Helm chart, you also need to install Helm, following the [official documentation](https://helm.sh/it/docs/intro/install/). Both the Helm chart and the associated Docker image are hosted on [Docker Hub](https://hub.docker.com/r/iochia02/bpfima).

To install the framework on a cluster there are three main ways. The recommended option is:

```bash
helm install <release_name> oci://registry-1.docker.io/iochia02/bpfima \
    --version <chart_version> \
    --namespace <target_namespace> \
    --create-namespace
```
Otherwise, the chart can be first downloaded and then installed:
```bash
helm pull oci://registry-1.docker.io/iochia02/bpfima --version <chart_version>
helm install <release_name> <downloaded.tgz> \
    --namespace <target_namespace> \
    --create-namespace
```
Finally, it can be installed directly from source:
```bash
# Clone repository
git clone https://github.com/lorenzoferro15/bpfima.git
# Move to bpfima folder
cd bpfima
# Install chart
helm install <release_name> ./install/kubernetes/bpfima \
    --namespace <target_namespace>  \
    --create-namespace
```

The correct deployment of all the expected resources can be verified via the following commands:
```bash
# Verify CRD registration
kubectl get crd policies.bpfima.polito.it
# Verify RBAC deployment
kubectl get ServiceAccount bpfima -n <target_namespace>
kubectl get ClusterRole bpfima
kubectl get ClusterRoleBinding bpfima
# Verify status BPFIMA DaemonSet Pods
kubectl get daemonset bpfima -n <target_namespace>
kubectl get pods -n <target_namespace>
# Verify low level assets
sudo lsmod | grep bpfima # kernel module inserted
sudo ls -1R /sys/fs/bpf/ # eBPF maps and programs pinned
sudo ls /sys/kernel/security/bpfima/ # securityfs interface available
```

### Framework Configuration
Custom parameters can be passed to `helm install` to customize the deployment parameters. First, it is possible to override individual values via the `--set` flag. This method is ideal for single-parameter adjustments, such as changing the target TPM PCR index or specifying a different image tag. An example is:
```bash
helm install <release> oci://registry-1.docker.io/iochia02/bpfima \
    --namespace <target_namespace> \
    --set initKernelModule.tpm_pcr_index=10 \
    --set image.tag="v0.2"
```

The second option is passing a custom YAML file via the `-f` flag. The configurable parameters include: the container image to use, the nodes to target, the eBPF hooks to load, the TPM PCR to extend, and the resource limits/requests for the various containers. These parameters are described in the [values.yaml](../install/kubernetes/bpfima/values.yaml) file:
```bash
helm install <release> oci://registry-1.docker.io/iochia02/bpfima \
    --namespace <target_namespace> \
    -f custom-values.yaml
```

### Policy Creation
Once the CRD is registered in the cluster (by the `helm install` command), administrators can define their specific integrity rules using standard YAML manifests. Two examples of Policy resources can be found in the [examples/](../install/kubernetes/bpfima/examples/) folder in the Helm chart. Because the Kubernetes API natively understands the BPFIMA schema, these Policy CRs are deployed like any built-in workload. By executing the standard command below, the control plane automatically validates the configuration and provisions the resource, immediately triggering the custom operator to intercept and enforce the new rules::
```bash
kubectl apply -f policy.yaml
```

### Upgrades and Rollbacks
Before performing an upgrade or rollback, administrators should inspect the deployment history to understand the current state of the framework. Helm maintains a chronological ledger of all actions performed on a specific release, that can be viewed with:
```bash
helm history bpfima --namespace <target_namespace>
```
This command outputs a list of revisions, alongside their deployment timestamp, operational status and a brief description.

An upgrade operation is required when releasing a new version of the framework:
```bash
helm upgrade <release> oci://registry-1.docker.io/iochia02/bpfima \
    --version <new_version> \
    --namespace <target_namespace>
```
Alternatively, if an administrator wishes to apply a new custom `values.yaml` file, they can use the `upgrade` command against the local chart source:
```bash
helm upgrade <release> oci://registry-1.docker.io/iochia02/bpfima \
    --version <version> \
    --namespace <target_namespace> \
    -f new-values.yaml
```
During an upgrade, Helm computes the differences between the current cluster state and the desired state declared in the new chart, issuing targeted Kubernetes API calls to transition the resources. For the BPFIMA DaemonSet, this triggers a rolling update, gracefully terminating and replacing the per-node Pods to ensure continuous integrity monitoring without requiring a complete framework uninstall.

If a rollout introduces unexpected behaviour, administrators can revert the framework to a previously stable state using a rollback operation.
The `helm rollback` command accepts the release name and an optional revision number to revert to. If the revision argument is omitted, Helm automatically rolls back to the immediate previous release.
To revert to the immediate previous state, execute:
```bash
helm rollback <release> --namespace <target_namespace>
```
To revert to a specific, known-stable revision (e.g., revision 1), execute:
```bash
helm rollback <release> 1 --namespace <target_namespace>
```

### Uninstallation
To remove the active BPFIMA deployment, administrators simply execute the standard `helm uninstall` command:
```bash
helm uninstall <release> --namespace <target_namespace>
```
Upon execution, Helm systematically tears down the primary resources, including the DaemonSet, and the associated \ac{RBAC} roles. Before finalizing the deletion, the framework automatically triggers a sanitation sequence across all nodes. This sequence unloads the eBPF assets, detaches the kernel module, and deletes the CRD, ensuring no residual state is left in the cluster. Finally, the namespace can be deleted with:
```bash
kubectl delete namespace <target_namespace>
```

### The testing suite
The testing infrastructure is divided into native Go unit tests (for the operator's internal logic) and end-to-end Bash scripts (for cluster and kernel validation).
To execute the Go unit tests, navigate to the specific package directory (`operator/internal/policyselector/`) and invoke the standard Go testing tool. The verbose flag is recommended to view the table-driven test outputs:
```bash
go test -v
```
The end-to-end functional and performance tests are bash scripts located in the [tests](../tests/) directory. Because some of these scripts dynamically compile kernel modules, and manipulate eBPF maps, they must be executed with elevated privileges:
```bash
# Execute a functional validation script
sudo ./tests/functional/script.sh
# Execute a performance benchmarking script
sudo ./tests/performance/script.sh
```

## Developer Manual
Some commands can be useful to extend and update the framework.

### CRD modifications
When developers modify the structs in [policy_types.go](../operator/api/v1alpha1/policy_types.go), the CRD manifest can be regenerated via:
```bash
make manifests
```

### Docker image creation
To build the Docker image, developers need to install Docker. Because Kubernetes clusters often consist of heterogeneous hardware, the BPFIMA container image must be built to support multiple architectures. An option is to use Docker Buildx, a CLI plugin that extends the Docker build capabilities to support multi-architecture image manifests.
To prepare the local development environment for cross-platform builds, developers must first create and bootstrap a new builder instance:
```bash
docker buildx create \
    --name container-builder \
    --driver docker-container \
    --bootstrap --use
```
Once the builder is active, the multi-architecture image can be compiled and pushed directly to an OCI registry (such as Docker Hub) in a single command. The `--platform` flag instructs Buildx to sequentially build the image for both targets and bundle them into a single registry manifest:
```bash
docker buildx build --platform linux/amd64,linux/arm64 \
    -t <repository>/bpfima:<tag> --push .
```
To build the image for a single architecture (matching the one of the machine used for development) it is sufficient to:
```bash
docker build -t <repository>/bpfima:<tag> . && \
      docker push <repository>/bpfima:<tag>
```

### Helm Packaging
To distribute the orchestration layer across diverse environments, the Kubernetes manifests are bundled into a Helm chart. It comprises the manifests of the DaemonSet, the custom controller's RBAC, the CRD, and the clean-up resources. Developers modifying the framework can update the core YAML definitions located within the [bfpima/install/kubernetes/bpfima/templates](../install/kubernetes/bpfima/templates) directory. Once the modifications are complete, the chart must be repackaged and distributed.
The chart is compiled into a versioned archive using the Helm CLI. Executing the package command validates the YAML syntax and compresses the directory into a `.tgz` file:
```bash
helm package bpfima
```
Because modern Helm fully supports OCI registries, the compiled chart can be pushed directly to a remote container registry (such as Docker Hub) alongside the framework's Docker images. This is accomplished using the `helm push` command, ensuring that the deployment logic and the application binaries are distributed through a unified, version-controlled channel:
```bash
helm push bpfima-0.1.0.tgz oci://registry-1.docker.io/<username>
```