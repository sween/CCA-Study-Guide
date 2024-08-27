# Top of Mind

*Cilium KVStore mesh*

KVStoreMesh is an extension of Cluster Mesh. It caches the information obtained from the remote clusters in a local kvstore (such as etcd), to which all local Cilium agents connect. _This is different from vanilla Cluster Mesh, where each agent directly pulls the information from the remote clusters_. KVStoreMesh enables improved scalability and isolation.

*L2 Announcement Feature, Why ?*

L2 Announcements is a feature which makes services visible and reachable on the local area network. _This feature is primarily intended for on-premises deployments within networks without BGP based routing such as office or campus networks._

*Hubble, who is responsible for metrics serving ?*

Hubble is made up of several components.

The Hubble server runs on each node and retrieves the eBPF-based visibility from Cilium. It is embedded into the Cilium agent in order to achieve high performance and low-overhead. It offers a gRPC service to retrieve flows and expose Prometheus metrics.

![image](https://github.com/user-attachments/assets/581d5e9e-13d3-4868-b92e-e954f24e6772)


EBPF ingress only on nic ?

XDP
Ingress only, any traffic that you see with an XDP program is only incoming and there is currently no way of seeing traffic that is .

How to disable policies globally temporarily

To disable policy enforcement globally in Cilium, you can _configure the Cilium agent to use the Never policy enforcement mode_. In this mode, all endpoints disable policy enforcement, even if rules select specific endpoints. This allows all traffic from any source or destination, regardless of the rules.

To configure the policy enforcement mode, you can adjust the Helm value *policyEnforcementMode* or the configuration flag *enable-policy*




Net Policy example, bi-directional between two pods, only on 80 at on specific route.

'
The Cilium Operator is responsible for managing duties in the cluster which should logically be handled once for the entire cluster, rather than once for each node in the cluster. 

```
kind: CiliumNetworkPolicy
metadata:
  name: "rule1"
spec:
  description: "L7 policy to restrict access to specific HTTP call"
  endpointSelector:
    matchLabels:
      org: empire
      class: deathstar
  ingress:
  - fromEndpoints:
    - matchLabels:
        org: empire
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      rules:
        http:
        - method: "POST"
          path: "/v1/request-landing"
```

Default Modes (routing)



CNI Chaining Modes



## Cilium Certified Associate Study Guide

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC_BY--NC_4.0-lightgrey.svg)](LICENSE)
![cca-banner](files/ogimage.jpeg)
The aim of this study guide is to help the Cilium community prepare for the CNCF's [Cilium Certified Associate(CCA)](https://training.linuxfoundation.org/certification/cilium-certified-associate-cca/) Exam 🐝

## About the Certification

You can find all you need to know about the Certification on its official [page](https://training.linuxfoundation.org/certification/cilium-certified-associate-cca/).

### General Overview

- [ ] [LinuxFoundationX: Introduction to Cilium](https://www.edx.org/learn/kubernetes/the-linux-foundation-introduction-to-cilium) 📖

### Installation and Configuration - 10%

#### Topics

- *Know How to Use Cilium CLI to Query and Modify the Configuration*
- *Using Cilium CLI to Install Cilium, Run Connectivity Tests, and Monitor its Status*

#### Resources

- [X] [Cilium Quick Installation - Cilium Docs](https://docs.cilium.io/en/latest/gettingstarted/k8s-install-default/#k8s-install-quick) 📖
- [X] [eCHO episode 1: Introduction to Cilium](https://www.youtube.com/watch?v=80OYrzS1dCA&list=PLDg_GiBbAx-mY3VFLPbLHcxo6wUjejAOC&index=114) 📺
- [X] [Getting Started with Cilium - Lab](https://isovalent.com/labs/getting-started-with-cilium/) 🥼
- [X] Tutorial: Tips and Tricks to install Cilium](https://isovalent.com/blog/post/tutorial-tips-and-tricks-to-install-cilium/) 📖
```
cilium install \
    --helm-set ipam.mode=kubernetes \
    --helm-set tunnel=disabled \
    --helm-set ipv4NativeRoutingCIDR="10.0.0.0/8" \
    --helm-set bgpControlPlane.enabled=true \
    --helm-set k8s.requireIPv4PodCIDR=true

root@server:~# cilium install --version=v1.11.1 --encryption wireguard --helm-auto-gen-values helm-values.yaml

```
- [X] [Cilium Command Cheat Sheet - Cilium Docs](https://docs.cilium.io/en/stable/cheatsheet/) 📖

### Architecture - 20%

![image](https://github.com/user-attachments/assets/8369df2f-2fb1-40f1-9dd6-09d648f10593)


#### Topics

- *Understand the Role of Cilium in Kubernetes Environments*
- *Cilium Architecture*
- *Cilium Component Roles*

![image](https://github.com/user-attachments/assets/b43fc670-f309-4a23-9568-918137b23c3a)

![image](https://github.com/user-attachments/assets/a56a911a-bf1c-4826-8abc-5b6501e0ad14)


*Cilium Operator*
The Cilium operator is responsible for managing duties in the cluster which should logically be handled once for the entire cluster, rather than once for each node in the cluster. The Cilium operator is not in the critical path for any forwarding or network policy decision. A cluster will generally continue to function if the operator is temporarily unavailable.

*Cilium Agent*
The Cilium agent runs as a daemonset so that there is a Cilium agent pod running on every node in your Kubernetes cluster. The agent does the bulk of the work associated with Cilium:

Interacts with Kubernetes API server to synchronize cluster state.
Interacts with the Linux kernel - loading eBPF programs and updating eBPF maps.
Interacts with the Cilium CNI plugin executable, via a filesystem socket, to get notified of newly scheduled workloads.
Creates on-demand DNS and Envoy proxies as needed based on requested network policy.
Creates Hubble gRPC services when Hubble is enabled.

*Cilium Client*
Each pod in the Cilium agent daemonset comes with a Cilium client executable that can be used to inspect the state of Cilium agent and eBPF maps resources installed on that node. The client communicates with the Cilium agent’s REST API from inside the daemonset pod.

Note: This is not the same as the Cilium CLI tool executable that you installed on your workstation. The Cilium client executable is included in each Cilium agent pod, and can be used as a diagnostic tool to help troubleshoot Cilium agent operation if needed. You’ll seldom interact with the Cilium client as part of normal operation, but we’ll use it in some of the labs to help us see into the internals of the Cilium network state as we work with some of the Cilium capabilities.

*Cilium CNI Plugin*
The Cilium agent daemonset also installs the Cilium CNI plugin executable into the Kubernetes host filesystem and reconfigures the node’s CNI to make use of the plugin. The CNI plugin executable is separate from the Cilium agent, and is installed as part of the agent daemonset initialization. When required, the Cilium CNI plugin will communicate with the running Cilium agent using a host filesystem socket.

*Hubble Relay*
When Hubble is enabled as part of a Cilium-managed cluster, the Cilium agents running on each node are restarted to enable the Hubble gRPC service to provide node-local observability. For cluster-wide observability, a Hubble Relay deployment is added to the cluster along with two additional services; the Hubble Observer service and the Hubble Peer service.

Hubble Relay is 1 per cluster.

The Hubble Relay deployment provides cluster-wide observability by acting as an intermediary between the cluster-wide Hubble Observer service and the Hubble gRPC services that each Cilium agent provides. The Hubble Peer service makes it possible for Hubble Relay to detect when new Hubble-enabled Cilium agents become active in the cluster. As a user, you will typically be interacting with the Hubble Observer service, using either the Hubble CLI tool or the Hubble UI, to gain insights into the network flows across your cluster that Hubble provides. The cluster you installed in this chapter’s lab should have Hubble enabled. We’ll get hands-on with Hubble in more detail in Chapter 5.

*Cluster Mesh API Server*
The Cluster Mesh API server is an optional deployment that is only installed if you enable the Cilium Cluster Mesh feature. Cilium Cluster Mesh allows Kubernetes services to be shared amongst multiple clusters.

Cilium Cluster Mesh deploys an *etcd key-value store in each cluster, to hold information about Cilium identities*. It also exposes a proxy service for each of these etcd stores. Cilium agents running in any member of the same Cluster Mesh can use this service to read information about Cilium identity state globally across the mesh. This makes it possible to create and access global services that span the Cluster Mesh. Once the Cilium Cluster Mesh API service is available, Cilium agents running in any Kubernetes cluster that is a member of the Cluster Mesh are then able to securely read from each cluster’s etcd proxy thus gaining knowledge of Cilium identity state globally across the mesh. This makes it possible to create global services that span the cluster mesh. We’ll cover the capabilities of the Cilium Cluster Mesh in more detail in a later chapter.

### Cilium

Agent
The Cilium agent (cilium-agent) runs on each node in the cluster. At a high-level, the agent accepts configuration via Kubernetes or APIs that describes networking, service load-balancing, network policies, and visibility & monitoring requirements.

The Cilium agent listens for events from orchestration systems such as Kubernetes to learn when containers or workloads are started and stopped. It manages the eBPF programs which the Linux kernel uses to control all network access in / out of those containers.

Client (CLI)
The Cilium CLI client (cilium) is a command-line tool that is installed along with the Cilium agent. It interacts with the REST API of the Cilium agent running on the same node. The CLI allows inspecting the state and status of the local agent. It also provides tooling to directly access the eBPF maps to validate their state.

Note

The in-agent Cilium CLI client described here should not be confused with the command line tool for quick-installing, managing and troubleshooting Cilium on Kubernetes clusters, which also has the name cilium. That tool is typically installed remote from the cluster, and uses kubeconfig information to access Cilium running on the cluster via the Kubernetes API.

Operator
The Cilium Operator is responsible for managing duties in the cluster which should logically be handled once for the entire cluster, rather than once for each node in the cluster. The Cilium operator is not in the critical path for any forwarding or network policy decision. A cluster will generally continue to function if the operator is temporarily unavailable. However, depending on the configuration, failure in availability of the operator can lead to:

- [ ] Delays in IP Address Management (IPAM) and thus delay in scheduling of new workloads if the operator is required to allocate new IP addresses
- [ ] Failure to update the kvstore heartbeat key which will lead agents to declare kvstore unhealthiness and restart.

CNI Plugin
The CNI plugin (cilium-cni) is invoked by Kubernetes when a pod is scheduled or terminated on a node. It interacts with the Cilium API of the node to trigger the necessary datapath configuration to provide networking, load-balancing and network policies for the pod.

Hubble
Server
The Hubble server runs on each node and retrieves the eBPF-based visibility from Cilium. It is embedded into the Cilium agent in order to achieve high performance and low-overhead. It offers a gRPC service to retrieve flows and Prometheus metrics.

Relay
Relay (hubble-relay) is a standalone component which is aware of all running Hubble servers and offers cluster-wide visibility by connecting to their respective gRPC APIs and providing an API that represents all servers in the cluster.

Client (CLI)
The Hubble CLI (hubble) is a command-line tool able to connect to either the gRPC API of hubble-relay or the local server to retrieve flow events.

Graphical UI (GUI)
The graphical user interface (hubble-ui) utilizes relay-based visibility to provide a graphical service dependency and connectivity map.

- *IP Address Management (IPAM) with Cilium*
IP Address Management (IPAM) is responsible for the allocation and management of IP addresses used by network endpoints (container and others) managed by Cilium. Various IPAM modes are supported to meet the needs of different users:

![image](https://github.com/user-attachments/assets/acffa596-04cb-48ee-855e-3edabc724687)

- *Datapath Models*

#### Resources

- [X] [Getting Started with Cilium - Lab](https://isovalent.com/labs/getting-started-with-cilium/) 🥼
- [X] [Cilium - Rethinking Linux Networking and Security for the Age of Microservices](https://cilium.io/blog/2018/04/24/cilium-security-for-age-of-microservices/) 📖

Service-Centric Identity and API-Awareness
With traditional firewalling, workloads are identified by IP addresses and the "intent" of the communication is identified by TCP/UDP port (e.g., TCP port 80 accesses Web, TCP port 22 accesses SSH).

But with microservices, an application is deconstructed into many distinct services, with each service implemented as a collection of stateless container for scale-out performance, failure redundancy, and incremental upgrades. As a result, IP addresses are relatively ephemeral, changing meaning each time a container is created or destroyed.

Furthermore, most communication happens using only a few ports (e.g., HTTP), and the actual “intent” of the communication between services can only be determined by understanding the API-layer “remote procedure calls” (RPCs) between API-driven services and datastores.

A typical microservices endpoint will expose 10s or even 100s of unique RPC calls:

A RESTful HTTP-based service often exposes POST/PUT/GET/DELETE for many different resource types, each represented by a URL prefix.
A Kafka broker will often have many different topics, and allow actions like produce and consume on each topic to different clients.
A datastore like Cassandra, Elasticsearch, Mongodb, Redis, and even Mysql and Postgres provides both read and write access to many distinct tables/indices.
As a result, port-based visibility and security is blind to the individual RPC calls and will expose either all RPC between two different services or none at all.

With Cilium, identity is extracted from the container orchestrator and embedded in each network request (e.g., id=app1). Unlike an IP address, such an identity is consistent across multiple replicas implementing a service, and consistent across time. Furthermore, Cilium provides API-aware visibility and security that understands HTTP Methods/URL, gRPC service methods, Kafka topics, etc. and enables fine-grained visibility and security at the granularity of the RPCs between microservices.

![image](https://github.com/user-attachments/assets/626a0d8f-252b-4a17-aecd-97105c2d95fb)


![image](https://github.com/user-attachments/assets/13709395-dc5b-4688-825f-30ef8f31f86b)

Identities

![image](https://github.com/user-attachments/assets/0f853307-ef05-4337-a98b-4eca500614f5)



- [X] [Cilium 1.0: Bringing the BPF Revolution to Kubernetes Networking and Security](https://cilium.io/blog/2018/04/24/cilium-10/) 📖
- [X] [Cilium Component Overview - Cilium Docs](https://docs.cilium.io/en/stable/overview/component-overview/) 📖
- [ ] [Cilium eBPF Datapath - Cilium Docs](https://docs.cilium.io/en/stable/network/ebpf/) 📖
- [ ] [IP Address Management (IPAM) - Cilium Docs](https://docs.cilium.io/en/stable/network/concepts/ipam/) 📖
- [X] [Cilium Technical Deep Dive: Under the Hood - Talk](https://www.youtube.com/watch?v=UZg_2SXDKis) 📺
- [X] [Cilium's BPF kernel datapath revamped - Talk](https://www.youtube.com/watch?v=u0PGas8D24w) 📺
- [ ] [Terminology - Cilium Docs](https://docs.cilium.io/en/stable/gettingstarted/terminology/) 📖

### Network Policy - 18%

- [X] Reviewer Layer Mappings
- [ ] Review Order of Operations with policy, like in the host Firewall lab
- [X] Review Policy types
NetworkPolicy (k8s), CilliumNetworkPolicy, CilliumClusterWideNetworkPolicy

![image](https://github.com/user-attachments/assets/9121bb0b-b69b-4fce-9147-4a167f25011a)



k8s standard Layers
![image](https://github.com/user-attachments/assets/76678937-8f71-465d-9dde-d11ae5f79f30)

Cilium Layers
![image](https://github.com/user-attachments/assets/3b11ed0f-cb9a-4b31-adf6-9d900048aaaa)

Layer 7 Examples

![image](https://github.com/user-attachments/assets/a91d75f1-6c37-41d3-859f-1ae2138d9f40)

WTF

![image](https://github.com/user-attachments/assets/ac8991db-12bd-47a9-9bd1-0475aaa4ee29)


#### Topics

- Interpret Cilium Network Polices and Intent
- Understand Cilium's Identity-based Network Security Model
- Policy Enforcement Modes
- Policy Rule Structure
- Kubernetes Network Policies versus Cilium Network Policies

#### Resources

- [Identity Based - Cilium Docs](https://docs.cilium.io/en/stable/security/network/identity/) 📖
- 
![image](https://github.com/user-attachments/assets/1fa6e413-48f2-451f-915c-c85144c7878e)

- [Network Policy Use Cases](https://cilium.io/use-cases/network-policy/) 📖
- [From IP to identity: making cattle out of pets in cloud native](https://www.cncf.io/blog/2023/07/24/from-ip-to-identity-making-cattle-out-of-pets-in-cloud-native/) 📖
- [Zero Trust Security with Cilium](https://isovalent.com/blog/post/zero-trust-security-with-cilium/) 📖

zero trust:

Default allow all so that observability kicks in.
Create policies for everything talking.
ensure allow all is workie no more.
remove allow all policy

- 
- [Network Policy - Cilium Docs](https://docs.cilium.io/en/latest/security/policy/) 📖
- [Policy Enforcement Mode - Cilium Docs](https://docs.cilium.io/en/latest/security/policy/intro/) 📖

- 
- [Why is Kubernetes Network Policy important?](https://youtu.be/5sc4R-wk7uo) 📺
- [Birth of Kubernetes Network Policy](https://youtu.be/x69ofJYr71g) 📺
- [NetworkPolicy Tutorial](https://github.com/networkpolicy/tutorial) 📖
- [eCHO Episode 43: Deep dive on FQDN Policy](https://www.youtube.com/watch?v=iJ98HRZi8hM) 📺
- [Network Policy Editor](https://networkpolicy.io/) 📖

### Service Mesh - 16%

#### Topics

![image](https://github.com/user-attachments/assets/20b16770-7740-4fa4-bfd7-fdbc21387990)


- Know How to use Ingress or Gateway API for Ingress Routing
- Service Mesh Use Cases
- Understand the Benefits of Gateway API over Ingress
- Encrypting Traffic in Transit with Cilium
- Sidecar-based versus Sidecarless Architectures

#### Resources

- [How eBPF will solve Service Mesh – Goodbye Sidecars](https://isovalent.com/blog/post/2021-12-08-ebpf-servicemesh/) 📖
- [Cilium Service Mesh Use Cases](https://cilium.io/use-cases/service-mesh/) 📖
- [Hello eBPF! Goodbye Sidecars?](https://www.youtube.com/watch?v=0JFd0W2CcMw) 📺
- [Cilium Service Mesh – Everything You Need to Know](https://isovalent.com/blog/post/cilium-service-mesh/) 📖
- [Cilium Ingress Controller - Lab](https://isovalent.com/labs/cilium-ingress-controller/) 🥼
- [Cilium Transparent Encryption with IPSec and WireGuard - Lab](https://isovalent.com/labs/cilium-transparent-encryption-with-ipsec-and-wireguard/) 🥼
- [Gateway API Support - Cilium Docs](https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/gateway-api/) 📖
- [Cilium Gateway API - Lab](https://isovalent.com/labs/gateway-api/) 🥼
- [Advanced Gateway API Use Cases - Lab](https://isovalent.com/labs/advanced-gateway-api-use-cases/) 📖
- [Ingress Controllers or the Kubernetes Gateway API? Which Is Right for You?](https://thenewstack.io/ingress-controllers-or-the-kubernetes-gateway-api-which-is-right-for-you/) 📖
- [A Deep Dive into Cilium Gateway API: The Future of Ingress Traffic Routing](https://isovalent.com/blog/post/cilium-gateway-api/) 📖
- [Mutual Authentication in Cilium - Cilium Docs](https://docs.cilium.io/en/stable/network/servicemesh/mutual-authentication/mutual-authentication/#mutual-authentication-in-cilium) 📖
- [Mutual Authentication in Cilium - Lab](https://isovalent.com/labs/mutual-authentication-with-cilium/) 🥼

### Network Observability - 10%

#### Topics

- Understand the Observability Capabilities of Hubble
- Enabling Layer 7 Protocol Visibility
- Know How to Use Hubble from the Command Line or the Hubble UI

![image](https://github.com/user-attachments/assets/3f4d5b93-758b-4edc-9ef7-7813e0ed35b8)

Prometheus

Sample Grafana deployment and patches...

https://github.com/cilium/cilium/tree/main/examples/kubernetes/addons/prometheus

![image](https://github.com/user-attachments/assets/7580f59e-3026-4126-810f-f2f9d87007ee)


#### Resources

- [eCHO episode 2: Introduction to Hubble](https://www.youtube.com/live/hD2iJUyIXQw?si=WqWaY7_jN2B-sRz5) 📺
- [Observability Use Cases](https://cilium.io/#observability) 📖
- [Setting up Hubble Observability - Cilium Docs](https://docs.cilium.io/en/latest/gettingstarted/hubble_setup/#hubble-setup) 📖
- [Layer 7 Protocol Visibility - Cilium Docs](https://docs.cilium.io/en/stable/observability/visibility/) 📖
- [Back to Basics – L7 Flow Visibility](https://isovalent.com/videos/back-to-basics-l7-flow-visibility/) 📺
- [Cilium IPv6 Networking and Observability - Lab](https://isovalent.com/labs/ipv6-networking-and-observability/) 🥼

### Cluster Mesh - 10%

#### Topics

- Understand the Benefits of Cluster Mesh for Multi-cluster Connectivity

  ![image](https://github.com/user-attachments/assets/52eafb0d-2505-4a32-a545-56a15e99cdb6)

- Achieve Service Discovery and Load Balancing Across Clusters with Cluster Mesh

  ![image](https://github.com/user-attachments/assets/8029087b-c08e-4c09-b364-e191612ce7a5)

Reqs:

Before you can enable the Cluster Mesh feature, you must make sure certain requirements are met:

All Kubernetes worker nodes must be assigned a unique IP address and all worker nodes must have IP connectivity between each other.
All clusters must be assigned unique PodCIDR ranges, to prevent pod IP addresses from overlapping across the mesh.
The network between clusters must allow inter-cluster communication so Cilium agents can access all Cluster Mesh API Servers in the mesh. For public cloud Kubernetes services, this is typically done using virtual private network peering and/or network security group configuration to ensure node-to-node communication between clusters. The exact firewalling requirements will depend on whether Cilium is configured to run in direct-routing or tunneling mode.

#### Resources

- [Cilium Cluster Mesh Use Cases](https://cilium.io/use-cases/cluster-mesh/) 📖
- [Setting Up Cluster Mesh - Cilium Docs](https://docs.cilium.io/en/stable/network/clustermesh/clustermesh/#setting-up-cluster-mesh) 📖
- [Cilium Cluster Mesh - Lab](https://isovalent.com/labs/cilium-cluster-mesh/) 🥼
- [Connecting Klusters on the Edge with Deep Dive into Cilium Cluster Mesh - Talk](https://www.youtube.com/watch?v=UcsEVnFtrLY) 📺
- [An Introduction to Cilium Cluster Mesh](https://www.youtube.com/watch?v=4bJkk7ghx7A) 📺
- [eCHO episode 41: Cilium Cluster Mesh](https://www.youtube.com/watch?v=VBOONHW65NU) 📺
- [eCHO Episode 94: Cluster API and Cilium Cluster Mesh](https://m.youtube.com/watch?v=HVqQhMRpUR4&pp=ygUKI2Fic29saXRlbQ%3D%3D) 📺

### eBPF - 10%

#### Topics

- Understand the Role of eBPF in Cilium
- eBPF Key Benefits
- eBPF-based Platforms versus IPtables-based Platforms

#### Resources

- [Why is the kernel community replacing iptables with BPF?](https://cilium.io/blog/2018/04/17/why-is-the-kernel-community-replacing-iptables/) 📖
- [What is eBPF?](https://isovalent.com/books/ebpf/) 📖
- [CNI Benchmark: Understanding Cilium Network Performance](https://cilium.io/blog/2021/05/11/cni-benchmark/) 📖
- [eBPF - The Future of Networking & Security](https://cilium.io/blog/2020/11/10/ebpf-future-of-networking/) 📖
- [Learning eBPF](https://isovalent.com/books/learning-ebpf/) 📖
- [Getting started with eBPF - Lab](https://isovalent.com/labs/getting-started-with-ebpf/) 🥼
- [eBPF - Host Routing - Cilium Docs](https://docs.cilium.io/en/stable/operations/performance/tuning/#ebpf-host-routing) 📖

### BGP and External Networking 6%

#### Topics

- Egress Connectivity Requirements
- Understand Options to Connect Cilium-managed Clusters with External Networks

#### Resources

- [Cilium BGP Use Cases](https://cilium.io/use-cases/bgp/) 📖
- [Cilium BGP Control Plane - Cilium Docs](https://docs.cilium.io/en/stable/network/bgp-control-plane/) 📖
- [Cilium BGP Service Advertisement](https://www.youtube.com/watch?v=Nzh2jc6qW6Y) 📺
- [BGP on Cilium - Lab](https://isovalent.com/labs/bgp-on-cilium/) 🥼
- [Cilium LoadBalancer IPAM and BGP Service Advertisement - Lab](https://isovalent.com/labs/lb-ipam-bgp-service/) 🥼
- [Advanced BGP Features - Lab](https://isovalent.com/labs/advanced-bgp-features/) 🥼
- [BGP with Cilium](https://nicovibert.com/2022/07/21/bgp-with-cilium/) 📖
- [Connecting your Kubernetes island to your network with Cilium BGP](https://isovalent.com/blog/post/connecting-your-kubernetes-island-to-your-network-with-cilium-bgp/) 📖
- [Cilium Egress Gateway - Cilium Docs](https://docs.cilium.io/en/stable/network/egress-gateway/) 📖
- [Cilium Egress Gateway - Lab](https://isovalent.com/labs/cilium-egress-gateway/) 🥼
- [Cilium L2 Announcements - Cilium Docs](https://docs.cilium.io/en/stable/network/l2-announcements/) 📖
- [Cilium LoadBalancer IPAM and L2 Service Announcement - Lab](https://isovalent.com/labs/cilium-loadbalancer-ipam-and-l2-service-announcement/) 🥼

## Next Steps

Finished this guide and want to learn more? Dive deep into the world of Cilium with more comprehensive [hands-on labs](https://labs-map.isovalent.com/).

![](./files/world-of-cilium.png)


## 
