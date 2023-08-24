# bpf-daemonset-template

A GitHub [template] repository with the scaffolding for a BPF program that is
run on a Kubernetes cluster, i.e. deployed as a [DaemonSet] on each cluster
node. The BPF program traces [execve(2)] system calls and sends events from
kernel to user space through a [BPF ring buffer], and prints them to the
standard output.

``` console
$ kubectl logs -f -n bpf-system daemonset/bpf-daemonset
BPF daemon started
{"Pid":46949,"PPid":46948,"Comm":"ip","Uid":1000,"Args":["/usr/sbin/ip","tuntap","show"]}
{"Pid":46950,"PPid":46948,"Comm":"cut","Uid":1000,"Args":["/usr/bin/cut","-d",":","-f1"]}
{"Pid":46951,"PPid":46948,"Comm":"head","Uid":1000,"Args":["/usr/bin/head","-n","1"]}
```

## Setup Development Environment

```
sudo apt-get update
```

```
sudo apt-get install build-essentials \
  pkgconf \
  libelf-dev \
  llvm \
  clang \
  clang-format
```

```
sudo apt-get install docker.io
sudo usermod -aG docker $USER
newgrp docker
docker version
```

```
sudo apt-get install linux-tools-$(uname -r)
bpftool version
```

```
sudo snap install kubectl --classic --channel=1.27
source <(kubectl completion bash)
```

## Compile Sources

```
git clone --recurse-submodules https://github.com/danielpacak/bpf-daemonset-template.git
cd bpf-daemonset-template
```

```
make all image
```

## Create DaemonSet

```
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/bin/
kind version
```

```
kind create cluster \
  --image="kindest/node:v1.27.3@sha256:3966ac761ae0136263ffdb6cfd4db23ef8a83cba8a463690e98317add2c9ba72"
```

```
kind load docker-image danielpacak/bpf-daemonset-template:latest
```

```
kubectl apply -f kube/bpf.daemonset.yml
```

``` console
$ kubectl logs -f -n bpf-system daemonset/bpf-daemonset
BPF daemon started
{"Pid":46947,"PPid":1293,"Comm":"xfce4-panel-gen","Uid":1000,"Args":["/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh"]}
{"Pid":46949,"PPid":46948,"Comm":"ip","Uid":1000,"Args":["/usr/sbin/ip","tuntap","show"]}
{"Pid":46950,"PPid":46948,"Comm":"cut","Uid":1000,"Args":["/usr/bin/cut","-d",":","-f1"]}
{"Pid":46951,"PPid":46948,"Comm":"head","Uid":1000,"Args":["/usr/bin/head","-n","1"]}
[...]
```

## Delete DaemonSet

```
kubectl delete -f kube/bpf.daemonset.yml
```

## Resources

* https://loft.sh/blog/tutorial-how-ebpf-improves-observability-within-kubernetes/
* https://github.com/iovisor/gobpf/blob/master/examples/bcc/execsnoop/execsnoop.go/
* https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.bpf.c/
* https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.c/
* https://medium.com/@calavera/spy-on-your-kubernetes-cluster-with-bpf-b09032bd1cdc/
* https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/
* https://www.groundcover.com/blog/what-is-ebpf/
* https://www.form3.tech/engineering/content/bypassing-ebpf-tools/
* https://www.pingcap.com/blog/tips-and-tricks-for-writing-linux-bpf-applications-with-libbpf/
* [Cgroup Iter: A step toward container-oriented observability - Hao Luo](https://www.youtube.com/watch?v=i-a9a6cZm20)

[DaemonSet]: https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/
[execve(2)]: https://man7.org/linux/man-pages/man2/execve.2.html
[template]: https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template/
[BPF ring buffer]: https://www.kernel.org/doc/html/next/bpf/ringbuf.html
