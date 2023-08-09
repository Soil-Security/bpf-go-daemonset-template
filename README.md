# bpf-daemonset-template

## Prerequisites

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
git clone https://github.com/danielpacak/bpf-daemonset-template.git
cd bpf-daemonset-template
```

```
git submodule update --init --recursive
```

```
docker build -t danielpacak/bpf-daemonset-template .
```

```
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/bin/
kind version
```

```
kind create cluster
```

```
make image
```
```
kind load docker-image danielpacak/bpf-daemonset-template
```

```
sudo snap install kubectl --classic --channel=1.27
source <(kubectl completion bash)
```

```
kubectl apply -f kube/bpf.daemonset.yml
```

```
kubectl logs -f -n bpf-system ds/bpf-daemonset
```

```
sudo bpftool prog tracelog
```

## Uninstall

```
kubectl delete -f kube/bpf.daemonset.yml
```

```
kind delete cluster
```

```
docker system prune
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
