# Yet another XDP eBPF LoadBalancer

YaxeLB is a XDP based Load Balancer in eBPF.
It is a very basic load balancer showing how XDP can be used to write LBs.

The configuration is a simple yaml file that where an example can be found in [./examples/config.yaml](./examples/config.yaml)

## Get started locally

Start the docker compose project that runs the load balancer as well as a set of backends.

1. `make compose-up`
Access the LoadBalancer from a client inside the docker network.
2. `docker compose exec client curl 10.0.0.2`

## Debugging traffic

The project contains tools to debug traffic using [xdpdump](https://github.com/xdp-project/xdp-tools/tree/main/xdp-dump) and [pwru](github.com/cilium/pwru).
You can use them with `make xdpdump` or `./hack/pwru.sh`. This will build the utilities using docker and run them inside containers.
