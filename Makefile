export KERNEL_VERSION = 6.12.59
export ARCH = $(shell uname -m)

INCLUDE_FOLDER = "internal/bpf/kern/include"
generate: go-generate

go-generate:
	docker build -t compile --target compile -f Dockerfile.bpf .
	docker run -ti -v $(PWD):/work -w /work compile go generate ./...


ebpf-test:
	docker run --privileged -v $(shell go env GOMODCACHE):/go/pkg/mod -v $(PWD):/src -v /sys/kernel/tracing:/sys/kernel/tracing:rw -w /src golang go test -v ./internal/bpf/...

generate-btf-headers:
	docker build -t bpftool https://github.com/libbpf/bpftool.git#main
	# ensure kernel of docker vm is new enough
	# TODO: find a way to make this reproducible for a certain kernel image
	docker run \
		-v /sys/kernel/btf:/sys/kernel/btf \
		bpftool btf dump file /sys/kernel/btf/nf_conntrack format c > $(INCLUDE_FOLDER)/vmlinux.h

build-libbpf-image:
	docker build -t libbpf --target libbpf .

generate-libbpf-headers: build-libbpf-image
	docker create --name libbpf libbpf
	docker cp libbpf:/usr/include/bpf $(INCLUDE_FOLDER)
	docker rm -f libbpf
	find $(INCLUDE_FOLDER)/bpf -maxdepth 1 -type f ! -name "bpf*.h" -delete

generate-linux-headers:
	crane pull -c /tmp/linuxkit linuxkit/kernel:$(KERNEL_VERSION) linuxkit.tar
	mkdir linuxkit || true
	tar -xf  "linuxkit.tar" -C linuxkit
	rm linuxkit.tar
	tar -xzvf `find linuxkit -name "*.tar.gz"` -C linuxkit
	mkdir /tmp/linux || true
	tar -xf "linuxkit/kernel-headers.tar" -C /tmp/linux
	cp -R /tmp/linux/usr/include/linux/ $(INCLUDE_FOLDER)/linux
	cp -R /tmp/linux/usr/include/asm* $(INCLUDE_FOLDER)
	rm -r linuxkit


compose-up:
	docker compose up --build

xdpdump:
	./hack/tools/xdptools.sh xdpdump --container yaxelb-lb-1 -i eth0 -p load_balance --rx-capture=entry,exit -w - | docker run -i nicolaka/netshoot tcpdump -r - -nevvva

xdpdump-wireshark:
	./hack/tools/xdpdump.sh xdpdump --container yaxelb-lb-1 -i eth0 -p load_balance --rx-capture=entry,exit -w - | wireshark -k -i -

xdpmonitor:
	./hack/tools/xdptools.sh xdp-monitor --container yaxelb-lb-1 -i eth0 -p load_balance --rx-capture=entry,exit -w - | docker run -i nicolaka/netshoot tcpdump -r - -nevvva
