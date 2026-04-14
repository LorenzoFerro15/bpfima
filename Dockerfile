FROM fedora:43
RUN sudo dnf -y install libbpf-devel elfutils-libelf-devel zlib-devel clang \
    llvm libyaml-devel pahole bpftool kmod --setopt=install_weak_deps=False

COPY ./ /opt/bpfima
ENTRYPOINT ["/opt/bpfima/scripts/init_module.sh"]
