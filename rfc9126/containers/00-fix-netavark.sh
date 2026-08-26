#!/usr/bin/env bash
# Corrige o bug netavark 2.0.0 x nftables 1.1.6 na VM do Podman (WSL2).
#
# CAUSA RAIZ: no setup de rede, o netavark executa `nft -j list table inet
# netavark`. Com nftables 1.1.6, listar uma tabela inexistente retorna EXIT 1;
# versoes antigas toleravam. O netavark 2.0.0 nao trata esse caso e ABORTA ->
# "nftables error: nft did not return successfully". Afeta qualquer rede
# bridge customizada (com ou sem -p).
#
# CORRECAO: desabilitar o firewall_driver do netavark (system-wide na VM).
# Nao usamos NAT/isolamento por nft neste laboratorio; bridge, DNS por nome
# (aardvark) e port-forward rootless (-p) continuam funcionando.
set -euo pipefail

echo "[fix] aplicando firewall_driver=none na VM (drop-in system-wide)..."
podman machine ssh 'sudo mkdir -p /etc/containers/containers.conf.d \
  && printf "[network]\nfirewall_driver = \"none\"\n" | sudo tee /etc/containers/containers.conf.d/99-fw-none.conf >/dev/null \
  && echo "  aplicado:" && sudo sed "s/^/    /" /etc/containers/containers.conf.d/99-fw-none.conf'
echo "[fix] ok. Redes bridge customizadas do Podman agora funcionam neste ambiente."
