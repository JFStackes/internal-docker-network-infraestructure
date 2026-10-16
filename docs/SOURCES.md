# Primary references

Reviewed during initial build on 2026-10-15. Version references are full tags, not proof that pulled image manifests are immutable or vulnerability-free. Review release notes/digests at each promotion.

- ICANN reservation of `.internal`: https://www.icann.org/en/board-activities-and-meetings/materials/approved-resolutions-special-meeting-of-the-icann-board-29-07-2024-en
- Smallstep ACME clients/Traefik, private trust and certificate duration: https://smallstep.com/docs/tutorials/acme-protocol-acme-clients/
- step-ca configuration and OSS authority-wide policy boundary: https://smallstep.com/docs/step-ca/configuration/
- step-ca ACME provisioners/challenges: https://smallstep.com/docs/step-ca/provisioners/
- Certificate templates: https://smallstep.com/docs/step-ca/templates/
- step-ca releases (0.30.2 baseline): https://github.com/smallstep/certificates/releases
- Traefik ACME resolver: https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/
- Traefik File Provider: https://doc.traefik.io/traefik/reference/install-configuration/providers/others/file/
- Traefik releases (v3.7.14 baseline): https://github.com/traefik/traefik/releases
- AdGuard Home configuration: https://adguard-dns.io/kb/adguard-home/configuration/
- DNS rewrite and denyallow semantics: https://adguard-dns.io/kb/general/dns-filtering-syntax/
- AdGuard Home releases (v0.107.79 baseline): https://github.com/AdguardTeam/AdGuardHome/releases
- AdGuard schema34 for that tag: https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/configmigrate/configmigrate.go
- Docker port publishing caveats: https://docs.docker.com/engine/network/port-publishing/
- Docker firewall behavior: https://docs.docker.com/engine/network/packet-filtering-firewalls/
- Docker iptables chains: https://docs.docker.com/engine/network/firewall-iptables/
- age implementation and usage: https://github.com/FiloSottile/age

The product deliberately does not equate an ICANN-reserved private suffix with automatic DNS, public CA eligibility or automatic trust on devices.
