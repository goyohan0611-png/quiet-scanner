# Quiet Guard

<!-- impeccable:product-schema 1 -->

## Platform

web

The initial management surface is a browser UI on the Linux server's loopback interface, reached remotely through SSH forwarding. This is the working default offered in this session; a separate Windows management app remains an open preference.

## Stack

Existing Rust agent and controllers. The management surface uses embedded HTML/CSS/JavaScript and a Rust HTTP adapter; the privileged controller remains separate from the web process. No third-party web fonts or analytics.

## Users

Solo and small-service developers operating servers they can administer. The product target includes Ubuntu/Debian, RHEL-compatible distributions and Windows Server. They need to understand protection state, act on a small set of findings, and recover from configuration failures without becoming security specialists.

## Product Purpose

Connect setup, SSH protection, web request inspection, exposure review and recovery in an understandable workflow. Running software alone must never imply verified protection.

## Operating Context

Ubuntu 24.04 x86_64 first. Existing SSH and Nginx services must be preserved. WAF currently supports a limited apt Nginx HTTP/1.x direct-access profile. Actual external verification is a separate operation; exposure evidence remains operator-supplied.

The user explicitly wants broad server applicability, including Red Hat-family systems and Windows Server. This is a support goal, not evidence of existing compatibility. Debian, RHEL, Rocky Linux, AlmaLinux and Windows Server require separate installation, protection and recovery verification; their supported versions and architectures are not yet committed. Amazon Linux is an additional candidate requiring its own qualification rather than inferred RHEL compatibility.

Keep the Rust policy/state model, management API contract and interface reusable. Isolate package management, service supervision, authentication-log collection, privileged IPC, exposure inventory and firewall enforcement behind platform-specific implementations. Windows Server needs native service/event-log/firewall integration, RDP-specific evidence evaluation and a separate IIS/web-inspection design. The current Linux Nginx implementation does not establish Windows WAF support.

Qualification is per operating-system version, architecture and feature. A successful build or open management screen does not establish protection support. Unsupported or unverified capabilities must stay explicit; automatic blocking requires proven management-access exceptions, finite decisions, read-back and safe removal. Deployments require authority to install and run a host agent; managed environments without that control need a separate integration design.

## Capabilities and Constraints

Existing signed foundation lifecycle, SSH control, WAF control, read-only exposure inventory and scoped external TCP probe. Protection and remaining risk are independent. Management UI, dependency preparation UX and alerts are being added. The UI must show unsupported profiles, missing dependencies, stale checks, partial operation and recovery failures honestly. No shell or arbitrary command endpoint.

## Brand Commitments

Quiet Guard is separate from Quiet Scanner. The Quiet family favors clear Korean labels, restrained blue accents and compact operational screens. The new management screen inherits those practical priorities; its visual details are implementation decisions rather than a new user-approved brand.

## Evidence on Hand

README.md documents implemented scope. The Ubuntu CI covers signed deployment, SSH, actual Nginx WAF and IPv4/IPv6 exposure checks. No customer counts, incident savings, performance benchmarks or complete-protection claims are available.

## Product Principles

- Show what is working, what is unknown and what needs action separately.
- Keep normal tasks short and progressive; expose diagnostic detail on demand.
- Preserve existing configuration and offer explicit recovery controls.
- Use existing security engines honestly and identify their operational limits.
- Default management access to local authenticated operation.
- Expand platform coverage through verified feature support, shared management and native platform adapters.
