# Quiet Guard

<!-- impeccable:product-schema 1 -->

## Platform

web

The initial management surface is a browser UI on the Linux server's loopback interface, reached remotely through SSH forwarding. This is the working default offered in this session; a separate Windows management app remains an open preference.

## Stack

Existing Rust agent and controllers. The management surface uses embedded HTML/CSS/JavaScript and a Rust HTTP adapter; the privileged controller remains separate from the web process. No third-party web fonts or analytics.

## Users

Solo and small-service developers operating their own Ubuntu server. They need to understand protection state, act on a small set of findings, and recover from configuration failures without becoming security specialists.

## Product Purpose

Connect setup, SSH protection, web request inspection, exposure review and recovery in an understandable workflow. Running software alone must never imply verified protection.

## Operating Context

Ubuntu 24.04 x86_64 first. Existing SSH and Nginx services must be preserved. WAF currently supports a limited apt Nginx HTTP/1.x direct-access profile. Actual external verification is a separate operation; exposure evidence remains operator-supplied.

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
