# Awesome Supply Chain Security

## Token Protect
- [truffleHog](https://github.com/trufflesecurity/truffleHog) - Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.

## Source Code Analysis
- [Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools) - Static Application Security Testing (SAST) Tools list, can help analyze source code or compiled versions of code to help find security flaws.
- [Go-SCP](https://github.com/OWASP/Go-SCP) - Go language web application secure coding practices.
- [SPDX](https://github.com/spdx) - SPDX is an open standard for communicating SBOM information, including provenance, license, security, and other related information.
- [CycloneDX](https://github.com/CycloneDX) - OWASP CycloneDX is a lightweight Software Bill of Materials (SBOM) standard designed for use in application security contexts and supply chain component analysis.
- [Tern](https://github.com/tern-tools/tern) - A software package inspection tool that can create a Software Bill of Materials (SBOM) for containers. It's written in Python3 with a smattering of shell scripts.
- [Syft](https://github.com/anchore/syft) - CLI tool and library for generating a Software Bill of Materials from container images and filesystems
- [FOSSology](https://github.com/fossology/fossology​) - An open source license compliance software system and toolkit. As a toolkit you can run license, copyright and export control scans from the command line. As a system, a database and web ui are provided to give you a compliance workflow.
- [OpenSCAP](https://github.com/OpenSCAP) - Open Source Security Compliance Solution

## Artifact Metadata
- [in-toto](https://github.com/in-toto/in-toto) - An open metadata standard that you can implement in your software's supply chain toolchain.
- [Grafeas](https://github.com/grafeas/grafeas) - An open-source artifact metadata API that provides a uniform way to audit and govern your software supply chain.

## Identity Management
- [Spiffe/Spire](https://spiffe.io/) A universal identity control plane for distributed systems.

## CI/CD
- [Kaniko](https://github.com/GoogleContainerTools/kaniko) - Build container images in Kubernetes.
- [Tektoncd](https://github.com/tektoncd/) - A cloud-native solution for building CI/CD systems.
- [Reproducible Builds](https://reproducible-builds.org/) - Reproducible builds are a set of software development practices that create an independently-verifiable path from source to binary code.
- [Argo](https://argoproj.github.io/) - Open source tools for Kubernetes to run workflows, manage clusters, and do GitOps right.
- [Jenkins](https://www.jenkins.io/) - The leading open source automation server, Jenkins provides hundreds of plugins to support building, deploying and automating any project.
- [Jenkins X](https://github.com/jenkins-x) - CI/CD solution for modern cloud applications on Kubernetes.

## Signing Artefacts
- [cosign](https://github.com/sigstore/cosign) - Container Signing, Verification and Storage in an OCI registry.
- [Fulcio](https://github.com/sigstore/fulcio) - A free Root-CA for code signing certs, issuing certificates based on an OIDC email address.
- [GPG](https://www.gnupg.org/index.html) - GnuPG is a complete and free implementation of the OpenPGP standard, it allows you to encrypt and sign your data and communications; it features a versatile key management system, along with access modules for all kinds of public key directories.
- [python-tuf](https://github.com/theupdateframework/python-tuf) - Python reference implementation of The Update Framework (TUF).
- [go-tuf](https://github.com/theupdateframework/go-tuf) - Go implementation of The Update Framework (TUF).
- [](https://github.com/awslabs/tough) - Rust libraries and tools for using and generating TUF repositories.
- [Notation](https://github.com/notaryproject/notation) - A project to add signatures as standard items in the registry ecosystem, and to build a set of simple tooling for signing and verifying these signatures. 

## Framework
- [SLSA](https://github.com/slsa-framework/slsa) - A security framework, a check-list of standards and controls to prevent tampering, improve integrity, and secure packages and infrastructure in your projects, businesses or enterprises. 
- [Blueprint Secure Software Pipeline](https://github.com/Venafi/blueprint-securesoftwarepipeline) - Blueprint for building modern, secure software development pipelines

## Kubernetes Admission Controller
- [Kyverno](https://github.com/kyverno/kyverno) - A policy engine designed for Kubernetes. It can validate, mutate, and generate configurations using admission controls and background scans. Kyverno policies are Kubernetes resources and do not require learning a new language. Kyverno is designed to work nicely with tools you already use like kubectl, kustomize, and Git.
- [Kritis](https://github.com/grafeas/kritis) - An open-source solution for securing your software supply chain for Kubernetes applications, it enforces deploy-time security policies using the Grafeas API.
- [Open Policy Agent](https://github.com/open-policy-agent/opa) - Open Policy Agent (OPA) is an open source, general-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack.

## Risk Management
- [Scorecard](https://github.com/ossf/scorecard) - Scorecards is an automated tool that assesses a number of important heuristics ("checks") associated with software security and assigns each check a score of 0-10.
- [Open Source Project Criticality Score](https://github.com/ossf/criticality_score) - Gives criticality score for an open source project

## Dependencies Track
- [DependencyTrack](https://github.com/orgs/DependencyTrack/repositories) - Dependency-Track is an intelligent Component Analysis platform that allows organizations to identify and reduce risk in the software supply chain.

## OCI Image Tools
- [Buildah](https://github.com/containers/buildah) - A tool that facilitates building OCI images.
- [Skopeo](https://github.com/containers/skopeo) - Work with remote images registries - retrieving information, images, signing content.
- [go-containerregistry](https://github.com/google/go-containerregistry) - Go library and CLIs for working with container registries

## Data Store
- [Trillian](https://github.com/google/trillian) - A transparent, highly scalable and cryptographically verifiable data store.
- [Rekor](https://github.com/sigstore/rekor) - Software Supply Chain Transparency Log

## Document
- [Is your software supply chain secure?](https://blog.convisoappsec.com/en/is-your-software-supply-chain-secure/)
- [Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/sscsp.md)
- [Secure Publication of Datadog Agent Integrations with TUF and in-toto](https://www.datadoghq.com/blog/engineering/secure-publication-of-datadog-agent-integrations-with-tuf-and-in-toto/)
