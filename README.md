# Awesome Supply Chain Security

## Token Protect
- [truffleHog](https://github.com/trufflesecurity/truffleHog) - Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
- [external-secrets](https://github.com/external-secrets/external-secrets) - External Secrets Operator reads information from a third-party service like AWS Secrets Manager and automatically injects the values as Kubernetes Secrets.

## SBOM
- [SPDX](https://github.com/spdx) - SPDX is an open standard for communicating SBOM information, including provenance, license, security, and other related information.
- [CycloneDX](https://github.com/CycloneDX) - OWASP CycloneDX is a lightweight Software Bill of Materials (SBOM) standard designed for use in application security contexts and supply chain component analysis.
- [Tern](https://github.com/tern-tools/tern) - A software package inspection tool that can create a Software Bill of Materials (SBOM) for containers. It's written in Python3 with a smattering of shell scripts.
- [Syft](https://github.com/anchore/syft) - CLI tool and library for generating a Software Bill of Materials from container images and filesystems

## Source Code Analysis
- [Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools) - Static Application Security Testing (SAST) Tools list, can help analyze source code or compiled versions of code to help find security flaws.
- [Go-SCP](https://github.com/OWASP/Go-SCP) - Go language web application secure coding practices.
- [FOSSology](https://github.com/fossology/fossology​) - An open source license compliance software system and toolkit. As a toolkit you can run license, copyright and export control scans from the command line. As a system, a database and web ui are provided to give you a compliance workflow.
- [OpenSCAP](https://github.com/OpenSCAP) - Open Source Security Compliance Solution
- [Scan](https://github.com/ShiftLeftSecurity/sast-scan) - Scan is a free & Open Source DevSecOps tool for performing static analysis based security testing of your applications and its dependencies.
- [trivy](https://github.com/aquasecurity/trivy) - Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues
- [starter-workflows](https://github.com/actions/starter-workflows/tree/main/code-scanning) - GitHub code scanning is a developer-first, GitHub-native approach to easily find security vulnerabilities before they reach production. 
- [CodeQL](https://github.com/github/codeql) - the libraries and queries that power security researchers around the world, as well as code scanning in GitHub Advanced Security (code scanning)
- [DevSkim](https://github.com/microsoft/DevSkim) - DevSkim is a set of IDE plugins and rules that provide security "linting" capabilities.
- [flawfinder](https://github.com/david-a-wheeler/flawfinder) - a static analysis tool for finding vulnerabilities in C/C++ source code
- [kubectl-kubesec](https://github.com/controlplaneio/kubectl-kubesec) - Security risk analysis for Kubernetes resources
- [mobsfscan](https://github.com/MobSF/mobsfscan) - mobsfscan is a static analysis tool that can find insecure code patterns in your Android and iOS source code. Supports Java, Kotlin, Swift, and Objective C Code. 
- [njsscan](https://github.com/ajinabraham/njsscan) - njsscan is a semantic aware SAST tool that can find insecure code patterns in your Node.js applications.
- [tfsec](https://github.com/aquasecurity/tfsec) - Security scanner for your Terraform code


## Container Security Scanners
- [Clair](https://github.com/quay/clair) - Vulnerability Static Analysis for Containers
- [Anchore](https://github.com/anchore/grype/) - A vulnerability scanner for container images and filesystems.
- [Dagda](https://github.com/eliasgranderubio/dagda/) - A tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities
- [Falco](https://github.com/falcosecurity/falco) - Open source cloud native runtime security tool. Falco makes it easy to consume kernel events, and enrich those events with information from Kubernetes and the rest of the cloud native stack. 
- [Aqua Security](https://github.com/aquasecurity) - Scanner for vulnerabilities in container images, provided vulnerability scanning and management for orchestrators like Kubernetes.
- [Docker Bench](https://github.com/docker/docker-bench-security) - The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production. 
- [Harbor](https://goharbor.io/) - It stores, signs, and scans docker images for vulnerabilities. 
- [JFrog Xray](https://jfrog.com/xray/) - Intelligent Supply Chain Security and Compliance at DevOps Speed.
- [Container Security](https://www.qualys.com/apps/container-security/) - Qualys container security is a tool used to discover, track, and continuously protect container environments. 
- [Docker Scan](https://github.com/anchore/grype/) -  Docker Scan leverages Synk engine and capable of scanning local Dockerfile, images, and its dependencies to find known vulnerabilities. You can run docker scan from Docker Desktop.

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
- [Prow](https://github.com/kubernetes/test-infra/tree/master/prow) - Prow is a Kubernetes based CI/CD system. Jobs can be triggered by various types of events and report their status to many different services.
- [jx-git-operator](https://github.com/jenkins-x/jx-git-operator) - An operator which polls a git repository for changes and triggers a Kubernetes Job to process the changes in git.
- [Lighthouse](https://github.com/jenkins-x/lighthouse) - Lighthouse is a lightweight ChatOps based webhook handler which can trigger Jenkins X Pipelines, Tekton Pipelines or Jenkins Jobs based on webhooks from multiple git providers such as GitHub, GitHub Enterprise, BitBucket Server and GitLab.
- [Starter Workflows](https://github.com/actions/starter-workflows) - Workflow files for helping people get started with GitHub Actions.

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
- [SLSA Attestations](https://github.com/slsa-framework/slsa/blob/main/controls/attestations.md) - Standardize the terminology, data model, layers, and conventions for software artifact metadata.
- [scim](https://github.com/microsoft/scim) - Supply Chain Integrity Model
- [Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/sscsp.md)
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
- [Buildpacks](https://github.com/GoogleCloudPlatform/buildpacks) - Providind tooling to transform source code into container images using modular, reusable build functions. 

## Data Store
- [Trillian](https://github.com/google/trillian) - A transparent, highly scalable and cryptographically verifiable data store.
- [Rekor](https://github.com/sigstore/rekor) - Software Supply Chain Transparency Log

## Demo

- [demonstration of SLSA provenance generation strategies](https://github.com/slsa-framework/provenance-architecture-demo) - A demonstration of SLSA provenance generation strategies that don't require full build system integration.
## Document
- [Is your software supply chain secure?](https://blog.convisoappsec.com/en/is-your-software-supply-chain-secure/)
- [Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/sscsp.md)
- [Secure Publication of Datadog Agent Integrations with TUF and in-toto](https://www.datadoghq.com/blog/engineering/secure-publication-of-datadog-agent-integrations-with-tuf-and-in-toto/)
- [The Secure Software Factory is a prototype implementation of the CNCF's Secure Software Factory Reference Architecture which is based on the CNCF's Software Supply Chain Best Practices White Paper](https://github.com/thesecuresoftwarefactory/ssf)
