# Awesome Software Supply Chain Security

## Glossary

- SBOM: Software Bill of Materials
- SCA: Software Composition Analysis
- SAST: Static Application Security Testing
- IAST: Interactive Application Security Testing
- VCS: Version Control System
- OSPO: Open Source Program Office
- CSPM: Cloud Security Posture Management

## Landscape

- [OSPO Landscape](https://landscape.todogroup.org/) - The OSPO landscape is intended as a map to explore the OSPO Ecosystem in terms of tooling, adopters and involved communities.

## Secret Leakages

- [truffleHog](https://github.com/trufflesecurity/truffleHog) - ![GitHub stars](https://img.shields.io/github/stars/trufflesecurity/truffleHog?style=flat-square) - Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
- [external-secrets](https://github.com/external-secrets/external-secrets) - ![GitHub stars](https://img.shields.io/github/stars/external-secrets/external-secrets?style=flat-square) - External Secrets Operator reads information from a third-party service like AWS Secrets Manager and automatically injects the values as Kubernetes Secrets.
- [Gitleaks](https://github.com/zricethezav/gitleaks) - ![GitHub stars](https://img.shields.io/github/stars/zricethezav/gitleaks?style=flat-square) - Gitleaks is a SAST tool for detecting and preventing hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an easy-to-use, all-in-one solution for detecting secrets, past or present, in your code.
- [SecLists](https://github.com/danielmiessler/SecLists) - ![GitHub stars](https://img.shields.io/github/stars/danielmiessler/SecLists?style=flat-square) - SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.

## Software Bill of Materials

- [SPDX](https://github.com/spdx) - SPDX is an open standard for communicating SBOM information, including provenance, license, security, and other related information.
- [CycloneDX](https://github.com/CycloneDX) - OWASP CycloneDX is a lightweight Software Bill of Materials (SBOM) standard designed for use in application security contexts and supply chain component analysis.
- [Tern](https://github.com/tern-tools/tern) - ![GitHub stars](https://img.shields.io/github/stars/tern-tools/tern?style=flat-square) - A software package inspection tool that can create a Software Bill of Materials (SBOM) for containers. It's written in Python3 with a smattering of shell scripts.
- [Syft](https://github.com/anchore/syft) - ![GitHub stars](https://img.shields.io/github/stars/anchore/syft?style=flat-square) - CLI tool and library for generating a Software Bill of Materials from container images and filesystems.
- [bom](https://github.com/kubernetes-sigs/bom) - ![GitHub stars](https://img.shields.io/github/stars/kubernetes-sigs/bom?style=flat-square) - A utility to generate SPDX-compliant Bill of Materials manifests
- [ko](https://github.com/google/ko) - ![GitHub stars](https://img.shields.io/github/stars/google/ko?style=flat-square) - Build and deploy Go applications on Kubernetes, support generate upload SBOM etc.
- [sbom-tool](https://github.com/microsoft/sbom-tool) - ![GitHub stars](https://img.shields.io/github/stars/microsoft/sbom-tool?style=flat-square) - Microsoft's SBOM tool is a highly scalable and enterprise ready tool to create SPDX 2.2 compatible SBOMs for any variety of artifacts.
- [spdx-sbom-generator](https://github.com/opensbom-generator/spdx-sbom-generator) - ![GitHub stars](https://img.shields.io/github/stars/opensbom-generator/spdx-sbom-generator?style=flat-square) - Support CI generation of SBOMs via golang tooling

## Software Composition Analysis

- [Open Source Insights](https://deps.dev/) - Open Source Insights is an experimental service developed and hosted by Google to help developers better understand the structure, construction, and security of open source software packages.
- [DependencyTrack](https://github.com/DependencyTrack/dependency-track) - ![GitHub stars](https://img.shields.io/github/stars/DependencyTrack/dependency-track?style=flat-square) - Dependency-Track is an intelligent Component Analysis platform that allows organizations to identify and reduce risk in the software supply chain.
- [DependencyCheck](https://github.com/jeremylong/DependencyCheck) - ![GitHub stars](https://img.shields.io/github/stars/jeremylong/DependencyCheck?style=flat-square) - OWASP dependency-check is a software composition analysis utility that detects publicly disclosed vulnerabilities in application dependencies.
- [scancode-toolkit](https://github.com/nexB/scancode-toolkit) - ![GitHub stars](https://img.shields.io/github/stars/nexB/scancode-toolkit?style=flat-square) - ScanCode detects licenses, copyrights, package manifests & dependencies and more by scanning code ... to discover and inventory open source and third-party packages used in your code.
- [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort) - ![GitHub stars](https://img.shields.io/github/stars/oss-review-toolkit/ort?style=flat-square) - The OSS Review Toolkit (ORT) aims to assist with the tasks that commonly need to be performed in the context of license compliance checks, especially for (but not limited to) Free and Open Source Software dependencies.
- [License Finder](https://github.com/pivotal/LicenseFinder) - ![GitHub stars](https://img.shields.io/github/stars/pivotal/LicenseFinder?style=flat-square) - LicenseFinder works with package managers to find dependencies, detect the licenses of the packages in them, compare those licenses against a user-defined list of permitted licenses.
- [go-licenses](https://github.com/google/go-licenses) - ![GitHub stars](https://img.shields.io/github/stars/google/go-licenses?style=flat-square) - Analyzes the dependency tree of a Go package/binary. It can output a report on the libraries used and under what license they can be used. It can also collect all of the license documents, copyright notices and source code into a directory in order to comply with license terms on redistribution.
- [Anchore](https://github.com/anchore/grype/) - ![GitHub stars](https://img.shields.io/github/stars/anchore/grype?style=flat-square) - A vulnerability scanner for container images and filesystems.
- [OpenSCA-Cli](https://github.com/XmirrorSecurity/OpenSCA-cli) - ![GitHub stars](https://img.shields.io/github/stars/XmirrorSecurity/OpenSCA-cli?style=flat-square) - OpenSCA is now capable of parsing configuration files in the listed programming languages and correspondent package managers.
- [MurphySec CLI](https://github.com/murphysecurity/murphysec) - ![GitHub stars](https://img.shields.io/github/stars/murphysecurity/murphysec?style=flat-square) - MurphySec CLI is used for detecting vulnerable dependencies from the command-line, and also can be integrated into your CI/CD pipeline.
- [Gemnasium](https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium) - Dependency Scanning analyzer that uses the GitLab Advisory Database.
- [reuse-tool](https://github.com/fsfe/reuse-tool) - ![GitHub stars](https://img.shields.io/github/stars/fsfe/reuse-tool?style=flat-square) - The tool for checking and helping with compliance with the REUSE recommendations
- [lgtm](https://lgtm.com/) - A code analysis platform for finding zero-days and preventing critical vulnerabilities

## Static Application Security Testing

- [trivy](https://github.com/aquasecurity/trivy) - ![GitHub stars](https://img.shields.io/github/stars/aquasecurity/trivy?style=flat-square) - Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues.
- [Horusec](https://github.com/ZupIT/horusec) - ![GitHub stars](https://img.shields.io/github/stars/ZupIT/horusec?style=flat-square) - Horusec is an open source tool that improves identification of vulnerabilities in your project with just one command.
- [Semgrep](https://github.com/returntocorp/semgrep) - ![GitHub stars](https://img.shields.io/github/stars/returntocorp/semgrep?style=flat-square) - Lightweight static analysis for many languages. Find bug variants with patterns that look like source code.
- [Scan](https://github.com/ShiftLeftSecurity/sast-scan) - ![GitHub stars](https://img.shields.io/github/stars/ShiftLeftSecurity/sast-scan?style=flat-square) - Scan is a free & Open Source DevSecOps tool for performing static analysis based security testing of your applications and its dependencies.
- [starter-workflows](https://github.com/actions/starter-workflows/tree/main/code-scanning) - GitHub code scanning is a developer-first, GitHub-native approach to easily find security vulnerabilities before they reach production.
- [CodeQL](https://github.com/github/codeql) - ![GitHub stars](https://img.shields.io/github/stars/github/codeql?style=flat-square) - the libraries and queries that power security researchers around the world, as well as code scanning in GitHub Advanced Security (code scanning)
- [DevSkim](https://github.com/microsoft/DevSkim) - ![GitHub stars](https://img.shields.io/github/stars/microsoft/DevSkim?style=flat-square) - DevSkim is a set of IDE plugins and rules that provide security "linting" capabilities.
- [flawfinder](https://github.com/david-a-wheeler/flawfinder) - ![GitHub stars](https://img.shields.io/github/stars/david-a-wheeler/flawfinder?style=flat-square) - a static analysis tool for finding vulnerabilities in C/C++ source code.
- [kubectl-kubesec](https://github.com/controlplaneio/kubectl-kubesec) - ![GitHub stars](https://img.shields.io/github/stars/controlplaneio/kubectl-kubesec?style=flat-square) - Security risk analysis for Kubernetes resources.
- [mobsfscan](https://github.com/MobSF/mobsfscan) - ![GitHub stars](https://img.shields.io/github/stars/MobSF/mobsfscan?style=flat-square) - mobsfscan is a static analysis tool that can find insecure code patterns in your Android and iOS source code. Supports Java, Kotlin, Swift, and Objective C Code.
- [njsscan](https://github.com/ajinabraham/njsscan) - ![GitHub stars](https://img.shields.io/github/stars/ajinabraham/njsscan?style=flat-square) - njsscan is a semantic aware SAST tool that can find insecure code patterns in your Node.js applications.
- [tfsec](https://github.com/aquasecurity/tfsec) - ![GitHub stars](https://img.shields.io/github/stars/aquasecurity/tfsec?style=flat-square) - Security scanner for your Terraform code.
- [insider](https://github.com/insidersec/insider) - ![GitHub stars](https://img.shields.io/github/stars/insidersec/insider?style=flat-square) - SAST Engine focused on covering the OWASP Top 10, support Java (Maven and Android), Kotlin (Android), Swift (iOS), .NET Ful...
- [SpotBugs](https://github.com/spotbugs/spotbugs) - ![GitHub stars](https://img.shields.io/github/stars/spotbugs/spotbugs?style=flat-square) - SpotBugs is FindBugs' successor. A tool for static analysis to look for bugs in Java code.
- [Find Security Bugs](https://github.com/find-sec-bugs/find-sec-bugs) - ![GitHub stars](https://img.shields.io/github/stars/find-sec-bugs/find-sec-bugs?style=flat-square) - The SpotBugs plugin for security audits of Java web applications and Android applications.
- [go-license-detector](https://github.com/src-d/go-license-detector) - ![GitHub stars](https://img.shields.io/github/stars/src-d/go-license-detector?style=flat-square) - a command line application and a library, written in Go. It scans the given directory for license files, normalizes and hashes them and outputs all the fuzzy matches with the list of reference texts.
- [askalono](https://github.com/jpeddicord/askalono) - ![GitHub stars](https://img.shields.io/github/stars/jpeddicord/askalono?style=flat-square) - askalono is a library and command-line tool to help detect license texts. It's designed to be fast, accurate, and to support a wide variety of license texts.
- [licensechecker](https://github.com/boyter/lc) - ![GitHub stars](https://img.shields.io/github/stars/boyter/lc?style=flat-square) - licensechecker (lc) a command line application which scans directories and identifies what software license things are under producing reports as either SPDX, CSV, JSON, XLSX or CLI Tabular output. Dual-licensed under MIT or the UNLICENSE.
- [licensee](https://github.com/licensee/licensee) - ![GitHub stars](https://img.shields.io/github/stars/licensee/licensee?style=flat-square) - A Ruby Gem to detect under what license a project is distributed.
- [licenseclassifier](https://github.com/google/licenseclassifier) - ![GitHub stars](https://img.shields.io/github/stars/google/licenseclassifier?style=flat-square) - The license classifier is a library and set of tools that can analyze text to determine what type of license it contains. It searches for license texts in a file and compares them to an archive of known licenses.
- [licensed](https://github.com/github/licensed) - ![GitHub stars](https://img.shields.io/github/stars/github/licensed?style=flat-square) - A Ruby gem to cache and verify the licenses of dependencies

## Infrastructure as Code Secure

- [kics](https://github.com/Checkmarx/kics) - ![GitHub stars](https://img.shields.io/github/stars/Checkmarx/kics?style=flat-square) - Find security vulnerabilities, compliance issues, and infrastructure misconfigurations early in the development cycle of your infrastructure-as-code.
- [Checkov](https://github.com/bridgecrewio/checkov) - ![GitHub stars](https://img.shields.io/github/stars/bridgecrewio/checkov?style=flat-square) - Prevent cloud misconfigurations during build-time for Terraform, CloudFormation, Kubernetes, Serverless framework and other infrastructure-as-code-languages with Checkov by Bridgecrew.

## Cloud Security Posture Management

- [nuclei](https://github.com/projectdiscovery/nuclei) - ![GitHub stars](https://img.shields.io/github/stars/projectdiscovery/nuclei?style=flat-square) - Nuclei is used to send requests across targets based on a template, leading to zero false positives and providing fast scanning on a large number of hosts. Nuclei offers scanning for a variety of protocols, including TCP, DNS, HTTP, SSL, File, Whois, Websocket, Headless etc.
- [RiskScanner](https://github.com/fit2cloud/riskscanner) - ![GitHub stars](https://img.shields.io/github/stars/fit2cloud/riskscanner?style=flat-square) - RiskScanner is an open source multi-cloud security compliance scanning platform, Based on Cloud Custodian, Prowler and Nuclei engines, it realizes security compliance scanning and vulnerability scanning of mainstream public (private) cloud resources.
- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) - ![GitHub stars](https://img.shields.io/github/stars/DefectDojo/django-DefectDojo?style=flat-square) - A security orchestration and vulnerability management platform.

## Anti-malware Engine

- [ClamAV](https://github.com/Cisco-Talos/clamav) - ![GitHub stars](https://img.shields.io/github/stars/Cisco-Talos/clamav?style=flat-square) - ClamAV is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats.

## Container Security Scanners

- [Clair](https://github.com/quay/clair) - ![GitHub stars](https://img.shields.io/github/stars/quay/clair?style=flat-square) - Vulnerability Static Analysis for Containers
- [Anchore](https://github.com/anchore/grype/) - ![GitHub stars](https://img.shields.io/github/stars/anchore/grype?style=flat-square) - A vulnerability scanner for container images and filesystems.
- [Dagda](https://github.com/eliasgranderubio/dagda/) - ![GitHub stars](https://img.shields.io/github/stars/eliasgranderubio/dagda?style=flat-square) - A tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities
- [Falco](https://github.com/falcosecurity/falco) - ![GitHub stars](https://img.shields.io/github/stars/falcosecurity/falco?style=flat-square) - Open source cloud native runtime security tool. Falco makes it easy to consume kernel events, and enrich those events with information from Kubernetes and the rest of the cloud native stack.
- [Aqua Security](https://github.com/aquasecurity) - Scanner for vulnerabilities in container images, provided vulnerability scanning and management for orchestrators like Kubernetes.
- [Docker Bench](https://github.com/docker/docker-bench-security) - ![GitHub stars](https://img.shields.io/github/stars/docker/docker-bench-security?style=flat-square) - The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production.
- [Harbor](https://goharbor.io/) - It stores, signs, and scans docker images for vulnerabilities.
- [JFrog Xray](https://jfrog.com/xray/) - Intelligent Supply Chain Security and Compliance at DevOps Speed.
- [Container Security](https://www.qualys.com/apps/container-security/) - Qualys container security is a tool used to discover, track, and continuously protect container environments.
- [Docker Scan](https://github.com/docker/scan-cli-plugin) - ![GitHub stars](https://img.shields.io/github/stars/docker/scan-cli-plugin?style=flat-square) - Docker Scan leverages Synk engine and capable of scanning local Dockerfile, images, and its dependencies to find known vulnerabilities. You can run docker scan from Docker Desktop.

## Vulnerabilities Database & Tools

- [National Vulnerability Database](https://nvd.nist.gov/) - The NVD is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP).
- [NVD Tools](https://github.com/facebookincubator/nvdtools) - ![GitHub stars](https://img.shields.io/github/stars/facebookincubator/nvdtools?style=flat-square) - A set of tools to work with the feeds (vulnerabilities, CPE dictionary etc.) distributed by National Vulnerability Database (NVD)
- [CVE Details](https://www.cvedetails.com/) - CVE Details provides an easy to use web interface to CVE vulnerability data.
- [Exploit Database Online](https://www.exploit-db.com/) - The Exploit Database is the most comprehensive collection of public exploits and corresponding vulnerable software, developed for use by penetration testers and vulnerability researchers.
- [Exploit Database Offline](https://github.com/offensive-security/exploitdb) - ![GitHub stars](https://img.shields.io/github/stars/offensive-security/exploitdb?style=flat-square) - The official Exploit Database repository.
- [VulnDB Data Mirror](https://github.com/stevespringett/vulndb-data-mirror) - ![GitHub stars](https://img.shields.io/github/stars/stevespringett/vulndb-data-mirror?style=flat-square) - A simple Java command-line utility to mirror the entire contents of VulnDB.
- [NIST Data Mirror](https://github.com/stevespringett/nist-data-mirror) - ![GitHub stars](https://img.shields.io/github/stars/stevespringett/nist-data-mirror?style=flat-square) - A simple Java command-line utility to mirror the CVE JSON data from NIST.
- [Snyk Vulnerability Database](https://security.snyk.io/vuln) - Snyk Vulnerability Database.
- [Vuldb](https://vuldb.com/) - Vulnerability database documenting and explaining security vulnerabilities, threats, and exploits since 1970.
- [osv](https://github.com/google/osv) - ![GitHub stars](https://img.shields.io/github/stars/google/osv?style=flat-square) - Open source vulnerability DB and triage service.
- [advisory-database](https://github.com/github/advisory-database) - ![GitHub stars](https://img.shields.io/github/stars/github/advisory-database?style=flat-square) - Security vulnerability database inclusive of CVEs and GitHub originated security advisories from the world of open source software.
- [golang/vulndb](https://github.com/golang/vulndb) - ![GitHub stars](https://img.shields.io/github/stars/golang/vulndb?style=flat-square) - The Go Vulnerability Database
- [pypa/advisory-database](https://github.com/pypa/advisory-database) - ![GitHub stars](https://img.shields.io/github/stars/pypa/advisory-database?style=flat-square) - Advisory database for Python packages published on pypi.org
- [RustSec/advisory-db](https://github.com/RustSec/advisory-db) - ![GitHub stars](https://img.shields.io/github/stars/RustSec/advisory-db?style=flat-square) - Security advisory database for Rust crates published through crates.io
- [gsd-database](https://github.com/cloudsecurityalliance/gsd-database) - ![GitHub stars](https://img.shields.io/github/stars/cloudsecurityalliance/gsd-database?style=flat-square) - The Global Security Database (GSD) is a new Working Group project from the Cloud Security Alliance meant to address the gaps in the current vulnerability identifier space.
- [oss-fuzz-vulns](https://github.com/google/oss-fuzz-vulns) - ![GitHub stars](https://img.shields.io/github/stars/google/oss-fuzz-vulns?style=flat-square) - OSS-Fuzz vulnerabilities for OSV.
- [vuln-list](https://github.com/aquasecurity/vuln-list) - ![GitHub stars](https://img.shields.io/github/stars/aquasecurity/vuln-list?style=flat-square) - Collect vulnerability information and save it in parsable format automatically.
- [CVE PoC](https://github.com/trickest/cve) - ![GitHub stars](https://img.shields.io/github/stars/trickest/cve?style=flat-square) - Gather and update all available and newest CVEs with their PoC.
- [CVE List](https://github.com/CVEProject/cvelist) - ![GitHub stars](https://img.shields.io/github/stars/CVEProject/cvelist?style=flat-square) - The CVE Automation Working Group is piloting use of git to share information about public vulnerabilities.
- [cve-ark](https://github.com/goncalor/cve-ark) - ![GitHub stars](https://img.shields.io/github/stars/goncalor/cve-ark?style=flat-square) - All published CVE and their recent changes, ready to be used by humans and machines.

## Artifact Metadata

- [in-toto](https://github.com/in-toto/in-toto) - ![GitHub stars](https://img.shields.io/github/stars/in-toto/in-toto?style=flat-square) - An open metadata standard that you can implement in your software's supply chain toolchain.
- [Grafeas](https://github.com/grafeas/grafeas) - ![GitHub stars](https://img.shields.io/github/stars/grafeas/grafeas?style=flat-square) - An open-source artifact metadata API that provides a uniform way to audit and govern your software supply chain.
- [tkn-intoto-formatter](https://github.com/OpenSecureSupplyChain/tkn-intoto-formatter) - ![GitHub stars](https://img.shields.io/github/stars/OpenSecureSupplyChain/tkn-intoto-formatter?style=flat-square) - A common library to convert any tekton resource to intoto attestation format.

## Identity Tools

- [Spiffe/Spire](https://spiffe.io/) A universal identity control plane for distributed systems.
- [SWID](https://www.ietf.org/archive/id/draft-ietf-sacm-coswid-18.html) - Software Identification (SWID) tags provide an extensible XML-based structure to identify and describe individual software components, patches, and installation bundles.
- [purl](https://github.com/package-url/purl-spec) - ![GitHub stars](https://img.shields.io/github/stars/package-url/purl-spec?style=flat-square) - A purl is a URL string used to identify and locate a software package in a mostly universal and uniform way across programing languages, package managers, packaging conventions, tools, APIs and databases.
- [Grafeas](https://github.com/grafeas/grafeas) - ![GitHub stars](https://img.shields.io/github/stars/grafeas/grafeas?style=flat-square) - Grafeas defines an API spec for managing metadata about software resources, such as container images, Virtual Machine (VM) images, JAR files, and scripts.
- [CIRCL hashlookup](https://www.circl.lu/services/hashlookup/) - CIRCL hash lookup is a public API to lookup hash values against known database of files.
- [Dex](https://github.com/dexidp/dex) - ![GitHub stars](https://img.shields.io/github/stars/dexidp/dex?style=flat-square) - Dex is an identity service that uses OpenID Connect to drive authentication for other apps.

## CI/CD

- [Kaniko](https://github.com/GoogleContainerTools/kaniko) - ![GitHub stars](https://img.shields.io/github/stars/GoogleContainerTools/kaniko?style=flat-square) - Build container images in Kubernetes.
- [BuildKit](https://github.com/moby/buildkit) - ![GitHub stars](https://img.shields.io/github/stars/moby/buildkit?style=flat-square) - concurrent, cache-efficient, and Dockerfile-agnostic builder toolkit
- [Tektoncd](https://github.com/tektoncd/) - A cloud-native solution for building CI/CD systems.
- [Reproducible Builds](https://reproducible-builds.org/) - Reproducible builds are a set of software development practices that create an independently-verifiable path from source to binary code.
- [Argo](https://argoproj.github.io/) - Open source tools for Kubernetes to run workflows, manage clusters, and do GitOps right.
- [Jenkins](https://www.jenkins.io/) - The leading open source automation server, Jenkins provides hundreds of plugins to support building, deploying and automating any project.
- [Jenkins X](https://github.com/jenkins-x) - CI/CD solution for modern cloud applications on Kubernetes.
- [Prow](https://github.com/kubernetes/test-infra/tree/master/prow) - ![GitHub stars](https://img.shields.io/github/stars/kubernetes/test-infra?style=flat-square) - Prow is a Kubernetes based CI/CD system. Jobs can be triggered by various types of events and report their status to many different services.
- [jx-git-operator](https://github.com/jenkins-x/jx-git-operator) - ![GitHub stars](https://img.shields.io/github/stars/jenkins-x/jx-git-operator?style=flat-square) - An operator which polls a git repository for changes and triggers a Kubernetes Job to process the changes in git.
- [Lighthouse](https://github.com/jenkins-x/lighthouse) - ![GitHub stars](https://img.shields.io/github/stars/jenkins-x/lighthouse?style=flat-square) - Lighthouse is a lightweight ChatOps based webhook handler which can trigger Jenkins X Pipelines, Tekton Pipelines or Jenkins Jobs based on webhooks from multiple git providers such as GitHub, GitHub Enterprise, BitBucket Server and GitLab.
- [Starter Workflows](https://github.com/actions/starter-workflows) - ![GitHub stars](https://img.shields.io/github/stars/actions/starter-workflows?style=flat-square) - Workflow files for helping people get started with GitHub Actions.
- [ko](https://github.com/google/ko) - ![GitHub stars](https://img.shields.io/github/stars/google/ko?style=flat-square) - Build and deploy Go applications on Kubernetes

## Signing Artefacts

- [cosign](https://github.com/sigstore/cosign) - ![GitHub stars](https://img.shields.io/github/stars/sigstore/cosign?style=flat-square) - Container Signing, Verification and Storage in an OCI registry.
- [Fulcio](https://github.com/sigstore/fulcio) - ![GitHub stars](https://img.shields.io/github/stars/sigstore/fulcio?style=flat-square) - A free Root-CA for code signing certs, issuing certificates based on an OIDC email address.
- [GPG](https://www.gnupg.org/index.html) - GnuPG is a complete and free implementation of the OpenPGP standard, it allows you to encrypt and sign your data and communications; it features a versatile key management system, along with access modules for all kinds of public key directories.
- [python-tuf](https://github.com/theupdateframework/python-tuf) - ![GitHub stars](https://img.shields.io/github/stars/theupdateframework/python-tuf?style=flat-square) - Python reference implementation of The Update Framework (TUF).
- [go-tuf](https://github.com/theupdateframework/go-tuf) - ![GitHub stars](https://img.shields.io/github/stars/theupdateframework/go-tuf?style=flat-square) - Go implementation of The Update Framework (TUF).
- [](https://github.com/awslabs/tough) - ![GitHub stars](https://img.shields.io/github/stars/awslabs/tough?style=flat-square) - Rust libraries and tools for using and generating TUF repositories.
- [Notation](https://github.com/notaryproject/notation) - ![GitHub stars](https://img.shields.io/github/stars/notaryproject/notation?style=flat-square) - A project to add signatures as standard items in the registry ecosystem, and to build a set of simple tooling for signing and verifying these signatures.
- [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) - ![GitHub stars](https://img.shields.io/github/stars/sigstore/k8s-manifest-sigstore?style=flat-square) - kubectl plugin for signing Kubernetes manifest YAML files with sigstore

## Framework

- [SLSA](https://github.com/slsa-framework/slsa) - ![GitHub stars](https://img.shields.io/github/stars/slsa-framework/slsa?style=flat-square) - A security framework, a check-list of standards and controls to prevent tampering, improve integrity, and secure packages and infrastructure in your projects, businesses or enterprises.
- [SCIM](https://github.com/microsoft/scim) - ![GitHub stars](https://img.shields.io/github/stars/microsoft/scim?style=flat-square) - The proposed SCIM will be an industry standard specification, easing the path for uniform data flow across globally distributed supply chains.
- [Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/sscsp.md) - ![GitHub stars](https://img.shields.io/github/stars/cncf/tag-security?style=flat-square) - CNCF provide a comprehensive software supply chain paper highlighting best practices for high and medium risk environments.
- [Blueprint Secure Software Pipeline](https://github.com/Venafi/blueprint-securesoftwarepipeline) - ![GitHub stars](https://img.shields.io/github/stars/Venafi/blueprint-securesoftwarepipeline?style=flat-square) - Blueprint for building modern, secure software development pipelines
- [Witness](https://github.com/testifysec/witness) - ![GitHub stars](https://img.shields.io/github/stars/testifysec/witness?style=flat-square) - Witness is a pluggable framework for software supply chain risk management. It automates, normalizes, and verifies software artifact providence.

## Kubernetes Admission Controller

- [Kyverno](https://github.com/kyverno/kyverno) - ![GitHub stars](https://img.shields.io/github/stars/kyverno/kyverno?style=flat-square) - A policy engine designed for Kubernetes. It can validate, mutate, and generate configurations using admission controls and background scans. Kyverno policies are Kubernetes resources and do not require learning a new language. Kyverno is designed to work nicely with tools you already use like kubectl, kustomize, and Git.
- [Kritis](https://github.com/grafeas/kritis) - ![GitHub stars](https://img.shields.io/github/stars/grafeas/kritis?style=flat-square) - An open-source solution for securing your software supply chain for Kubernetes applications, it enforces deploy-time security policies using the Grafeas API.
- [Open Policy Agent](https://github.com/open-policy-agent/opa) - ![GitHub stars](https://img.shields.io/github/stars/open-policy-agent/opa?style=flat-square) - Open Policy Agent (OPA) is an open source, general-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack.
- [Ratify](https://github.com/deislabs/ratify) - ![GitHub stars](https://img.shields.io/github/stars/deislabs/ratify?style=flat-square) - The project provides a framework to integrate scenarios that require verification of reference artifacts and provides a set of interfaces that can be consumed by various systems that can participate in artifact ratification.

## Risk Management

- [Scorecard](https://github.com/ossf/scorecard) - ![GitHub stars](https://img.shields.io/github/stars/ossf/scorecard?style=flat-square) - Scorecards is an automated tool that assesses a number of important heuristics ("checks") associated with software security and assigns each check a score of 0-10.
- [Open Source Project Criticality Score](https://github.com/ossf/criticality_score) - ![GitHub stars](https://img.shields.io/github/stars/ossf/criticality_score?style=flat-square) - Gives criticality score for an open source project
- [allstar](https://github.com/ossf/allstar) - ![GitHub stars](https://img.shields.io/github/stars/ossf/allstar?style=flat-square) - GitHub App to set and enforce security policies

## OCI Image Tools

- [Buildah](https://github.com/containers/buildah) - ![GitHub stars](https://img.shields.io/github/stars/containers/buildah?style=flat-square) - A tool that facilitates building OCI images.
- [Skopeo](https://github.com/containers/skopeo) - ![GitHub stars](https://img.shields.io/github/stars/containers/skopeo?style=flat-square) - Work with remote images registries - retrieving information, images, signing content.
- [go-containerregistry](https://github.com/google/go-containerregistry) - ![GitHub stars](https://img.shields.io/github/stars/google/go-containerregistry?style=flat-square) - Go library and CLIs for working with container registries
- [Buildpacks](https://github.com/GoogleCloudPlatform/buildpacks) - ![GitHub stars](https://img.shields.io/github/stars/GoogleCloudPlatform/buildpacks?style=flat-square) - Providind tooling to transform source code into container images using modular, reusable build functions.

## Data Store

- [Trillian](https://github.com/google/trillian) - ![GitHub stars](https://img.shields.io/github/stars/google/trillian?style=flat-square) - A transparent, highly scalable and cryptographically verifiable data store.
- [Rekor](https://github.com/sigstore/rekor) - ![GitHub stars](https://img.shields.io/github/stars/sigstore/rekor?style=flat-square) - Software Supply Chain Transparency Log
- [ORAS](https://oras.land/) - Registries are evolving as generic artifact stores. To enable this goal, the ORAS project provides a way to push and pull OCI Artifacts to and from OCI Registries.

## Fuzz Testing

- [OSS-Fuzz](https://github.com/google/oss-fuzz) - ![GitHub stars](https://img.shields.io/github/stars/google/oss-fuzz?style=flat-square) - OSS-Fuzz - continuous fuzzing for open source software.

## Demo

- [ssf](https://github.com/thesecuresoftwarefactory/ssf) - ![GitHub stars](https://img.shields.io/github/stars/thesecuresoftwarefactory/ssf?style=flat-square) - Prototype implementation of the CNCF's Software Supply Chain Best Practices White Paper
- [demonstration of SLSA provenance generation strategies](https://github.com/slsa-framework/provenance-architecture-demo) - ![GitHub stars](https://img.shields.io/github/stars/slsa-framework/provenance-architecture-demo?style=flat-square) - A demonstration of SLSA provenance generation strategies that don't require full build system integration.
