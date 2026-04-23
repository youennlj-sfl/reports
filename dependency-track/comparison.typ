/*
notes:
- container long to start, downloads and parses nvd database on first startup
  - 1h30 wait before everything completed, podman crashed
```
8d0e67d51ee1 2026-04-15 10:07:15,202 INFO [NistMirrorTask] NIST mirroring complete
8d0e67d51ee1 2026-04-15 10:07:15,203 INFO [NistMirrorTask] Time spent (d/l):   14163ms
8d0e67d51ee1 2026-04-15 10:07:15,204 INFO [NistMirrorTask] Time spent (parse): 3603534ms
8d0e67d51ee1 2026-04-15 10:07:15,204 INFO [NistMirrorTask] Time spent (total): 4284186ms
...
8d0e67d51ee1 2026-04-15 10:43:34,237 INFO [EpssMirrorTask] EPSS mirroring complete
8d0e67d51ee1 2026-04-15 10:43:34,239 INFO [EpssMirrorTask] Time spent (d/l):   784ms
8d0e67d51ee1 2026-04-15 10:43:34,239 INFO [EpssMirrorTask] Time spent (parse): 2178098ms
8d0e67d51ee1 2026-04-15 10:43:34,239 INFO [EpssMirrorTask] Time spent (total): 2179020ms
```
- no way to import spdx.tar.zst
- only supports CycloneDX -> requires extra layer for Yocto
  - no filtering on compiled vulnerabilities --- ongoing in iris-GmbH fork
  - does not skip CVEs with backported patches (get_patched_cves method of poky cve_check library) --- fixed in iris-GmbH fork
- "exploit prediction" tab that contains a graph that maps EPSS to CVSS
- made to be deployed somewhere and accessed by multiple people
  - user management
  - gigantic DB
- interesting "policies" system, similar to "fail conditions" in VulnScout
  - conditions less complex than VulnScout
  - allows to view only vulnerabilities that trigger the policy for easy reviewing
  - displays the amount of vulnerabilities that trigger the policy in an easy-to-see place
  - suggestion for VS: store the fail condition in the DB and evaluate them outside of the CI mode
*/

#import "@preview/subpar:0.2.2"

// Styling:
#show raw.where(block: false): box.with(fill: luma(90%), outset: (x: .15em, y: .25em), radius: 2pt)
#show raw.where(block: true): set block(fill: luma(95%), inset: .5em, radius: 4pt)
#show ref: underline

#set page(numbering: "1/1", header: text(fill: luma(50%))[Savoir-faire Linux #h(1fr) Youenn Le Jeune])
#set heading(numbering: "1.")
#set par(justify: true, first-line-indent: 1em)

// Aliases for conciseness:
#let VS = "VulnScout"
#let DT = "Dependency-Track"

#set document(author: "Youenn Le Jeune", title: [Yocto vulnerability assessment:\ #VS or #DT?])

#align(center, title())

Yocto-based projects are huge software projects that have huge dependency trees and that can have hundreds or thousands of vulnerabilities. Assessing them is crucial (and soon to be mandatory in Europe#footnote(link("https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act"))). There are several software solutions available for vulnerability assessment and this paper will compare 2 of them: #VS@vulnscout developed by Savoir-Faire Linux and #DT@dependencytrack developed by the OWASP Foundation. The comparison will especially focus on differences that matter for Yocto@yoctoproject based projects.

= Design philosophies
Both tools have a fundamental design difference: #DT is made to be deployed on a server in a company's infrastructure and is to be used by multiple people. It can be deployed once and centralize all projects of the company in a single place. #VS is very different: it is made to be ran on the user's machine only for the duration of its use and to be stopped afterwards.

This design difference is obvious when you look at the out-of-box experience: to launch #VS, all you have to do is clone the repository, run `./vulnscout --serve` and wait a few seconds. To start #DT, you have to download a Docker Compose file, run it then wait dozens of minutes for the databases to be mirrored (when testing it to write this report, it took a whole 1h30m). Then you'll have to set-up administrative credentials, and finally you'll be able to access the application.

This difference alone can already contribute to the choice of assessment tool: for instance, when you only have to do assessments once every few months for a few small to medium projects, it might not be worth it to deploy a #DT instance. #VS can perfectly handle that. Another example would be an open-source project: if you want your external contributors or end users to be able to completely reproduce the build workflow, from the source fetch to the vulnerability assessment on the build artifacts, you'll have to either give access to your #DT instance (which might not be possible) or require external users to install it themselves (which is cumbersome as we saw earlier). #VS is better suited for this. Now, if you handle several big, closed source projects and you need to constantly keep a global view on the vulnerabilities, it might be better to deploy #DT at your company and centralize your projects there.


= Features comparison
== SBOM formats <section:sbom>
#DT historically supported SPDX2 as an import format but it has been removed for political and technical reasons#footnote(link("https://github.com/DependencyTrack/dependency-track/discussions/1222")). While SPDX3 support is being considered#footnote(link("https://github.com/DependencyTrack/dependency-track/issues/1746")), as of now, #DT can only import CycloneDX SBOM and VEX files (see @fig:dt:bom-formats). It never supported the OpenVEX format #footnote(link("https://github.com/DependencyTrack/dependency-track/issues/4862#issuecomment-2820847602")). This is unfortunate since Yocto can natively output SBOM as SPDX2 and/or SPDX3 files (depending on the Yocto version) and CVE statuses as OpenVEX files. While there are some ways to circumvent this issue, they are not perfect:
- Some tools allow to convert SPDX files to CycloneDX files. However, they usually loose quite a lot of information.
- iris-GmbH maintains _meta-cyclonedx_ @meta-cyclonedx as a way to export CycloneDX files from Yocto. However, they do not contain as much data as the SPDX files natively generated by Yocto: for instance, there is no way to export the list of compiled files that would allow to filter out a lot of Linux Kernel vulnerabilities (but some work seems to be ongoing in a forked repository#footnote(link("https://github.com/iris-GmbH/meta-cyclonedx/issues/53"))).

#figure(
  image("assets/dt-bom-formats.png", width: 85%),
  caption: [#DT "BOM Formats" configuration page showing only CycloneDX],
  placement: auto,
) <fig:dt:bom-formats>

On the contrary, #VS support a lot of SBOM formats: SPDX2 (both individual JSON files and archive files produced by Yocto Scarthgap), SPDX3, CycloneDX, OpenVEX, output of Grype scans, output of Yocto's `cve-check` class. Basically, #VS can be directly wired to the output of a Yocto build without complicated manipulations.

== Reports
#VS has an interesting feature: you can pass it Jinja templates (named "reports") and it will _render_ them using an internal set of variables spanning vulnerabilities, projects, packages and so on. It is really interesting in order to produce an artifact than can be attached to builds and given to end users so they are informed about the packaged software and the detected vulnerabilities in full transparency. It looks like #DT does not have such a feature.

== Policies
Both tools have a way for users to setup a condition when vulnerabilities are "too important" and should ring a bell.

In #VS, the feature is meant to be used in a CI environment and is really simple: you run #VS with the `--match-condition` flag set to a condition and optionally a report that will be exported with the matched CVEs. The program will exit with a non-zero code if vulnerabilities matched the condition, making it extremely easy-to-use in CI pipelines. Concerning the conditions, they are logic expressions that can be as complex as necessary (see an example in @fig:vs:match-condition). For now, match conditions are purely a back-end feature and do not exist on the dashboard.

#figure(
  ```sh
  $ ./vulnscout \
    --match-condition "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending == true or affected == true))" \
    --report "match_condition.adoc"
  # Vulnerability triggered fail condition: CVE-2016-0749
  # Vulnerability triggered fail condition: CVE-2016-10642
  # ...
  # Report written: /scan/outputs/match_condition.adoc
  ```,
  caption: [A #VS execution with a match condition and a report],
) <fig:vs:match-condition>

In contrast, in #DT the feature is fully integrated in the app: there is a "policy management" tab that allows users to define any number of policies with names, "violation states" (info, warn or fail) and conditions. The conditions cannot be as complex as in #VS: you only input a list of criterion that are AND-ed (see @fig:dt:policies). However, where this feature truly shines is how integrated it is with the rest of the app: there are graphs showing the amount of vulnerabilities violating the policies (@fig:dt:violations:dashboard and @fig:dt:violations:project-list) and lists showing only them for easy assessment (@fig:dt:violations:project). #DT policies are however not as easy to integrate in CI/CD pipelines since it would need communicating via the REST API to get a list of violations and handle the results ourselves, which is more complex than getting a failure exit code (more on than in @section:ci).

#figure(
  image("assets/dt-policies.png"),
  caption: [#DT "Policy Management" tab with two policies already set-up],
  placement: auto,
) <fig:dt:policies>

#subpar.grid(
  figure(
    image("assets/dt-violations-dashboard.png", width: 50%),
    caption: [Policy violations evolution graph on the main dashboard],
  ),
  <fig:dt:violations:dashboard>,
  figure(
    image("assets/dt-violations-project-list.png"),
    caption: [Policy violations summary in the project list],
  ),
  <fig:dt:violations:project-list>,
  figure(
    image("assets/dt-violations-project.png"),
    caption: [Policy violations list for a specific project],
  ),
  <fig:dt:violations:project>,
  gap: 1em,
  placement: auto,
  caption: [Various #DT views where policy violations appear],
) <fig:dt:violations>

== Integration with CIs <section:ci>
#VS is really easy to integrate in a CI thanks to its complete CLI.#footnote(link("https://vulnscout.readthedocs.io/en/latest/vulnscout-script.html#non-interactive-mode-ci-automation")) Since #VS is basically a container that can be spinned up in a few seconds, it can be soundly started directly in the CI environment without needing a particular cache. This makes it good to use in public CIs such as GitHub Actions @github-actions. You can find in @fig:vs:ci-workflow a simple workflow that loads SPDX and Yocto cve-check files, generates reports and fails if some CVEs matched the fail condition.

#figure(
  ```sh
  ./vulnscout --project demo --variant x86 \
    --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
    --add-cve-check $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json

  ./vulnscout \
    --match-condition "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending == true or affected == true)) \
    --report "summary.adoc" \
    --report "vulnerabilities.csv" \
    --report "match_condition.adoc"

  # The previous command will fail if a CVE matched the condition, thus failing the workflow.

  ```,
  caption: [Example of a simple CI workflow for #VS],
) <fig:vs:ci-workflow>

#DT cannot be used in the same way since it requires its database mirror to be populated, which takes a long time. For it to be used in CI, the workflow must reference a deployed instance of #DT and use the REST API to interact with it, which means managing authentication via access tokens. Then, to do the actual interaction, there are several possibilities:
- use the official Jenkins plugin which does a really great job (uploads BOMs, displays vulnerabilities, reports policy violations...);
- use the official GitHub Action which is not actively maintainted and only handles uploading BOMs;
- use third-party GitHub Actions which do more things... but are maintained by third parties, which is a security risk;
- making raw HTTP requests and handle the data received, which is more complex to write.

== Integration with Yocto
As already stated in @section:sbom, #DT cannot directly work on the output of a Yocto build, you need a separate layer to create CycloneDX files. On the contrary, #VS directly supports the files created by Yocto so they can be uploaded via the frontend or the CLI. But in order to ease even more integration with Yocto, Savoir-Faire Linux developed a custom `meta-vulnscout` layer@meta-vulnscout that includes all of the necessary scripts and classes to produce the best CVE check possible (for example by filtering kernel CVEs) and even a custom task to directly start #VS from inside Bitbake.

= Conclusion
Both tools serve fundamentally different purposes. #DT is made to be deployed once in a centralized location (e.g. on a server in the company's internal network) and then accessed by everyone from there. It centralizes SBOMs, licenses, vulnerabilities and so on for every project of the company. It also has a really powerful "policies" feature that makes tracking important vulnerabilities easy.

On the other hand, #VS is more self-contained: users that want to see or assess vulnerabilities simply spin it up on their machine, load the SBOMs and previous assessment files and go on from there. It offers no mean of centralization, the goal is to be able to quickly get a working environment to assess vulnerabilities. This flexibility makes it easily usable in CI/CDs.

#VS truly shines for open-source and/or Yocto-based projects: its self-contained nature makes it easy for contributors and users to reproduce assessments, and its wide range of supported input formats contain the default output formats of native Yocto classes, making integration practically painless. Users wanting to use #VS directly in the Bitbake environment can even use the `meta-vulnscout` layer which eases out the setup to a breeze.

#bibliography("bibliography.yml")
