# Intentional Trivy example

This lockfile deliberately pins minimist 1.2.5, affected by CVE-2021-44906
(prototype pollution). It is a non-executed scanner fixture, outside the runtime
package and dependency tree. Do not install or import it into the application.

Trivy should report the vulnerable package. Fixing the demo means upgrading this
fixture to a patched version (1.2.6 or later), then rescanning. This illustrates a
dependency finding independently of Semgrep's dynamic-evaluation findings and
DeepSec's code-execution analysis. This vulnerable PR must remain unmerged.
