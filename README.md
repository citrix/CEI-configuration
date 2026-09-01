# uberAgent Configuration

This repository is the home for the [uberAgent](https://www.citrix.com/platform/uberagent.html) configuration. This repository contains UXM configuration settings (timers, metrics, etc.) as well as ESA Threat Detection rules and Security & Compliance Inventory tests.

## Getting Started

1. Select the Git branch that matches your installed uberAgent version.
2. Clone this repository to your machine.
3. Update the files in your [uberAgent configuration](https://docs.citrix.com/en-us/uberagent/current-release/planning/configuration-options)
   - Choose either the files from the `config` or the `config-dist` folder of this repository, depending on your uberAgent version (see [Folder Structure](#folder-structure)).

## Repository Structure

### uberAgent Versions & Git Branches

This repository is organized in such a way that uberAgent releases are represented by Git branches. Each Git branch contains the configuration that is compatible with the matching uberAgent release.

| uberAgent version | Git branch                            |
| ----------------- | ------------------------------------- |
| `8.1.x`           | [version/8.1](../../tree/version/8.1) |
| `8.0`             | [version/8.0](../../tree/version/8.0) |
| `7.5.x`           | [version/7.5](../../tree/version/7.5) |
| `7.4.x`           | [version/7.4](../../tree/version/7.4) |

The `main` branch does not carry a configuration. It only serves as the template the version branches are created from.

### Folder Structure

| Folder        | Description                                                                                                                         |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `config`      | Compiled configuration as individual source files. Use the contents of this folder for your **deployment with any uberAgent version**. |
| `config-dist` | Compiled configuration as configuration archive (`uberAgent.uAConfig`). Use the contents of this folder for your **deployment with uberAgent 7.1+**. |

## Configuration Updates

While the configuration for uberAgent UXM remains relatively static, the configuration for uberAgent ESA changes daily due to regular updates to the included Sigma rules. Pull the branch of your uberAgent version regularly so that your endpoints receive the latest threat detection rules.

## Help and Support

Please see the [uberAgent documentation portal](https://docs.citrix.com/en-us/uberagent/current-release/) for docs, help and support options.
