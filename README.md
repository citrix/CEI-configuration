# Citrix Experience Insights Configuration

This repository is the home for the [Citrix Experience Insights (CEI)](https://www.citrix.com/platform/uberagent.html) configuration. This repository contains  configuration settings (timers, metrics, etc.) as well as Threat Detection rules and Security & Compliance Inventory tests.

## Getting Started

1. Select the Git branch that matches your installed CEI version.
2. Clone this repository to your machine.
3. Update the files in your [CEI configuration](https://docs.citrix.com/en-us/uberagent/current-release/planning/configuration-options)
   - Choose either the files from the `config` or the `config-dist` folder of this repository, depending on your CEI version (see [Folder Structure](#folder-structure)).

## Repository Structure

### CEI Versions & Git Branches

This repository is organized in such a way that CEI releases are represented by Git branches. Each Git branch contains the configuration that is compatible with the matching CEI release.

| CEI version | Git branch                            |
| ----------- | ------------------------------------- |
| `8.1.x`     | [version/8.1](../../tree/version/8.1) |
| `8.0`       | [version/8.0](../../tree/version/8.0) |
| `7.5.x`     | [version/7.5](../../tree/version/7.5) |
| `7.4.x`     | [version/7.4](../../tree/version/7.4) |

The `main` branch does not carry a configuration. It only serves as the template the version branches are created from.

### Folder Structure

| Folder        | Description                                                                                                                         |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `config`      | Compiled configuration as individual source files. Use the contents of this folder for your **deployment with any CEI version**. |
| `config-dist` | Compiled configuration as configuration archive. Use the contents of this folder for your **deployment with any CEI version**. |

## Configuration Updates

The configuration is uploaded to this repository at the end of each release cycle.

## Help and Support

Please see the [CEI documentation portal](https://docs.citrix.com/en-us/uberagent/current-release/) for docs, help and support options.
