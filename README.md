# Citrix Experience Insights Configuration

This repository is the home for the [Citrix Experience Insights (CEI)](https://www.citrix.com/platform/uberagent.html) configuration. It contains configuration settings (timers, metrics, etc.) as well as Threat Detection rules and Security & Compliance Inventory tests.

## Getting Started

1. Select the Git branch that matches your installed CEI version (see [CEI Versions & Git Branches](#cei-versions--git-branches)).
2. Clone this repository to your machine.
3. Update the files in your [CEI configuration](https://docs.citrix.com/en-us/uberagent/current-release/planning/configuration-options):
   - Use either the individual files from the `config` folder or a configuration archive from the `config-dist` folder (see [Folder Structure](#folder-structure)).
   - Starting with CEI 9.0, the configuration uses the YAML format. When upgrading from an older version, see [Upgrading to CEI 9.0](#upgrading-to-cei-90).

## Repository Structure

### CEI Versions & Git Branches

This repository is organized in such a way that CEI releases are represented by Git branches. Each Git branch contains the configuration that is compatible with the matching CEI release.

| CEI version | Git branch                            |
| ----------- | ------------------------------------- |
| `9.0.x`     | [version/9.0](../../tree/version/9.0) |
| `8.1.x`     | [version/8.1](../../tree/version/8.1) |
| `8.0`       | [version/8.0](../../tree/version/8.0) |
| `7.5.x`     | [version/7.5](../../tree/version/7.5) |
| `7.4.x`     | [version/7.4](../../tree/version/7.4) |

The `main` branch does not carry a configuration. It only serves as the template the version branches are created from.

### Folder Structure

#### CEI 9.0 and Newer

| Folder        | Description                                                                                                        |
| ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `config`      | Configuration as individual YAML files, grouped into subfolders by topic.                                          |
| `config-dist` | Configuration as ready-to-use configuration archives, e.g., for Central Config File Management (CCFM).            |
| `yaml-config` | JSON Schema and metadata of the YAML configuration format (see [Editor Support](#editor-support)). Do not deploy. |

The `config-dist` folder contains two archive variants:

| Archive                                 | Content                                                                                                            |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `configuration.zip`                     | The complete configuration.                                                                                        |
| `configuration-without-sigma-rules.zip` | The same configuration without the Sigma rules. Use this variant if you maintain your own Threat Detection rules. |

The `config` folder is organized as follows:

```text
config/
├── uberAgent.yaml                          Main configuration file
├── uberAgent-data-volume-optimized.yaml    Alternative main configuration, optimized for small data volume
├── uberAgent-meta-config.yaml              Settings needed before the main configuration is read, e.g., the log file path
├── uberAgent-remote-config-linux.yaml      Central Config File Management settings for Linux
├── uberAgent-remote-config-macOS.yaml      Central Config File Management settings for macOS
├── ESA/                                    Security capability: Threat Detection and Security & Compliance Inventory settings
│   └── Sigma rules/                        Threat Detection rules converted from Sigma, one file per level and platform
├── Event data filter/                      Event data filters
├── GPO/                                    Additional configuration for deployments via Group Policy
└── Security inventory/                     Security & Compliance Inventory tests
    ├── Windows/                            PowerShell scripts, signed by Citrix
    └── macOS/                              zsh scripts
```

- The files reference each other by relative paths. Keep the folder structure when deploying them.
- To use the data volume optimized configuration, rename `uberAgent-data-volume-optimized.yaml` to `uberAgent.yaml`, replacing the default file.
- By default, `ESA/uberAgent-ESA.yaml` includes the Sigma rules of the levels `critical` and `high`. The files of the other levels are provided but not included.
- The PowerShell scripts in `Security inventory/Windows` are signed. Modifying a script invalidates its signature, which matters if your endpoints only run signed scripts. Templates for your own tests are located in the `Examples` subfolders.
- Unlike the former `.conf` templates, the YAML files contain no explanatory comments. The available settings are described in the documentation and in the [JSON Schema](#editor-support).

#### CEI 8.1 and Older

| Folder        | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `config`      | Configuration as individual `.conf` files.                     |
| `config-dist` | Configuration as configuration archive (`uberAgent.uAConfig`). |

## Upgrading to CEI 9.0

- **Configuration format:** The configuration files are YAML files now. If a folder contains a `.conf` and a `.yaml` file with the same name, CEI uses the `.yaml` file. Transfer your customizations to the YAML files instead of keeping the old `.conf` files.
- **Folder structure:** The files are grouped into subfolders (`ESA`, `ESA/Sigma rules`, `Event data filter`, `GPO`) instead of a single flat folder.
- **Configuration archive:** The archive is now called `configuration.zip`. `uberAgent.uAConfig` is still supported, but if both archives are present in the same folder, `configuration.zip` takes precedence.
- **Group Policy:** The additional configuration file moved from `uberAgent-GPO-include.conf` in the configuration root to `GPO/uberAgent-GPO-include.yaml`. In existing GPOs, update the setting **Additional configuration file** accordingly, e.g., to `C:\ProgramData\vast limits\uberAgent\Configuration\GPO\uberAgent-GPO-include.yaml`. Updating the agent or the administrative template does not change existing GPOs.

## Editor Support

Starting with CEI 9.0, the `yaml-config` folder contains a JSON Schema (`uberAgent-config.schema.json`) that describes all configuration settings. Editors with JSON Schema support for YAML use it to validate the configuration files, offer auto-completion and show descriptions of the settings. In Visual Studio Code with the YAML extension, add the following line at the top of a configuration file, using the branch that matches your CEI version:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/citrix/CEI-configuration/version/9.0/yaml-config/uberAgent-config.schema.json
```

The schema can also be used to validate configuration changes automatically, e.g., in a CI pipeline. `uberAgent-config.metadata.json` is a machine-readable description of the configuration format for tools.

## Configuration Updates

The configuration is uploaded to this repository at the end of each release cycle. The contents are generated from the CEI source code and replaced with each update, so changes made directly in this repository, including pull requests, are not carried over.

## License

This repository is licensed under the [Apache License 2.0](LICENSE).

## Help and Support

Please see the [CEI documentation portal](https://docs.citrix.com/en-us/uberagent/current-release/) for docs, help and support options.
