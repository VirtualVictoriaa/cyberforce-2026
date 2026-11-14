# Snort

## Install Snort 3

`install.sh` builds Snort 3 and LibDAQ from source, installs the Snort community
rules, merges in the `*.rules` files from the directory you provide, validates
the configuration, and starts a detection-only service. It supports Debian,
Ubuntu, openSUSE, and Alpine. Debian, Ubuntu, and openSUSE use systemd; Alpine
uses OpenRC.

The install requires root access and internet connectivity. The source builds
can take several minutes. Snort and LibDAQ versions are pinned in the script;
set `BUILD_JOBS` to change the build parallelism (default: 2).

1. Copy this directory to the target host and enter it.
2. Find the capture interface with `ip -br link`.
3. Run the installer, replacing the interface and network with the values for
	 the host. The rules directory must contain at least one `*.rules` file.

```sh
sudo ./install.sh -i eth0 -r . -H 10.0.47.128/27 -E any
```

The repository's `our.rules` and `fireeye.rules` are included when `-r .` is
used from this directory. The installer also downloads and includes the Snort
community rules. Use `-r /path/to/rules` to provide a different directory.

## Verify the Service

The installer tests the configuration and enables and starts the service before
printing `[+] done`. On systemd hosts, check that it remains running:

```sh
sudo systemctl status snort-detect --no-pager
```

The status should show `active (running)` and `enabled`. To inspect service
logs:

```sh
sudo journalctl -u snort-detect -n 50 --no-pager
```

On Alpine, the installer starts Snort through `/etc/local.d/snort.start`; check
its startup log with:

```sh
sudo tail -n 50 /var/log/snort/startup.log
```

To restart systemd Snort after changing the configuration or service unit:

```sh
sudo systemctl restart snort-detect
sudo systemctl status snort-detect --no-pager
```

## Troubleshooting

- Run Snort tests and read its protected config with `sudo`.
- If Snort reports that it cannot find the `pcap` DAQ module, check where it
	was installed:

	```sh
	sudo find /usr/local/lib /usr/local/lib64 -type f -name daq_pcap.so -print
	```

	The installer detects that directory and passes it to Snort with
	`--daq-dir`. For a manual test, use the directory containing `daq_pcap.so`:

	```sh
	sudo /usr/local/bin/snort --daq-dir /usr/local/lib/daq -T -i eth0 \
		-c /etc/snort/snort.lua -l /var/log/snort -k none
	```

- If the service fails to start on systemd, inspect its journal with the
	command above. If you rerun the installer while the service is already
	running, restart it so it picks up the newly written unit and configuration.

## Other Files

- `our.rules`: custom detection rules.
- `fireeye.rules`: FireEye rules.
- `adorsys_install-snort.sh`: third-party installer from ADORSYS-GIS; not
	maintained by this project.

