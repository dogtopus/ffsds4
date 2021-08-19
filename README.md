# ffsds4

Crappy DoubleShock4 simulator.

plz let me on PSXHAX again.

## Usage

Make sure the UDC driver module for your board and `libcomposite` module are loaded. If testing on PC, use `dummy_hcd` as the UDC driver. Also, make sure `libaio` is installed on both your target and development systems since `python-functionfs` requires it.

To start ffsds4 using pipenv, run:

```sh
pipenv install # after checkout
pipenv run start-with-sudo -k <path to a DS4Key> --username=$USER
```

To create an executable for easy transport and faster startup, use:

```sh
pipenv install --dev # after checkout

# Make a standalone package
pipenv run package

# Make a single file executable
pipenv run package-onefile
```

Note that targeting Arm-based hardware requires the use of emulators and like (such as QEMU) or a real Arm-based hardware that runs a Linux distro similar enough to the target board (in terms of libc version).

If ffsds4 fails with `-EBUSY`, try unloading the kernel module `g_ffs`. If the module is built-in (e.g. on Manjaro ARM for Pinephone), blacklist `gfs_init` function by adding `initcall_blacklist=gfs_init` to the kernel cmdline and reboot the system.

## Profiling

Run ffsds4 with parameter `--profile path/to/result.profile` to enable profiler.

Result is saved as standard Python profile/cProfile dump file. This file can be decoded using Python's `profile` or `cProfile` module.

To visualize the result using `snakeviz`, make sure you installed the development dependencies, then run

```sh
pipenv run snakeviz path/to/result.profile
```

Alternatively you could use `tuna`, which sometimes produces better graph than snakeviz but has less features:

```sh
pipenv run tuna path/to/result.profile
```
