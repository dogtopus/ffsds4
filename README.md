# ffsds4

Crappy DoubleShock4 simulator.

plz let me on PSXHAX again.

## Usage

Make sure the UDC driver module for your board and `libcomposite` module are loaded. If testing on PC, use `dummy_hcd` as the UDC driver. Also, make sure `libaio` is installed in your target and development systems since `python-functionfs` requires it.

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

Note that targeting Arm-based hardware requires the use of emulators and like (such as QEMU) or a real Arm-based hardware that runs a Linux version similar enough to the target board.

If ffsds4 fails with `-EBUSY`, try unloading the kernel module `g_ffs`. If the module is built-in (e.g. on Manjaro ARM for Pinephone), blacklist `gfs_init` function by adding `initcall_blacklist=gfs_init` to the kernel cmdline and reboot the system.
