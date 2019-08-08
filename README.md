# restartable
List running processes using files deleted by recent upgrades

[![Build Status](https://travis-ci.org/ricardobranco777/restartable.svg?branch=master)](https://travis-ci.org/ricardobranco777/restartable)

When upgrading packages, the package manager won't restart services or programs that depend on some updated library, for obvious reasons.  This has security implications in the case of outdated libraries still in use.

OpenSUSE has a cool `zypper ps` command to check for programs and services using deleted files.
It's also available in other distros as `zypp-CheckAccessDeleted` from the `libzypp` package.
Those commands parse `lsof` output and check `/proc/<pid>/cgroup` to extract the service names.

Here's a Python version that checks `/proc/<pid>/maps`, extracting information from other files in `/proc/<pid>`.

No `lsof` dependency needed.

Excerpt from `zypper` manual:

> After each upgrade or removal of packages, there may be running processes on the system which continue to use meanwhile deleted files. zypper ps lists all processes using deleted files, together
> with the corresponding files, and a service name hint, in case it’s a known service. This gives a hint which services may need to be restarted after an update. Usually programs which continue to
> use deleted shared libraries. The list contains the following information:
>

|   |   |
|---|---|
| PID | ID of the process
| PPID | ID of the parent process
| UID | ID of the user running the process
| Login | Login name of the user running the process
| Command | Command used to execute the process
| Service | Service name, if command is associated with a system service
| Files | The list of the deleted files

## Installation

```
sudo pip3 install restartable
```

## Usage

```
sudo restartable [OPTIONS]

List running processes using files deleted by recent upgrades

Options:
    -P, --proc PROC_DIRECTORY
	Specify /proc directory
    -s, --short
	Create a short table not showing the deleted files. Given twice,
	show only processes which are associated with a system service.
	Given three times, list the associated system service names only.
    -v, --verbose
        Show the complete command line
```

## NOTES

  - Verified to work on Python 3.4+
  - You must run it as root to see the information you want.
  - The output is different from `zypper ps` to be easily parseable

## BUGS / LIMITATIONS

  - The service names can only be extracted if started by Systemd
