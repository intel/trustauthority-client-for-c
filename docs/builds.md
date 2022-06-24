# Build Instructions
The Amber Client is build proces uses Docker and produces binaries (.so files, etc.) in the /bin directory. 

## Prerequisites
- Docker v20+
- make

## Instructions
- The table below lists the Linux distributions that the build process currently supports.

    |Distribution|Build Target Name|
    |------------|-----------------|
    |Ubuntu 20.04|ubuntu_20|
    |Ubuntu 18.04|NA|
    |RHEL 8.x| NA|

- `make {{"Build Target Name"}}` (ex. `make ubuntu_20` will produce binaries in bin\ubuntu_20).
