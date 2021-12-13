# Sysdig Docker image

To build the Sysdig image, run `docker build -f docker/sysdig/Dockerfile .` from the Sysdig root directory

By default, a compatible version of the `falcosecurity/libs` dependency is downloaded from GitHub and built. If you want to link against a local falcosecurity/libs version you can do so by putting it under `falcosecurity-libs` in the Sysdig root directory.
