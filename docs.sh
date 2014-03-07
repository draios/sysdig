#!/bin/bash

# Have relative paths correct
cd $(dirname $0)/../

# Just not to break anything
if [[ ! -d sysdig/  || ! -d draios.github.io/ ]]; then
    echo "This script assumes to run inside draios/sysdig
    draios/
        sysdig/
        draios.github.io/"
    exit -1
fi

# In other version css and js files may differ
if [ $(doxygen --version) != "1.8.4" ]; then
    echo "The docs are supposed to use Doxygen@1.8.4."
    echo "Use the -f|--force flag to continue but make sure everthing is still working in the UI."

    if [[ $1 != "-f" && $1 != "--force" ]]; then
        exit -2
    fi
fi

# Clean up
rm -rf draios.github.io/libscap/
rm -rf draios.github.io/libsinsp/

# Generate the docs
cd sysdig/userspace/libscap/doxygen/
doxygen conf.dox
cd ../../libsinsp/doxygen/
doxygen conf.dox
cd ../../../../

# Move for cleaning up sysdig repo
mv sysdig/userspace/libscap/doxygen/html draios.github.io/libscap
mv sysdig/userspace/libsinsp/doxygen/html draios.github.io/libsinsp

cd draios.github.io/

# Override with our custom scripts
cp -f assets/vendor/doxygen/doxygen.css libscap/
cp -f assets/vendor/doxygen/tabs.css libscap/
cp -f assets/vendor/doxygen/dynsections.js libscap/

cp -f assets/vendor/doxygen/doxygen.css libsinsp/
cp -f assets/vendor/doxygen/tabs.css libsinsp/
cp -f assets/vendor/doxygen/dynsections.js libsinsp/

echo
echo "Push changes under draios.github.io to go live"

exit 0
