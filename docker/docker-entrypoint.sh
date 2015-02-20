#!/bin/bash
#set -e

if [ ! -z "$ACCESS_KEY" ]; then
	echo "* Setting access key"
	
	if ! grep ^customerid /opt/draios/bin/dragent.properties > /dev/null 2>&1; then
		echo "customerid = $ACCESS_KEY" >> /opt/draios/bin/dragent.properties
	else
		sed -i "s/^customerid.*/customerid = $ACCESS_KEY/g" /opt/draios/bin/dragent.properties
	fi
fi

if [ ! -z "$TAGS" ]; then
	echo "* Setting tags"

	if ! grep ^ui.tags /opt/draios/bin/dragent.properties > /dev/null 2>&1; then
		echo "ui.tags = $TAGS" >> /opt/draios/bin/dragent.properties
	else
		sed -i "s/^ui\.tags.*/ui.tags = $TAGS/g" /opt/draios/bin/dragent.properties
	fi
fi

if [ $# -eq 0 ]; then
	if ! /usr/bin/sysdig-probe-installer; then
		exit 1
	fi

	exec /opt/draios/bin/dragent
else
	exec "$@"
fi
