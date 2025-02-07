JUSTHASHES := ".justhashes"

buildfile fpath:
    #!/bin/bash

    # Init hash files if does not exit
    if [ ! -f {{ JUSTHASHES }} ]; then
        touch {{ JUSTHASHES }}
    fi

    if [ -d {{ fpath }}]
        echo "{{ fpath }} already exists as dir."
        exit 1
    fi

    # Run the file recipe if it changed or was not built before
    if [ ! -f {{ fpath }} ] || [ ! "$(md5sum {{ fpath }} | head -c 32)" == "$(grep " {{ fpath }}" {{ JUSTHASHES }} | head -c 32)" ]; then
        just {{ fpath }}
        echo "$(grep -v "{{ fpath }}" {{ JUSTHASHES }})" > {{ JUSTHASHES }}
        md5sum {{ fpath }} >> {{ JUSTHASHES }}
    fi
