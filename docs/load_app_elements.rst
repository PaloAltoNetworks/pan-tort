Load Application Elements into Skeleton
=======================================

The below are quick steps to load submodules and set up the environment for local
usage of the iron skillet cnc app.

.. NOTE::

    These are sandbox instructions only and may not be required with container and other usage models


Prequisites
-----------

    + clone the skeleton branch

    + active python virtual enviroment (recommended)

Values Used in this Example
---------------------------


    + Panorama IP address: 192.168.55.7

    + application server port: 9999


Add and prep the pan-cnc submodule then start the server
--------------------------------------------------------

::

    git submodule add -b develop --force git@github.com:PaloAltoNetworks/pan-cnc.git ./cnc
    cd cnc
    pip install -r requirements.txt
    ./manage.py migrate
    ./manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_superuser('vistoq', 'admin@example.com', 'vistoq')"
    export PANORAMA_IP=192.168.55.8
    export PANORAMA_USERNAME=admin
    export PANORAMA_PASSWORD=admin
    ./manage.py runserver 9999
