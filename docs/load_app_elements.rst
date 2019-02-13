Load Application Elements into Skeleton
=======================================

The below are quick steps to load submodules and set up the environment for local
usage of the iron skillet cnc app.

.. NOTE::

    These are sandbox instructions only and may not be required with container and other usage models


Prerequisites
-------------

    + clone the skeleton branch

    + active python virtual enviroment (recommended)

Values Used in this Example
---------------------------


    + Panorama IP address: 192.168.55.7

    + application server port: 9999


Add and prep the pan-cnc submodule then start the server
--------------------------------------------------------

::

    git submodule init
    git submodule update
    pip install -r requirements.txt
    pip install -r cnc/requirements.txt
    ./cnc/manage.py migrate
    ./cnc/manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_superuser('paloalto', 'admin@example.com', 'tort')"
    ./cnc/manage.py runserver 9999
