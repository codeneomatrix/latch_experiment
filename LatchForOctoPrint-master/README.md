![Version](https://img.shields.io/badge/OctoPrint-Latch%20for%20OctoPrint%20v1.0-red.svg?style=flat-square)
![License](https://img.shields.io/badge/license-GNU-green.svg?style=flat-square)
![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg?style=flat-square)

# Latch for OctoPrint

"Latch for OctoPrint" is a hack to implement Latch on a OctoPrint server.

Patching OctoPrint
==================

Download and copy the content of "octoprint" folder in the directory with the same name at OctoPrint project that is "src".

```
git clone https://github.com/foosel/OctoPrint.git
git clone https://github.com/toolsprods/LatchForOctoPrint
cp -r LatchForOctoPrint/octoprint OctoPrint/src/
```

Pairing Latch
=============

**Note:** For this step you must create an application from the Latch developer panel and have the App ID and the secret.

Edit the "config.py" file in "src/octoprint/server/latch" with the App ID and the secret.

Pair from the OctoPrint directory:

```
python src/octoprint/server/latch -p PAIRING_CODE_HERE
```

Back to edit the "config.py" file, adding now the Account ID received.

To unpair:

```
python src/octoprint/server/latch -u
```

Installing OctoPrint
====================

Finally it ends with the installation of OctoPrint. Run at OctoPrint directory:

```
virtualenv venv
./venv/bin/python setup.py install
```

Run OctoPrint:

```
./venv/bin/octoprint
```

Authors
=======

**Álvaro Núñez** - <toolsprods@gmail.com>

**Latch** - [Eleven Paths](https://latch.elevenpaths.com)

License
=======

This project is licensed under the GNU General Public License - see the LICENSE file for details