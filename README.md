# MasterPasswordPy

This is a Python variant of
[MasterPassword](https://github.com/Lyndir/MasterPassword) by
[Lyndir](https://lhunath.com/).

## Installation

Create a virtual environment "venv":

```bash
python -m venv venv
```

Change in the newly created environment:

```sh
source venv/bin/activate
```

Install the requirements (scrypt):

```sh
pip install -r requirements.txt
```

Run MasterPassword:

```sh
./mpw.py -u test -M test test
```

The generated password should be **CefoTiciJuba7@**.