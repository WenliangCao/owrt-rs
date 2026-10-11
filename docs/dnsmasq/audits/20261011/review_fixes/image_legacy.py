import os, runpy, subprocess, sys
from pathlib import Path
source = Path('/home/ubuntu/dnsmasq-review-fix-20261011/source')
image = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
rust = Path('/home/ubuntu/dnsmasq-review-fix-20261011/source/private/sdk-source-acquire-02/payload/usr/sbin/dnsmasq')
sys.path.insert(0, str(source / 'tools/dnsmasq'))
from m2_rootfs import image_elf_command
original = subprocess.Popen
class ImagePopen(original):
    def __init__(self, argv, *args, **kwargs):
        if isinstance(argv, (list, tuple)) and str(argv[0]) in (str(rust), str(image / 'usr/sbin/dnsmasq')):
            argv = image_elf_command(image, Path(argv[0])) + list(argv[1:])
        super().__init__(argv, *args, **kwargs)
subprocess.Popen = ImagePopen
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
