# -*- coding: utf-8 -*-

import os.path

from fabric.contrib import files
from cuisine import *


CONF_DIR = '/etc/swift'
NODE_DIR = '/srv/node'
STORAGE_CONFIGS = (
    'account-server.conf', 'object-server.conf', 'container-server.conf')

RSYNC_CONF = '/etc/rsyncd.conf'
OWNER = {
    'owner': 'swift',
    'group': 'swift'
}


def install_storage_packages():
    for package in ('swift-account', 'swift-container', 'swift-object'):
        package_ensure(package)


def install_storage_config():
    with cd(CONF_DIR):
        for config in STORAGE_CONFIGS:
            with mode_sudo():
                file_write(config, _template(config, {}), **OWNER)

    with mode_sudo():
        dir_ensure(NODE_DIR, recursive=True, **OWNER)


def install_storage_devices(devices):
    """The `devices` property should be a list of strings or dicts
    defining storage devices:

    devices = [
        'sdb1',
        {
            'name': 'foo',
            'path': '/dev/mapper/ubuntu--vg-storage'
        }
    ]

    """

    for device, mount_point in __extract_devices(devices):
        with mode_sudo():
            dir_ensure(mount_point)
            mount_ensure(device, mount_point)
            dir_attribs(mount_point, recursive=True, **OWNER)


def __extract_devices(devices):
    for device in devices:
        if isinstance(device, dict):
            yield device['path'], '{}/{}'.format(NODE_DIR, device['name'])
        else:
            yield '/dev/{}'.format(device), '{}/{}'.format(NODE_DIR, device)


def install_rsync_packages():
    package_ensure('rsync')


def install_rsync_config():
    rsync_conf_template = os.path.basename(RSYNC_CONF)

    with mode_sudo():
        file_write(RSYNC_CONF, _template(rsync_conf_template, {}))

    sudo("sed -ie 's/RSYNC_ENABLE=false/RSYNC_ENABLE=true/' "
         "/etc/default/rsync")


def start():
    sudo('swift-init all start')


def stop():
    sudo('swift-init all stop')


def _template(name, data):
    return _get_template(name).format(**data)


def _get_template(name):
    template_path = os.path.join(os.path.dirname(__file__), 'templates', name)

    with open(template_path) as template:
        return template.read()


# Validations

from expects import expect


def validate_storage_config():
    with cd(CONF_DIR):
        for config in STORAGE_CONFIGS:
            _expect_file_exists(config)
            _expect_owner(config, OWNER)

    _expect_dir_exists(NODE_DIR)
    _expect_owner(NODE_DIR, OWNER)


def validate_storage_devices(devices):
    with cd(NODE_DIR):
        for device in devices:
            _expect_dir_exists(device)
            _expect_owner(device, OWNER)
            _expect_mounted(device)


def validate_rsync_config():
    _expect_file_exists(RSYNC_CONF)
    _expect_owner(RSYNC_CONF, {'owner': 'root', 'group': 'root'})


def validate_started():
    for service in ('swift-account', 'swift-container', 'swift-object'):
        expect(process_find(service)).not_to.be.empty


def _expect_file_exists(path):
    expect(file_exists(path)).to.be.true


def _expect_dir_exists(path):
    expect(dir_exists(path)).to.be.true


def _expect_owner(path, owner):
    attribs = file_attribs_get(path)

    expect(attribs).to.have.keys(owner)


def _expect_mounted(device):
    expect(mount_exists(device)).to.be.true


def mount_ensure(device, mount_point):
    if not mount_exists(device):
        sudo('mount {} {}'.format(device, mount_point))

    files.append(
        '/etc/fstab',
        _fstab_mount(device, mount_point),
        use_sudo=True)


def _fstab_mount(device, mount_point):
    return '{} {} xfs noatime,noriatime,nobarrier,logbufs=8 0 0'.format(
        device, mount_point)


def mount_exists(device):
    return True if run('mount | grep {} ; true'.format(device)) else False
