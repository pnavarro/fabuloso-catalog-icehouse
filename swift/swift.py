# -*- coding: utf-8 -*-

import os.path
import tempfile

from fabric.api import get, put, warn_only, settings
from cuisine import *


def _random_token():
    import hashlib
    import random

    return hashlib.sha512(str(random.getrandbits(16))).hexdigest()[:8]

DEFAULT = {
    'swift_hash_path_prefix': _random_token(),
    'swift_hash_path_suffix': _random_token()
}

CONF_DIR = '/etc/swift'
CONF_FILE = 'swift.conf'
OWNER = {
    'owner': 'swift',
    'group': 'swift'
}

RINGS = ('account', 'container', 'object')


def install_common_packages():
    package_ensure('swift')


def install_common_config(
    swift_hash_path_prefix=DEFAULT['swift_hash_path_prefix'],
    swift_hash_path_suffix=DEFAULT['swift_hash_path_suffix']):

    with mode_sudo():
        dir_ensure(CONF_DIR, **OWNER)

    data = dict(
        swift_hash_path_suffix=swift_hash_path_suffix,
        swift_hash_path_prefix=swift_hash_path_prefix
    )

    config = _template(CONF_FILE, data)

    with cd(CONF_DIR):
        with mode_sudo():
            file_write(CONF_FILE, config, **OWNER)


def create_rings(devices, part_power=18, replicas=3, min_part_hours=1):
    with cd(CONF_DIR):
        for name in RINGS:
            builder = '{}.builder'.format(name)

            _create_ring_builder(builder, part_power, replicas, min_part_hours)

            for device in devices:
                _add_device_to_ring(
                    builder,
                    device['zone'],
                    device['host'],
                    device['{}_port'.format(name)],
                    device['name'],
                    device['weight'])


def rebalance_rings():
    with cd(CONF_DIR):
        for name in RINGS:
            builder = '{}.builder'.format(name)
            ring = '{}.ring.gz'.format(name)

            with warn_only():
                _rebalance_ring(builder)

            with mode_sudo():
                file_attribs(ring, **OWNER)


def deploy_rings(nodes):
    local_path = tempfile.mkdtemp(prefix='swift-rings')

    # Download the built rings from the target node
    with cd(CONF_DIR):
        get('*.ring.gz', local_path)

    # Upload rings to each node
    for node in nodes:
        with settings(host_string=node):
            for ring in ('{}.ring.gz'.format(name) for name in RINGS):
                put(os.path.join(local_path, ring), CONF_DIR, use_sudo=True)

                with cd(CONF_DIR), mode_sudo():
                    file_attribs(ring, **OWNER)


def add_device_to_rings(zone, host, name, weight=100,
                        account_port=6002, container_port=6001,
                        object_port=6000):

    with cd(CONF_DIR):
        for ring_name in RINGS:
            builder = '{}.builder'.format(ring_name)

            _add_device_to_ring(
                builder,
                zone,
                host,
                locals()['{}_port'.format(ring_name)],
                name,
                weight)


def _create_ring_builder(name, part_power, replicas, min_part_hours):
    print 'Creating builder {}'.format(name)

    sudo(_ring_builder(name, 'create', part_power, replicas, min_part_hours))


def _add_device_to_ring(builder, zone, host, port, name, weight):
    sudo(_ring_builder(
        builder, 'add',
        'z{}-{}:{}/{} {}'.format(zone, host, port, name, weight)))


def _rebalance_ring(builder):
    sudo(_ring_builder(builder, 'rebalance'))


def _ring_builder(*args):
    command = [str(arg) for arg in args]
    command.insert(0, 'swift-ring-builder')

    return ' '.join(command)


def _template(name, data):
    return _get_template(name).format(**data)


def _get_template(name):
    template_path = os.path.join(os.path.dirname(__file__), 'templates', name)

    with open(template_path) as template:
        return template.read()


# Validations

from expects import expect

def validate_common_config():
    _expect_dir_exists(CONF_DIR)
    _expect_owner(CONF_DIR, OWNER)

    with cd(CONF_DIR):
        _expect_file_exists(CONF_FILE)
        _expect_owner(CONF_FILE, OWNER)


def validate_rings():
    # TODO(jaimegildesagredo): It would be interesting to validate
    #                          that each ring contains the given devices.

    with cd(CONF_DIR):
        for name in RINGS:
            ring = '{}.ring.gz'.format(name)

            _expect_file_exists(ring)
            _expect_owner(ring, OWNER)


def _expect_dir_exists(path):
    expect(dir_exists(path)).to.be.true


def _expect_file_exists(path):
    expect(file_exists(path)).to.be.true


def _expect_owner(path, owner):
    attribs = file_attribs_get(path)

    expect(attribs).to.have.keys(owner)
