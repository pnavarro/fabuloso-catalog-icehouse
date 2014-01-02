# -*- coding: utf-8 -*-

import os.path

from cuisine import *

DEFAULT = {
    'keystone_signing_dir': '/var/lib/swift/keystone-signing'
}

CONF_DIR = '/etc/swift'
PROXY_CONF = 'proxy-server.conf'
OWNER = {
    'owner': 'swift',
    'group': 'swift'
}


def install_proxy_packages():
    for package in ('swift-proxy', 'python-webob'):
        package_ensure(package)


def install_proxy_config(
    auth_port=35357,
    auth_host='localhost',
    auth_protocol='http',
    admin_tenant_name='service',
    admin_user='swift',
    admin_password='stackops',
    memcache_servers=['localhost:11211'],
    keystone_signing_dir=DEFAULT['keystone_signing_dir']):

    data = dict(
        auth_port=auth_port,
        auth_host=auth_host,
        auth_protocol=auth_protocol,
        admin_tenant_name=admin_tenant_name,
        admin_user=admin_user,
        admin_password=admin_password,
        memcache_servers=','.join(memcache_servers),
        keystone_signing_dir=keystone_signing_dir
    )

    config = _template(PROXY_CONF, data)

    with cd(CONF_DIR):
        with mode_sudo():
            file_write(PROXY_CONF, config, **OWNER)

    with mode_sudo():
        dir_ensure(keystone_signing_dir, recursive=True, **OWNER)


def start():
    sudo('swift-init proxy start')


def _template(name, data):
    return _get_template(name).format(**data)


def _get_template(name):
    template_path = os.path.join(os.path.dirname(__file__), 'templates', name)

    with open(template_path) as template:
        return template.read()


# Validations

from expects import expect


def validate_proxy_config(
    keystone_signing_dir=DEFAULT['keystone_signing_dir']):

    with cd(CONF_DIR):
        _expect_file_exists(PROXY_CONF)
        _expect_owner(PROXY_CONF, OWNER)

    _expect_dir_exists(keystone_signing_dir)
    _expect_owner(keystone_signing_dir, OWNER)


def validate_started():
    # I don't know why, but the `ps -A` command run in the `process_find`
    # function truncates the processes names so I can't match the entire
    # process name 'swift-proxy-server'.

    expect(process_find('swift-proxy')).not_to.be.empty


def _expect_dir_exists(path):
    expect(dir_exists(path)).to.be.true


def _expect_file_exists(path):
    expect(file_exists(path)).to.be.true


def _expect_owner(path, owner):
    attribs = file_attribs_get(path)

    expect(attribs).to.have.keys(owner)
