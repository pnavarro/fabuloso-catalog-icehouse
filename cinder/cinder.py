#   Copyright 2012-2013 STACKOPS TECHNOLOGIES S.L.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from fabric.api import settings, sudo
from cuisine import package_clean, package_ensure
from fabuloso import fabuloso

import fabuloso.utils as utils

CINDER_CONF = '/etc/cinder/cinder.conf'
CINDER_API_PASTE_CONF = '/etc/cinder/api-paste.ini'


def stop():
    with settings(warn_only=True):
        sudo("nohup service cinder-api stop")
        sudo("nohup service cinder-scheduler stop")
        sudo("nohup service cinder-volume stop")


def start():
    stop()
    sudo("nohup service cinder-api start")
    sudo("nohup service cinder-scheduler start")
    sudo("nohup service cinder-volume start")


def iscsi_stop():
    with settings(warn_only=True):
        sudo("nohup service tgt stop")


def iscsi_start():
    iscsi_stop()
    sudo("nohup service tgt start")


def uninstall():
    """Uninstall cinder packages"""
    package_clean('cinder-api')
    package_clean('cinder-scheduler')
    package_clean('cinder-volume')
    package_clean('tgt')
    package_clean('python-cinderclient')
    package_clean('python-mysqldb')


def install():
    """Generate cinder configuration. Execute on both servers"""
    """Configure cinder packages"""
    package_ensure('cinder-api')
    package_ensure('cinder-scheduler')
    package_ensure('cinder-volume')
    package_ensure('tgt')
    package_ensure('python-cinderclient')
    package_ensure('python-mysqldb')
    sudo("echo 'include /var/lib/cinder/volumes/*' > "
         "/etc/tgt/conf.d/cinder.conf")
    sudo("echo 'include /etc/tgt/conf.d/cinder.conf' > /etc/tgt/targets.conf")


def set_config_file(user='cinder', password='stackops', auth_host='127.0.0.1',
                    auth_port='35357', auth_protocol='http',
                    mysql_username='cinder',
                    mysql_password='stackops', mysql_host='127.0.0.1',
                    mysql_port='3306', mysql_schema='cinder', tenant='service',
                    rabbit_password='guest', rabbit_host='localhost',
                    iscsi_ip_address='127.0.0.1'):

    utils.set_option(CINDER_CONF, 'rootwrap_config',
                     '/etc/cinder/rootwrap.conf')
    utils.set_option(CINDER_CONF, 'auth_strategy', 'keystone')
    utils.set_option(CINDER_CONF, 'iscsi_helper', 'tgtadm')
    utils.set_option(CINDER_CONF, 'rpc_backend',
                     'cinder.openstack.common.rpc.impl_kombu')
    utils.set_option(CINDER_CONF, 'rabbit_password', rabbit_password)
    utils.set_option(CINDER_CONF, 'rabbit_host', rabbit_host)
    utils.set_option(CINDER_CONF, 'sql_connection',
                     utils.sql_connect_string(mysql_host, mysql_password,
                                              mysql_port, mysql_schema,
                                              mysql_username))
    utils.set_option(CINDER_CONF, 'verbose', 'true')
    utils.set_option(CINDER_CONF, 'api_paste_config',
                     '/etc/cinder/api-paste.ini')
    utils.set_option(CINDER_CONF, 'volume_group', 'cinder-volumes')
    utils.set_option(CINDER_CONF, 'iscsi_ip_address', iscsi_ip_address)
    utils.set_option(CINDER_CONF, 'log_dir', '/var/log/cinder')
    utils.set_option(CINDER_CONF, 'notification_driver',
                     'cinder.openstack.common.notifier.rpc_notifier')
    utils.set_option(CINDER_CONF, 'notification_topics',
                     'notifications,monitor')
    utils.set_option(CINDER_CONF, 'default_notification_level', 'INFO')
    # Check storage types, TODO: Add more storages types   '''
    utils.set_option(CINDER_CONF, 'scheduler_driver',
                     'cinder.scheduler.filter_scheduler.FilterScheduler')
    utils.set_option(CINDER_API_PASTE_CONF, 'admin_tenant_name',
                     tenant, section='filter:authtoken')
    utils.set_option(CINDER_API_PASTE_CONF, 'admin_user',
                     user, section='filter:authtoken')
    utils.set_option(CINDER_API_PASTE_CONF, 'admin_password',
                     password, section='filter:authtoken')
    utils.set_option(CINDER_API_PASTE_CONF, 'auth_host', auth_host,
                     section='filter:authtoken')
    utils.set_option(CINDER_API_PASTE_CONF, 'auth_port', auth_port,
                     section='filter:authtoken')
    utils.set_option(CINDER_API_PASTE_CONF, 'auth_protocol',
                     auth_protocol, section='filter:authtoken')
    auth_uri = 'http://' + auth_host + ':5000/v2.0'
    utils.set_option(CINDER_API_PASTE_CONF, 'auth_uri',
                     auth_uri, section='filter:authtoken')
    sudo('cinder-manage db sync')


def configure_nfs_storage(nfs_server=None, nfs_sparsed_volumes=True,
                          nfs_shares_config="/var/lib/cinder/nfsshare.conf"):
    ''' Write the list with nfs storage list '''
    shared_nfs_list = nfs_server.split(',')
    for nfs_share in shared_nfs_list:
        sudo("echo \"%s\" >> %s" % (nfs_share, nfs_shares_config))
    with settings(warn_only=True):
        sudo("chown cinder:cinder %s" % (nfs_shares_config))
    utils.set_option(CINDER_CONF, 'volume_driver',
                     'cinder.volume.nfs.NfsDriver')
    utils.set_option(CINDER_CONF, 'nfs_shares_config', nfs_shares_config)
    utils.set_option(CINDER_CONF, 'nfs_mount_point_base',
                     '/var/lib/cinder/volumes/')
    utils.set_option(CINDER_CONF, 'nfs_disk_util', 'df')
    utils.set_option(CINDER_CONF, 'nfs_sparsed_volumes',
                     nfs_sparsed_volumes)


def create_volume(partition='/dev/sdb1'):
    sudo('pvcreate %s' % partition)
    sudo('vgcreate cinder-volumes %s' % partition)


def validate_database(database_type, username, password, host, port,
                      schema, drop_schema=None, install_database=None):
    fab = fabuloso.Fabuloso()
    fab.validate_database(database_type, username, password, host, port,
                          schema, drop_schema, install_database)


def validate_credentials(user, password, tenant, endpoint, admin_token):
    fab = fabuloso.Fabuloso()
    fab.validate_credentials(user, password, tenant, endpoint, admin_token)


def validate_rabbitmq(service_type, host, rport=None, ruser=None,
                      rpassword=None, virtual_host=None):
    fab = fabuloso.Fabuloso()
    fab.send_rabbitMQ(service_type, host, rport, ruser, rpassword,
                      virtual_host)
