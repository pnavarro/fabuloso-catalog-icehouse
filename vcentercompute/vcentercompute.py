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
from fabric.api import *
from cuisine import *

import fabuloso.utils as utils

PAGE_SIZE = 2 * 1024 * 1024
BONUS_PAGES = 40

NOVA_COMPUTE_CONF = '/etc/nova/nova-compute.conf'

NOVA_CONF = '/etc/nova/nova.conf'

COMPUTE_API_PASTE_CONF = '/etc/nova/api-paste.ini'

NEUTRON_API_PASTE_CONF = '/etc/neutron/api-paste.ini'

NEUTRON_CONF = '/etc/neutron/neutron.conf'


def stop():
    with settings(warn_only=True):
        ntp_stop()
        compute_stop()

def start():
    stop()
    ntp_start()
    compute_start()

def compute_stop():
    with settings(warn_only=True):
        sudo("nohup service nova-api-metadata stop")
    with settings(warn_only=True):
        sudo("nohup service nova-compute stop")


def compute_start():
    compute_stop()
    with settings(warn_only=True):
        sudo("nohup service nova-api-metadata start")
    sudo("nohup service nova-compute start")

def ntp_stop():
    with settings(warn_only=True):
        sudo("service ntp stop")


def ntp_start():
    ntp_stop()
    sudo("service ntp start")


def configure_ubuntu_packages():
    """Configure compute packages"""
    package_ensure('python-amqp')
    package_ensure('python-suds')
    package_ensure('python-software-properties')
    package_ensure('ntp')
    package_ensure('pm-utils')
    package_ensure('nova-compute-qemu')


def uninstall_ubuntu_packages():
    """Uninstall compute packages"""
    package_clean('python-amqp')
    package_clean('python-suds')
    package_clean('python-software-properties')
    package_clean('ntp')
    package_clean('pm-utils')
    package_clean('nova-compute-qemu')


def install(cluster=False):
    """Generate compute configuration. Execute on both servers"""
    configure_ubuntu_packages()
    sudo('rm -rf /etc/nova/nova-compute.conf')
    sudo('ln -s /etc/nova/nova.conf /etc/nova/nova-compute.conf')


def configure_forwarding():
    sudo("sed -i -r 's/^\s*#(net\.ipv4\.ip_forward=1.*)"
         "/\\1/' /etc/sysctl.conf")
    sudo("echo 1 > /proc/sys/net/ipv4/ip_forward")


def configure_network(iface_bridge='eth1', br_postfix='bond-vm',
                      bridge_name=None,
                      bond_parameters='bond_mode=balance-slb '
                                      'other_config:bond-detect-mode=miimon '
                                      'other_config:bond-miimon-interval=100',
                      network_restart=False):

    pass


def configure_ntp(host='ntp.ubuntu.com'):
    sudo('echo "server %s" > /etc/ntp.conf' % host)


def configure_vhost_net():
    sudo('modprobe vhost-net')
    sudo("sed -i '/modprobe vhost-net/d' /etc/rc.local")
    sudo("sed -i '/exit 0/d' /etc/rc.local")
    sudo("echo 'modprobe vhost-net' >> /etc/rc.local")
    sudo("echo 'exit 0' >> /etc/rc.local")


def set_config_file(user='nova',
                    password='stackops',
                    auth_host='127.0.0.1', auth_port='35357',
                    auth_protocol='http', neutron_host='127.0.0.1',
                    rabbit_host='127.0.0.1',
                    vncproxy_host='127.0.0.1', glance_host='127.0.0.1',
                    glance_port='9292', mysql_username='nova',
                    mysql_password='stackops', mysql_schema='nova',
                    mysql_host='127.0.0.1', tenant='service',
                    mysql_port='3306', rabbit_password='guest',
                    vncproxy_port='6080', vcenter_host_ip='localhost',
                    vecenter_host_username='root',
                    vcenter_host_password='stackops',
                    vcenter_cluster_name='my_cluster',
                    integration_bridge='br-int'):

    utils.set_option(COMPUTE_API_PASTE_CONF, 'admin_tenant_name',
                     tenant, section='filter:authtoken')
    utils.set_option(COMPUTE_API_PASTE_CONF, 'admin_user',
                     user, section='filter:authtoken')
    utils.set_option(COMPUTE_API_PASTE_CONF, 'admin_password',
                     password, section='filter:authtoken')
    utils.set_option(COMPUTE_API_PASTE_CONF, 'auth_host', auth_host,
                     section='filter:authtoken')
    utils.set_option(COMPUTE_API_PASTE_CONF, 'auth_port', auth_port,
                     section='filter:authtoken')
    utils.set_option(COMPUTE_API_PASTE_CONF, 'auth_protocol',
                     auth_protocol, section='filter:authtoken')

    utils.set_option(NOVA_COMPUTE_CONF, 'sql_connection',
                     utils.sql_connect_string(mysql_host, mysql_password,
                                              mysql_port, mysql_schema,
                                              mysql_username))
    utils.set_option(NOVA_COMPUTE_CONF, 'start_guests_on_host_boot', 'false')
    utils.set_option(NOVA_COMPUTE_CONF, 'resume_guests_state_on_host_boot',
                     'true')
    utils.set_option(NOVA_COMPUTE_CONF, 'allow_same_net_traffic', 'True')
    utils.set_option(NOVA_COMPUTE_CONF, 'allow_resize_to_same_host', 'True')

    utils.set_option(NOVA_CONF, 'compute_driver',
                     'vmwareapi.VMwareVCDriver')
    # Vmware section
    utils.set_option(NOVA_CONF, 'host_ip',
                     vcenter_host_ip, section='vmware')
    utils.set_option(NOVA_CONF, 'host_username',
                     vecenter_host_username, section='vmware')
    utils.set_option(NOVA_CONF, 'host_passwod',
                     vcenter_host_password, section='vmware')
    utils.set_option(NOVA_CONF, 'cluster_name',
                     vcenter_cluster_name, section='vmware')
    utils.set_option(NOVA_CONF, 'integration_bridge',
                     integration_bridge, section='vmware')
    wsdl_loc = 'http://%s/sdk/vimService.wsdl' % vcenter_host_ip
    utils.set_option(NOVA_CONF, 'wsdl_location', wsdl_loc, section='vmware')
    #utils.set_option(NOVA_CONF, 'datastore_regex',
    #                 datastore_regex, section='vmware')

    utils.set_option(NOVA_COMPUTE_CONF, 'network_api_class',
                     'nova.network.neutronv2.api.API')
    utils.set_option(NOVA_COMPUTE_CONF, 'neutron_auth_strategy',
                     'keystone')
    utils.set_option(NOVA_COMPUTE_CONF, 'neutron_admin_username',
                     'neutron')
    utils.set_option(NOVA_COMPUTE_CONF, 'neutron_admin_password',
                     'stackops')
    utils.set_option(NOVA_COMPUTE_CONF, 'neutron_admin_tenant_name',
                     'service')
    admin_auth_url = 'http://' + auth_host + ':35357/v2.0'
    utils.set_option(NOVA_COMPUTE_CONF, 'neutron_admin_auth_url',
                     admin_auth_url)
    neutron_url = 'http://' + neutron_host + ':9696'
    utils.set_option(NOVA_COMPUTE_CONF, 'neutron_url',
                     neutron_url)
    utils.set_option(NOVA_COMPUTE_CONF, 'rpc_backend', 'nova.rpc.impl_kombu')
    utils.set_option(NOVA_COMPUTE_CONF, 'rabbit_host', rabbit_host)
    utils.set_option(NOVA_COMPUTE_CONF, 'rabbit_password', rabbit_password)

    utils.set_option(NOVA_COMPUTE_CONF, 'auth_strategy', 'keystone')
    utils.set_option(NOVA_COMPUTE_CONF, 'use_deprecated_auth', 'false')
    utils.set_option(NOVA_COMPUTE_CONF, 'logdir', '/var/log/nova')
    utils.set_option(NOVA_COMPUTE_CONF, 'state_path', '/var/lib/nova')
    utils.set_option(NOVA_COMPUTE_CONF, 'lock_path', '/var/lock/nova')
    utils.set_option(NOVA_COMPUTE_CONF, 'root_helper',
                     'sudo nova-rootwrap /etc/nova/rootwrap.conf')
    utils.set_option(NOVA_COMPUTE_CONF, 'verbose', 'true')
    utils.set_option(NOVA_COMPUTE_CONF, 'notification_driver',
                     'nova.openstack.common.notifier.rpc_notifier')
    utils.set_option(NOVA_COMPUTE_CONF, 'notification_topics',
                     'notifications,monitor')
    utils.set_option(NOVA_COMPUTE_CONF, 'default_notification_level', 'INFO')

    utils.set_option(NOVA_COMPUTE_CONF, 'start_guests_on_host_boot',
                     'false')
    utils.set_option(NOVA_COMPUTE_CONF, 'resume_guests_state_on_host_boot',
                     'false')

    utils.set_option(NOVA_COMPUTE_CONF, 'novncproxy_base_url',
                     'http://%s:%s/vnc_auto.html'
                     % (vncproxy_host, vncproxy_port))
    utils.set_option(NOVA_COMPUTE_CONF, 'vncserver_listen', '0.0.0.0')
    utils.set_option(NOVA_COMPUTE_CONF, 'vnc_enable', 'true')

    utils.set_option(NOVA_COMPUTE_CONF, 'compute_driver',
                     'libvirt.LibvirtDriver')

    utils.set_option(NOVA_COMPUTE_CONF, 'image_service',
                     'nova.image.glance.GlanceImageService')
    utils.set_option(NOVA_COMPUTE_CONF, 'glance_api_servers',
                     '%s:%s' % (glance_host, glance_port))

    utils.set_option(NOVA_COMPUTE_CONF, 'rabbit_host', rabbit_host)
    utils.set_option(NOVA_COMPUTE_CONF, 'rabbit_password', rabbit_password)

    utils.set_option(NOVA_COMPUTE_CONF, 'ec2_private_dns_show_ip', 'True')
    utils.set_option(NOVA_COMPUTE_CONF, 'network_api_class',
                     'nova.network.neutronv2.api.API')
    utils.set_option(NOVA_COMPUTE_CONF, 'dmz_cidr', '169.254.169.254/32')
    utils.set_option(NOVA_COMPUTE_CONF, 'volume_api_class',
                     'nova.volume.cinder.API')
    utils.set_option(NOVA_COMPUTE_CONF, 'cinder_catalog_info',
                     'volume:cinder:internalURL')

    utils.set_option(NOVA_COMPUTE_CONF, 'allow_same_net_traffic',
                     'True')
    start()


def get_memory_available():
    return 1024 * int(sudo("cat /proc/meminfo | grep 'MemTotal' | "
                           "sed 's/[^0-9\.]//g'"))


def configure_nfs_storage(nfs_server, delete_content=False,
                          set_nova_owner=True,
                          nfs_server_mount_point_params='defaults'):
    pass


def configure_local_storage(delete_content=False, set_nova_owner=True):
    pass
