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
from cuisine import *
from fabric.api import *

import fabuloso.utils as utils

NEUTRON_API_PASTE_CONF = '/etc/neutron/api-paste.ini'

DHCP_AGENT_CONF = '/etc/neutron/dhcp_agent.ini'

L3_AGENT_CONF = '/etc/neutron/l3_agent.ini'

LBAAS_AGENT_CONF = '/etc/neutron/lbaas_agent.ini'

OVS_PLUGIN_CONF = '/etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini'

ML2_PLUGIN_CONF = '/etc/neutron/plugins/ml2/ml2_conf.ini'

NEUTRON_CONF = '/etc/neutron/neutron.conf'

NEUTRON_METADATA_CONF = '/etc/neutron/metadata_agent.ini'


def openvswitch_stop():
    with settings(warn_only=True):
        sudo("service openvswitch-switch stop")


def openvswitch_start():
    openvswitch_stop()
    sudo("service openvswitch-switch start")


def neutron_plugin_openvswitch_agent_stop():
    with settings(warn_only=True):
        sudo("service neutron-plugin-openvswitch-agent stop")


def neutron_plugin_openvswitch_agent_start():
    neutron_plugin_openvswitch_agent_stop()
    sudo("service neutron-plugin-openvswitch-agent start")


def neutron_dhcp_agent_stop():
    with settings(warn_only=True):
        sudo("service neutron-dhcp-agent stop")


def neutron_dhcp_agent_start():
    neutron_dhcp_agent_stop()
    sudo("service neutron-dhcp-agent start")


def neutron_l3_agent_stop():
    with settings(warn_only=True):
        sudo("service neutron-l3-agent stop")


def neutron_l3_agent_start():
    neutron_l3_agent_stop()
    sudo("service neutron-l3-agent start")


def neutron_metadata_agent_stop():
    sudo("service neutron-metadata-agent stop")


def neutron_metadata_agent_start():
    neutron_metadata_agent_stop()
    with settings(warn_only=True):
        sudo("service neutron-metadata-agent start")


def neutron_lbaas_agent_stop():
    with settings(warn_only=True):
        sudo("service neutron-lbaas-agent stop")


def neutron_lbaas_agent_start():
    neutron_lbaas_agent_stop()
    with settings(warn_only=True):
        sudo("service neutron-lbaas-agent start")


def stop():
    openvswitch_stop()
    neutron_plugin_openvswitch_agent_stop()
    neutron_dhcp_agent_stop()
    neutron_l3_agent_stop()
    neutron_metadata_agent_stop()
    neutron_lbaas_agent_stop()


def start():
    openvswitch_start()
    neutron_plugin_openvswitch_agent_start()
    neutron_dhcp_agent_start()
    neutron_l3_agent_start()
    neutron_metadata_agent_start()
    neutron_lbaas_agent_start()


def compile_datapath():
    package_ensure('openvswitch-datapath-source')
    sudo('DEBIAN_FRONTEND=noninteractive module-assistant -fi '
         'auto-install openvswitch-datapath')


def configure_ubuntu_packages():
    """Configure openvwsitch and neutron packages"""
    package_ensure('python-amqp')
    package_ensure('vlan')
    package_ensure('bridge-utils')
    package_ensure('python-cliff')
    package_ensure('openvswitch-datapath-dkms')
    package_ensure('openvswitch-switch')
    package_ensure('neutron-plugin-openvswitch-agent')
    package_ensure('neutron-l3-agent')
    package_ensure('neutron-dhcp-agent')
    package_ensure('neutron-lbaas-agent')
    package_ensure('haproxy')
    package_ensure('neutron-metadata-agent')
    package_ensure('python-pyparsing')
    package_ensure('python-mysqldb')


def uninstall_ubuntu_packages():
    """Uninstall openvswitch and neutron packages"""
    package_clean('python-amqp')
    package_clean('openvswitch-datapath-dkms')
    package_clean('openvswitch-switch')
    package_clean('python-cliff')
    package_clean('neutron-plugin-openvswitch-agent')
    package_clean('neutron-l3-agent')
    package_clean('neutron-dhcp-agent')
    package_clean('neutron-metadata-agent')
    package_clean('neutron-lbaas-agent')
    package_clean('haproxy')
    package_clean('python-pyparsing')
    package_clean('python-mysqldb')
    package_clean('vlan')
    package_clean('bridge-utils')


def configure_network():
    sudo("sed -i -r 's/^\s*#(net\.ipv4\.ip_forward=1.*)/\\1/' "
         "/etc/sysctl.conf")
    sudo("echo 1 > /proc/sys/net/ipv4/ip_forward")


def install(cluster=False, iface_ex="eth2"):
    """Generate neutron configuration. Execute on both servers"""
    if iface_ex is None:
        puts("{'error':'You need to pass the physical interface as argument "
             "of the external bridge'}")
        return
    configure_ubuntu_packages()
    if cluster:
        stop()
    configure_network()
    openvswitch_start()
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-ex')
    sudo('ovs-vsctl add-br br-ex')
    sudo('ovs-vsctl add-port br-ex %s' % iface_ex)
    sudo('update-rc.d neutron-dhcp-agent defaults 98 02')
    sudo('update-rc.d neutron-l3-agent defaults 98 02')
    sudo('update-rc.d neutron-plugin-openvswitch-agent defaults 98 02')


def configure_ovs_plugin_vlan(iface_bridge='eth1', br_postfix='eth1',
                              vlan_start='1', vlan_end='4094',
                              mysql_username='neutron',
                              mysql_password='stackops',
                              mysql_host='127.0.0.1',
                              mysql_port='3306', mysql_schema='neutron'):

    sudo('echo [database] >> %s' % OVS_PLUGIN_CONF)
    utils.set_option(OVS_PLUGIN_CONF, 'sql_connection',
                     utils.sql_connect_string(mysql_host, mysql_password,
                                              mysql_port, mysql_schema,
                                              mysql_username),
                     section='database')
    utils.set_option(OVS_PLUGIN_CONF, 'reconnect_interval', '2',
                     section='database')
    utils.set_option(OVS_PLUGIN_CONF, 'tenant_network_type', 'vlan',
                     section='ovs')
    utils.set_option(OVS_PLUGIN_CONF, 'network_vlan_ranges', 'physnet1:%s:%s'
                     % (vlan_start, vlan_end), section='ovs')
    utils.set_option(OVS_PLUGIN_CONF, 'bridge_mappings',
                     'physnet1:br-%s' % iface_bridge, section='ovs')
    # security group section
    utils.set_option(OVS_PLUGIN_CONF, 'firewall_driver',
                     'neutron.agent.linux.iptables_firewall.'
                     'OVSHybridIptablesFirewallDriver',
                     section='securitygroup')
    # agent section
    utils.set_option(OVS_PLUGIN_CONF, 'root_helper',
                     'sudo neutron-rootwrap /etc/neutron/rootwrap.conf',
                     section='agent')
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-int')
    sudo('ovs-vsctl add-br br-int')
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-%s' % br_postfix)
    sudo('ovs-vsctl add-br br-%s' % br_postfix)
    sudo('ovs-vsctl add-port br-%s %s' % (br_postfix, iface_bridge))
    openvswitch_start()
    neutron_plugin_openvswitch_agent_start()


def configure_ovs_plugin_gre(ip_tunnel='127.0.0.1', tunnel_start='1',
                             tunnel_end='1000', mysql_username='neutron',
                             mysql_password='stackops', mysql_host='127.0.0.1',
                             mysql_port='3306', mysql_schema='neutron'):
    utils.set_option(OVS_PLUGIN_CONF, 'sql_connection',
                     utils.sql_connect_string(mysql_host, mysql_password,
                                              mysql_port, mysql_schema,
                                              mysql_username),
                     section='DATABASE')
    utils.set_option(OVS_PLUGIN_CONF, 'reconnect_interval', '2',
                     section='DATABASE')
    utils.set_option(OVS_PLUGIN_CONF, 'tenant_network_type', 'gre',
                     section='OVS')
    utils.set_option(OVS_PLUGIN_CONF, 'tunnel_id_ranges',
                     '%s:%s' % (tunnel_start, tunnel_end), section='OVS')
    utils.set_option(OVS_PLUGIN_CONF, 'local_ip', ip_tunnel, section='OVS')
    utils.set_option(OVS_PLUGIN_CONF, 'integration_bridge', 'br-int',
                     section='OVS')
    utils.set_option(OVS_PLUGIN_CONF, 'tunnel_bridge', 'br-tun', section='OVS')
    utils.set_option(OVS_PLUGIN_CONF, 'enable_tunneling', 'True',
                     section='OVS')
    utils.set_option(OVS_PLUGIN_CONF, 'root_helper',
                     'sudo /usr/bin/neutron-rootwrap '
                     '/etc/neutron/rootwrap.conf',
                     section='AGENT')
    #utils.set_option(OVS_PLUGIN_CONF, 'firewall_driver',
    #                 'neutron.agent.linux.iptables_firewall.'
    #                 'OVSHybridIptablesFirewallDriver',
    # section='securitygroup')
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-int')
    sudo('ovs-vsctl add-br br-int')
    openvswitch_start()
    neutron_plugin_openvswitch_agent_start()

def configure_ml2_plugin_vlan(iface_bridge='eth1', br_postfix='eth1',
                              vlan_start='1', vlan_end='4094',
                              mysql_username='neutron',
                              mysql_password='stackops',
                              mysql_host='127.0.0.1',
                              mysql_port='3306', mysql_schema='neutron'):
    # TODO Fix that when ml2-neutron-plugin will be added in icehouse
    sudo('mkdir -p /etc/neutron/plugins/ml2')
    sudo('ln -s %s %s' %(OVS_PLUGIN_CONF, ML2_PLUGIN_CONF))
    sudo('echo "''" > %s' % OVS_PLUGIN_CONF)
    sudo('echo [ml2] >> %s' % OVS_PLUGIN_CONF)
    sudo('echo [ml2_type_vlan] >> %s' % OVS_PLUGIN_CONF)
    sudo('echo [database] >> %s' % OVS_PLUGIN_CONF)
    sudo('echo [securitygroup] >> %s' % OVS_PLUGIN_CONF)
    sudo('echo [agent] >> %s' % OVS_PLUGIN_CONF)
    # ML2 section
    utils.set_option(OVS_PLUGIN_CONF, 'tenant_network_types', 'vlan',
                     section='ml2')
    utils.set_option(OVS_PLUGIN_CONF, 'type_drivers',
                     'local,flat,vlan,gre,vxlan', section='ml2')
    utils.set_option(OVS_PLUGIN_CONF, 'mechanism_drivers',
                     'openvswitch,linuxbridge', section='ml2')
    # ml2_type_vlan section
    utils.set_option(OVS_PLUGIN_CONF, 'network_vlan_ranges', 'physnet1:%s:%s'
                     % (vlan_start, vlan_end), section='ml2_type_vlan')
    # database section
    utils.set_option(OVS_PLUGIN_CONF, 'connection',
                     utils.sql_connect_string(mysql_host, mysql_password,
                                              mysql_port, mysql_schema,
                                              mysql_username),
                     section='database')
    # security group section
    utils.set_option(OVS_PLUGIN_CONF, 'firewall_driver',
                     'neutron.agent.linux.iptables_firewall.'
                     'OVSHybridIptablesFirewallDriver',
                     section='securitygroup')
    # agent section
    utils.set_option(OVS_PLUGIN_CONF, 'root_helper',
                     'sudo neutron-rootwrap /etc/neutron/rootwrap.conf',
                     section='agent')
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-int')
    sudo('ovs-vsctl add-br br-int')
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-%s' % br_postfix)
    sudo('ovs-vsctl add-br br-%s' % br_postfix)
    sudo('ovs-vsctl add-port br-%s %s' % (br_postfix, iface_bridge))
    openvswitch_start()
    neutron_plugin_openvswitch_agent_start()


def configure_lbaas_agent():
    sudo('mkdir -p /etc/neutron/plugins/services/agent_loadbalancer/')
    utils.set_option(LBAAS_AGENT_CONF, 'use_namespaces', 'True')
    utils.set_option(LBAAS_AGENT_CONF, 'interface_driver',
                     'neutron.agent.linux.interface.OVSInterfaceDriver')
    utils.set_option(LBAAS_AGENT_CONF, 'device_driver',
                     'neutron.services.loadbalancer.drivers.haproxy.'
                     'namespace_driver.HaproxyNSDriver')
    utils.set_option(LBAAS_AGENT_CONF, 'user_group', 'haproxy')
    #utils.set_option(LBAAS_AGENT_CONF, 'ovs_use_veth', 'True')



def configure_metadata_agent(user='neutron', password='stackops',
                             auth_host='127.0.0.1',
                             region='RegionOne', metadata_ip='127.0.0.1',
                             tenant='service'):
    auth_url = 'http://' + auth_host + ':35357/v2.0'
    utils.set_option(NEUTRON_METADATA_CONF, 'auth_url', auth_url)
    utils.set_option(NEUTRON_METADATA_CONF, 'auth_region', region)
    utils.set_option(NEUTRON_METADATA_CONF, 'admin_tenant_name', tenant)
    utils.set_option(NEUTRON_METADATA_CONF, 'admin_user', user)
    utils.set_option(NEUTRON_METADATA_CONF, 'admin_password', password)
    utils.set_option(NEUTRON_METADATA_CONF, 'nova_metadata_ip', metadata_ip)
    utils.set_option(NEUTRON_METADATA_CONF, 'nova_metadata_port', '8775')
    utils.set_option(NEUTRON_METADATA_CONF,
                     'metadata_proxy_shared_secret', 'password')


def configure_l3_agent(user='neutron', password='stackops',
                       auth_host='127.0.0.1',
                       region='RegionOne', metadata_ip='127.0.0.1',
                       tenant='service'):
    utils.set_option(L3_AGENT_CONF, 'debug', 'True')
    utils.set_option(L3_AGENT_CONF, 'interface_driver',
                     'neutron.agent.linux.interface.OVSInterfaceDriver')
    auth_url = 'http://' + auth_host + ':35357/v2.0'
    utils.set_option(L3_AGENT_CONF, 'auth_url', auth_url)
    utils.set_option(L3_AGENT_CONF, 'auth_region', region)
    utils.set_option(L3_AGENT_CONF, 'admin_tenant_name', tenant)
    utils.set_option(L3_AGENT_CONF, 'admin_user', user)
    utils.set_option(L3_AGENT_CONF, 'admin_password', password)
    utils.set_option(L3_AGENT_CONF, 'root_helper',
                     'sudo neutron-rootwrap /etc/neutron/rootwrap.conf')
    utils.set_option(L3_AGENT_CONF, 'metadata_ip', metadata_ip)
    utils.set_option(L3_AGENT_CONF, 'use_namespaces', 'True')
    #utils.set_option(L3_AGENT_CONF, 'ovs_use_veth', 'True')


def configure_dhcp_agent(name_server='8.8.8.8'):
    utils.set_option(DHCP_AGENT_CONF, 'use_namespaces', 'True')
    utils.set_option(DHCP_AGENT_CONF, 'dnsmasq_dns_server', name_server)
    utils.set_option(DHCP_AGENT_CONF, 'dhcp_driver',
                     'neutron.agent.linux.dhcp.Dnsmasq')
    utils.set_option(DHCP_AGENT_CONF, 'interface_driver',
                     'neutron.agent.linux.interface.OVSInterfaceDriver')
    #utils.set_option(DHCP_AGENT_CONF, 'ovs_use_veth', 'True')


def set_config_file(user='neutron', password='stackops', auth_host='127.0.0.1',
                    auth_port='35357', auth_protocol='http', tenant='service',
                    rabbit_password='guest', rabbit_host='127.0.0.1',
                    mysql_username='neutron', mysql_password='stackops',
                    mysql_schema='neutron', mysql_host='127.0.0.1',
                    mysql_port='3306'):

    utils.set_option(NEUTRON_API_PASTE_CONF, 'admin_tenant_name',
                     tenant, section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'admin_user',
                     user, section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'admin_password',
                     password, section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_host', auth_host,
                     section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_port', auth_port,
                     section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_protocol', auth_protocol,
                     section='filter:authtoken')
    auth_uri = 'http://' + auth_host + ':5000'
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_uri',
                     auth_uri, section='filter:authtoken')
    #cp = 'neutron.plugins.ml2.plugin.Ml2Plugin'
    cp = 'neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2'
    utils.set_option(NEUTRON_CONF, 'core_plugin', cp)
    utils.set_option(NEUTRON_CONF, 'auth_strategy', 'keystone')
    utils.set_option(NEUTRON_CONF, 'fake_rabbit', 'False')
    utils.set_option(NEUTRON_CONF, 'rabbit_password', rabbit_password)
    utils.set_option(NEUTRON_CONF, 'rabbit_host', rabbit_host)
    utils.set_option(NEUTRON_CONF, 'notification_driver',
                     'neutron.openstack.common.notifier.rpc_notifier')
    utils.set_option(NEUTRON_CONF, 'notification_topics',
                     'notifications,monitor')
    utils.set_option(NEUTRON_CONF, 'default_notification_level', 'INFO')
    utils.set_option(NEUTRON_CONF, 'core_plugin', cp)
    utils.set_option(NEUTRON_CONF, 'connection', utils.sql_connect_string(
        mysql_host, mysql_password, mysql_port, mysql_schema, mysql_username),
                     section='database')
    utils.set_option(NEUTRON_CONF, 'admin_tenant_name',
                     tenant, section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'admin_user',
                     user, section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'admin_password',
                     password, section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_host', auth_host,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_port', auth_port,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_protocol', auth_protocol,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_protocol', auth_protocol,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'allow_overlapping_ips', 'True')
    # security group section
    utils.set_option(OVS_PLUGIN_CONF, 'firewall_driver',
                     'neutron.agent.linux.iptables_firewall.'
                     'OVSHybridIptablesFirewallDriver',
                     section='securitygroup')


def configure_fwaas_service():
    utils.set_option(NEUTRON_CONF, 'service_plugins',
                     'neutron.services.loadbalancer.plugin.LoadBalancerPlugin, '
                     'neutron.services.firewall.fwaas_plugin.FirewallPlugin')
    utils.set_option(NEUTRON_CONF, 'driver',
                     'neutron.services.firewall.drivers.linux.'
                     'iptables_fwaas.IptablesFwaasDriver', section='fwaas')
    utils.set_option(NEUTRON_CONF, 'enabled', 'True', section='fwaas')
    start()


def configure_external_bridge(floating_range):
    sudo('ip addr flush dev br-ex')
    sudo('ip addr add %s dev br-ex' % floating_range)
    sudo('ip link set br-ex up')


def get_net_id(network_name, admin_user, admin_tenant_name, admin_pass,
               auth_url):

    stdout = sudo("neutron --os-auth-url %s --os-username %s --os-password %s "
                  "--os-tenant-name %s net-list | grep %s | awk '/ | "
                  "/ { print $2 }'"
                  % (auth_url, admin_user, admin_pass, admin_tenant_name,
                     network_name))
    puts(stdout)
    return stdout.replace('\n', '')


def get_subnet_id(subnetwork_name, admin_user, admin_tenant_name, admin_pass,
                  auth_url):
    stdout = sudo("neutron --os-auth-url %s --os-username %s --os-password %s "
                  "--os-tenant-name %s subnet-list | grep %s | awk '/ | / "
                  "{ print $2 }'"
                  % (auth_url, admin_user, admin_pass, admin_tenant_name,
                     subnetwork_name))
    puts(stdout)
    return stdout.replace('\n', '')


def get_router_id(router_name, admin_user, admin_tenant_name, admin_pass,
                  auth_url):
    stdout = sudo("neutron --os-auth-url %s --os-username %s --os-password %s "
                  "--os-tenant-name %s router-list | grep %s | awk '/ | / "
                  "{ print $2 }'"
                  % (auth_url, admin_user, admin_pass, admin_tenant_name,
                     router_name))
    puts(stdout)
    return stdout.replace('\n', '')


def configure_external_network(floating_start, floating_end, floating_gw,
                               floating_range, admin_user='admin',
                               admin_tenant_name='admin',
                               admin_pass='stackops',
                               auth_url='http://localhost:5000/v2.0',
                               external_network_name='ext-net'):

    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name '
         '%s net-create %s --provider:network_type local '
         '--router:external=True'
         % (auth_url, admin_user, admin_pass, admin_tenant_name,
            external_network_name))

    external_network_id = get_net_id(external_network_name, admin_user,
                                     admin_tenant_name,
                                     admin_pass, auth_url)
    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name %s subnet-create --ip_version 4 --allocation-pool '
         'start=%s,end=%s --gateway %s --name %s %s %s --enable_dhcp=False'
         % (auth_url, admin_user, admin_pass, admin_tenant_name,
            floating_start, floating_end, floating_gw, external_network_name,
            external_network_id, floating_range))
    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name %s router-create provider-router'
         % (auth_url, admin_user, admin_pass, admin_tenant_name))
    router_id = get_router_id('provider-router', admin_user, admin_tenant_name,
                              admin_pass, auth_url)
    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name %s router-gateway-set %s %s'
         % (auth_url, admin_user, admin_pass, admin_tenant_name, router_id,
            external_network_name))


def add_route_to_neutron_host(private_range, neutron_host):
    sudo('route add -net %s gw %s' % (private_range, neutron_host))


def configure_default_private_network(private_range="10.0.0.0/16",
                                      private_gw="10.0.0.1",
                                      admin_user='admin',
                                      admin_tenant_name='admin',
                                      admin_pass='stackops',
                                      auth_url='http://localhost:5000/v2.0',
                                      network_name='default-private',
                                      dns_list='8.8.8.8 8.8.4.4'):

    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name %s net-create %s'
         % (auth_url, admin_user, admin_pass, admin_tenant_name,
            network_name))
    private_network_id = get_net_id(network_name, admin_user,
                                    admin_tenant_name, admin_pass, auth_url)

    sc = ('neutron --os-auth-url %s --os-username %s --os-password %s '
          '--os-tenant-name %s subnet-create --ip_version 4 %s %s --gateway '
          '%s --dns_nameservers list=true %s --name %s'
          % (auth_url, admin_user, admin_pass, admin_tenant_name,
             private_network_id, private_range, private_gw, dns_list,
             network_name))
    sudo(sc)
    private_subnet_id = get_subnet_id(network_name, admin_user,
                                      admin_tenant_name, admin_pass, auth_url)
    router_id = get_router_id('provider-router', admin_user, admin_tenant_name,
                              admin_pass, auth_url)
    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name %s router-interface-add %s %s'
         % (auth_url, admin_user, admin_pass, admin_tenant_name, router_id,
            private_subnet_id))


def delete_network(network_id, admin_user='admin', admin_tenant_name='admin',
                   admin_pass='stackops',
                   auth_url='http://localhost:5000/v2.0'):
    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name %s net-delete %s'
         % (auth_url, admin_user, admin_pass, admin_tenant_name, network_id))


def delete_router(router_id, admin_user='admin', admin_tenant_name='admin',
                  admin_pass='stackops',
                  auth_url='http://localhost:5000/v2.0'):
    sudo('neutron --os-auth-url %s --os-username %s --os-password %s '
         '--os-tenant-name %s router-delete %s'
         % (auth_url, admin_user, admin_pass, admin_tenant_name, router_id))


def configure_metadata(private_cidr='10.0.0.0/16', neutron_host='127.0.0.1'):
    sudo('route add -net %s gw %s' % (private_cidr, neutron_host))


def configure_iptables(public_ip):
    package_ensure('iptables-persistent')
    sudo('service iptables-persistent flush')
    iptables_conf = text_strip_margin('''
    |
    |# Generated by iptables-save v1.4.4
    |*filter
    |:INPUT ACCEPT [0:0]
    |:FORWARD ACCEPT [0:0]
    |:OUTPUT ACCEPT [0:0]
    |-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    |-A INPUT -d %s/32 -p icmp -m icmp --icmp-type echo-request -j ACCEPT
    |-A INPUT -d %s/32 -j DROP
    |COMMIT
    |''' % (public_ip, public_ip))
    sudo('echo "%s" > /etc/iptables/rules.v4' % iptables_conf)
    sudo('service iptables-persistent start')
