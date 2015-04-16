#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info, lg
from mininet.link import TCLink, Intf
from subprocess import call

from mininet.nodelib import NAT
from mininet.topolib import TreeNet
"""
			    __________
			   /          \
           h1	 nat0-----|  INTERNET  |   
           |	  |	   \__________/
           s1-----
     ______|_______
    |              |
   s2              s3
    |              |
   h2              h3
"""

def myNetwork():

    net = Mininet( topo=None,
                   listenPort=6633,
                   build=False,
                   ipBase='10.0.0.0/8',
		   link=TCLink,
		   )

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
		      protocols='OpenFlow13',
		      ip='127.0.0.1'
                     )

    info( '*** Add switches\n')
    s1 = net.addSwitch('s3', cls=OVSSwitch, mac='00:00:00:00:00:06', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSSwitch, mac='00:00:00:00:00:05', protocols='OpenFlow13')
    s3 = net.addSwitch('s1', cls=OVSSwitch, mac='00:00:00:00:00:04', protocols='OpenFlow13')

    info( '*** Add hosts\n')
    h1 = net.addHost('h3', cls=Host, ip='10.0.0.3', mac='00:00:00:00:00:03', defaultRoute='via 10.0.0.4')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', mac='00:00:00:00:00:02', defaultRoute='via 10.0.0.4')
    h3 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:01', defaultRoute='via 10.0.0.4')
    # La ruta por defecto de los host es la de NAT (10.0.0.4 en este caso)

    info('*** Add NAT\n')
    net.addNAT().configDefault()


    info( '*** Add links\n')
    net.addLink(s1, s2, bw=10, delay='0.2ms')
    net.addLink(s1, s3, bw=10, delay='0.2ms')
    #net.addLink(s2, s1, bw=10, delay='0.2ms') #Esta linea con este controlador provoca errores.
    net.addLink(s1, h1, bw=10, delay='0.2ms')
    net.addLink(s2, h2, bw=10, delay='0.2ms')
    net.addLink(s3, h3, bw=10, delay='0.2ms')


    info( '*** Starting network\n')
    net.build()
    net.start()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()


    info( '*** Starting switches\n')
    net.get('s3').start([c0])
    net.get('s2').start([c0])
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
