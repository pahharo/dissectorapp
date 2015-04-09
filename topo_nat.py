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

from mininet.topolib import TreeNet
"""
           h3
           |
           s3
     ______|_______
    |              |
   nat1           nat2
    |              |
   s1              s2
    |              |
   h1              h2
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
                      protocol='tcp', protocols='OpenFlow13',
		      ip='127.0.0.1'
                     )

    info( '*** Add switches\n')
    s3 = net.addSwitch('s3', cls=OVSSwitch, mac='00:00:00:00:00:06', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSSwitch, mac='00:00:00:00:00:05', protocols='OpenFlow13')
    s1 = net.addSwitch('s1', cls=OVSSwitch, mac='00:00:00:00:00:04', protocols='OpenFlow13')

    info( '*** Add hosts\n')
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', mac='00:00:00:00:00:03')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', mac='00:00:00:00:00:02')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:01')
    info('*** Add NAT\n')
    nat1 = net.addNAT(name='nat1', connect=True, ip = '10.0.0.7')
    nat2 = net.addNAT(name='nat2', connect=True, ip = '10.0.0.8')

    info( '*** Add links\n')
    net.addLink(s3, s1, bw=10, delay='0.2ms')
    net.addLink(s3, s2, bw=10, delay='0.2ms')
    #net.addLink(s2, s1, bw=10, delay='0.2ms') #Esta linea con este controlador provoca errores.
    net.addLink(s3, h3, bw=10, delay='0.2ms')
    net.addLink(s2, h2, bw=10, delay='0.2ms')
    net.addLink(s1, h1, bw=10, delay='0.2ms')
    net.addLink(s1, nat1)
    net.addLink(s3, nat1)
    net.addLink(s3, nat2)  
    net.addLink(s2, nat2)  
    net.staticArp()


    info( '*** Starting network\n')
    net.build()
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
