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
    s1 = net.addSwitch('s1', cls=OVSSwitch, mac='00:00:00:00:00:10', protocols='OpenFlow13')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:01', defaultRoute='via 10.0.0.2') # defaultRoute es la ip del nat

    info('*** Add NAT\n')
    net.addNAT().configDefault()


    net.addLink(s1, h1, bw=10, delay='0.2ms')
    #net.addLink(s1, nat1)
    #net.addLink(s3, nat1)
    #net.addLink(s3, nat2)  
    #net.addLink(s2, nat2)  
    #net.staticArp()


    info( '*** Starting network\n')
    net.build()
    net.start()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()


    info( '*** Starting switches\n')
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
