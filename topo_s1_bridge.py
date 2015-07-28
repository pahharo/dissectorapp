#!/usr/bin/python

"""
Copyright (C) 2015 Manuel Sanchez Lopez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have getTransmitErrorCountd a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

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
		bridge	
	 _________________
      --|---s1 ----wlan0--|---INTERNET
      | |_________________|
      |
      h1
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
    s1 = net.addSwitch('s1', cls=OVSSwitch, mac='00:00:00:00:00:04', protocols='OpenFlow13')
    #s1 = net.addSwitch('s1', ip='10.0.0.10')



    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', mac='00:00:00:00:00:02')

    info( '*** Add links\n') 
    net.addLink(s1, h1, bw=10, delay='0.2ms')
    net.addLink(s1, h2, bw=10, delay='0.2ms')

    info( '*** Add bridge\n')
    Intf('eth1',node=s1)

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
