/********************************************************************************************************
 * 																										*
 * Project Name: dissectorapp															                *
 * Author: Manuel Sánchez López (@M4nu_sl)															    *
 * github: pahharo															                            *
 * Description: This project concerns the creation of a deep packet inspector that is going to detect   *
 * the youtube traffic and it must be marked to offer quality of service in the network. It is based on *
 * the OpenDaylight controller and the communication is over OpenFlow protocol.                         *
 * 															                                            *
 * *****************************************************************************************************/




package ugr.manu.dissectorapp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
//import readmejava.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.io.UnsupportedEncodingException;
import java.lang.Object;
import java.lang.Enum;

import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.SetDlDst;
import org.opendaylight.controller.sal.action.SetDlSrc;
import org.opendaylight.controller.sal.action.SetNwDst;
import org.opendaylight.controller.sal.action.SetNwSrc;
import org.opendaylight.controller.sal.action.SetNwTos;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.yang.gen.v1.urn.opendaylight.openflow.augments.rev131002.NwTosAction;
import org.opendaylight.yang.gen.v1.urn.opendaylight.openflow.augments.rev131002.NwTosActionBuilder;
import org.opendaylight.yangtools.yang.binding.DataContainer;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.projectfloodlight.openflow.protocol.match.MatchFields;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//////
//import org.opendaylight.controller.protocol_plugin.openflow.IDataPacketListen;
//import org.opendaylight.controller.protocol_plugin.openflow.core.IMessageListener;





//import org.opendaylight.controller.sal.packet.UDP;
//import org.opendaylight.controller.
import static java.nio.charset.StandardCharsets.*;
/*
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.U16;
*/
//////
public class DissectorHandler implements IListenDataPacket {
    
    private static final Logger log = LoggerFactory.getLogger(DissectorHandler.class);
	private static final Object SetNwTos = 3;
    //private static final String PUBLIC_IP = "10.0.0.100";
    //private static final int SERVICE_PORT = 7777;
    //private static final String SERVER1_IP = "10.0.0.1";
    //private static final String SERVER2_IP = "10.0.0.2";
    //private static final byte[] SERVER1_MAC = {0,0,0,0,0,0x01};
    //private static final byte[] SERVER2_MAC = {0,0,0,0,0,0x02};
    //private static final byte[] SERVICE_MAC = {0,0,0,0,0,0x64};
    //private static final String SERVER1_CONNECTOR_NAME = "s1-eth1";
    //private static final String SERVER2_CONNECTOR_NAME = "s1-eth2";
    private IDataPacketService dataPacketService;
    private IFlowProgrammerService flowProgrammerService;
    private ISwitchManager switchManager;
    //
    private Map<Node, Map<Long, NodeConnector>> mac_to_port_per_switch = new HashMap<Node, Map<Long, NodeConnector>>();
    //
    //private InetAddress publicInetAddress;
    //private InetAddress server1Address;
    //private InetAddress server2Address;
    //private int serverNumber = 0;
    /*
    static private InetAddress intToInetAddress(int i) {
        byte b[] = new byte[] { (byte) ((i>>24)&0xff), (byte) ((i>>16)&0xff), (byte) ((i>>8)&0xff), (byte) (i&0xff) };
        InetAddress addr;
        try {
            addr = InetAddress.getByAddress(b);
        } catch (UnknownHostException e) {
            return null;
        }

        return addr;
    }
    

    public DissectorHandler() {
        try {
            publicInetAddress = InetAddress.getByName(PUBLIC_IP);
        } catch (UnknownHostException e) {
            log.error(e.getMessage());
        }
        
        try {
            server1Address = InetAddress.getByName(SERVER1_IP);
        } catch (UnknownHostException e) {
            log.error(e.getMessage());
        }
        
        try {
            server2Address = InetAddress.getByName(SERVER2_IP);
        } catch (UnknownHostException e) {
            log.error(e.getMessage());
        }
    }
    */
    
    /**
     * Sets a reference to the requested DataPacketService
     */
    void setDataPacketService(IDataPacketService s) {
        log.trace("Set DataPacketService.");

        dataPacketService = s;
    }

    /**
     * Unsets DataPacketService
     */
    void unsetDataPacketService(IDataPacketService s) {
        log.trace("Removed DataPacketService.");

        if (dataPacketService == s) {
            dataPacketService = null;
        }
    }
    
    /**
     * Sets a reference to the requested FlowProgrammerService
     */
    void setFlowProgrammerService(IFlowProgrammerService s) {
        log.trace("Set FlowProgrammerService.");

        flowProgrammerService = s;
    }

    /**
     * Unsets FlowProgrammerService
     */
    void unsetFlowProgrammerService(IFlowProgrammerService s) {
        log.trace("Removed FlowProgrammerService.");

        if (flowProgrammerService == s) {
            flowProgrammerService = null;
        }
    }

    /**
     * Sets a reference to the requested SwitchManagerService
     */
    void setSwitchManagerService(ISwitchManager s) {
        log.trace("Set SwitchManagerService.");
        switchManager = s;
    }

    /**
     * Unsets SwitchManagerService
     */
    void unsetSwitchManagerService(ISwitchManager s) {
        log.trace("Removed SwitchManagerService.");
        if (switchManager == s) {
            switchManager = null;
        }
    }
    
    //////////////////////////////////
    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     * Con esta función deshabilitamos el paquete simple-forwading.
     */
    void init() {
        log.info("Initialized");
        // Disabling the SimpleForwarding and ARPHandler bundle to not conflict with this one
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        for(Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getSymbolicName().contains("simpleforwarding")) {
                try {
                    bundle.uninstall();
                } catch (BundleException e) {
                    log.error("Exception in Bundle uninstall "+bundle.getSymbolicName(), e); 
                }   
            } 
        }
    }
    
    private void floodPacket(RawPacket inPkt) {
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();
        Set<NodeConnector> nodeConnectors = this.switchManager.getUpNodeConnectors(incoming_node);
        for (NodeConnector p : nodeConnectors) {
            if (!p.equals(incoming_connector)) {
                try {
                    RawPacket destPkt = new RawPacket(inPkt);
                    destPkt.setOutgoingNodeConnector(p);
                    this.dataPacketService.transmitDataPacket(destPkt);
                    //log.info("Datos de paquete transmitido dentro de floodpacket: "+this.dataPacketService.decodeDataPacket(destPkt).toString());
                } catch (ConstructionException e2) {
                    continue;
                }
            }
        }
    }
    ///////////////////////////////////
    
    /**
     * Con esta función tratamos el paquete recibido.
     **/
    public PacketResult receiveDataPacket(RawPacket inPkt) {
    	if (inPkt == null) {
            return PacketResult.IGNORED;
        }
    	// The connector, the packet came from ("port")
        NodeConnector ingressConnector = inPkt.getIncomingNodeConnector();
        // The node that received the packet ("switch")
        Node node = ingressConnector.getNode();
        log.trace("Packet from " + node.getNodeIDString() + " " + ingressConnector.getNodeConnectorIDString());
        /////////////////////////////////////////////////////////////
        Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();
        if(formattedPak instanceof Ethernet) {
        	Ethernet ethFrame = (Ethernet) formattedPak;
            Object l3Pkt = ethFrame.getPayload();
        	byte[] srcMAC = ((Ethernet)formattedPak).getSourceMACAddress();
            byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();
            long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
            long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
            Match match = new Match();
            match.setField( new MatchField(MatchType.IN_PORT, incoming_connector) );
            match.setField( new MatchField(MatchType.DL_DST, dstMAC.clone()) );
            //match.setField(MatchType.NW_TOS, (byte) 1);
            //log.info("antes");
            //match.setField(MatchType.NW_TOS, (byte) 0);
            //log.info("despues");
            /////
            if (l3Pkt instanceof IPv4) {
                IPv4 ipv4Pkt = (IPv4) l3Pkt;
                Object l4Datagram = ipv4Pkt.getPayload();
                ipv4Pkt.getSourceAddress();
                // Esta es la clave para que añada el flujo!!!!!!!! no borrarrrrr
                match.setField(MatchType.DL_TYPE, (short) 0x0800);  // IPv4 ethertype
                match.setField(MatchType.NW_PROTO, (byte) 6);       // TCP protocol id
                //byte tos = 1;            	
                if (l4Datagram instanceof TCP){
                	TCP tcpDatagram = (TCP) l4Datagram;
                	byte[] tcpRawPayload = tcpDatagram.getRawPayload();
                	log.info("Payload del paquete TCP: "+Arrays.toString(tcpRawPayload));
                	//String tcpRawPayData = new String(tcpRawPayload, UTF_8);
                	//log.info("Payload de UDP en string: "+tcpRawPayData);
                    byte[] arrayPacketData = inPkt.getPacketData();
                    log.info("Datos del paquete arrayPacketData: "+Arrays.toString(arrayPacketData));
                    String datosDNS = new String(arrayPacketData, UTF_8);
                    //log.info("Los datos del paquete son en UTF-8: "+datosDNS);
                    if(datosDNS.contains("googlevideo")){
                    	log.info("Lo tenemos!!!");
                    	//match.setField(MatchType.NW_TOS, (byte) 0x01);                    	
                    }
                }
            }
            /////
         // Set up the mapping: switch -> src MAC address -> incoming port
            if (this.mac_to_port_per_switch.get(incoming_node) == null) {
                this.mac_to_port_per_switch.put(incoming_node, new HashMap<Long, NodeConnector>());
            }            
            this.mac_to_port_per_switch.get(incoming_node).put(srcMAC_val, incoming_connector);

            NodeConnector dst_connector = this.mac_to_port_per_switch.get(incoming_node).get(dstMAC_val);
            
            
         // Do I know the destination MAC?
            if (dst_connector != null) {
                List<Action> actions = new ArrayList<Action>();
                actions.add(new Output(dst_connector));
                actions.add(new SetNwTos(1));
                //int tos = 1;
                //actions.add(new SetNwTos(tos));
                log.info("Prueba diquiticien");
                //log.info("Añadiendo flujo: "+match.getMatches()+"\nAcciones a realizar"+actions.toString());
                Flow f = new Flow(match, actions);
                
                // Modify the flow on the network node
                Status status = flowProgrammerService.addFlow(incoming_node, f);
                if (!status.isSuccess()) {
                    log.warn(
                            "SDN Plugin failed to program the flow: {}. The failure is: {}",
                            f, status.getDescription());
                    return PacketResult.IGNORED;
                }
                log.info("Installed flow {} in node {}",
                        f, incoming_node);
            }
            /*else 
                floodPacket(inPkt);*/
        }
        /////////////////////////////////////////////////////////////
        
        /*
        // Use DataPacketService to decode the packet.
        Packet pkt = this.dataPacketService.decodeDataPacket(inPkt);
        
        if (pkt instanceof Ethernet) {
            Ethernet ethFrame = (Ethernet) pkt;
            Object l3Pkt = ethFrame.getPayload();
	        //
            byte[] srcMAC = ((Ethernet)pkt).getSourceMACAddress();
            byte[] dstMAC = ((Ethernet)pkt).getDestinationMACAddress();
            long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
            long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
            //
         
            if (l3Pkt instanceof IPv4) {
                IPv4 ipv4Pkt = (IPv4) l3Pkt;
                InetAddress clientAddr = intToInetAddress(ipv4Pkt.getSourceAddress());
                InetAddress dstAddr = intToInetAddress(ipv4Pkt.getDestinationAddress());
                Object l4Datagram = ipv4Pkt.getPayload();
                if (l4Datagram instanceof TCP) {
                    TCP tcpDatagram = (TCP) l4Datagram;
                    int clientPort = tcpDatagram.getSourcePort();
                    int dstPort = tcpDatagram.getDestinationPort();

                    if (publicInetAddress.equals(dstAddr) && dstPort == SERVICE_PORT) { 
                        log.info("Received packet for load balanced service");
                        
                        // Select one of the two servers round robin.
                        
                        InetAddress serverInstanceAddr;
                        byte[] serverInstanceMAC;
                        NodeConnector egressConnector;
                        
                        // Synchronize in case there are two incoming requests at the same time.
                        synchronized (this) {
                            if (serverNumber == 0) {
                                log.info("Server 1 is serving the request");
                                serverInstanceAddr = server1Address;
                                serverInstanceMAC = SERVER1_MAC;
                                egressConnector = switchManager.getNodeConnector(node, SERVER1_CONNECTOR_NAME);
                                serverNumber = 1;
                            } else {
                                log.info("Server 2 is serving the request");
                                serverInstanceAddr = server2Address;
                                serverInstanceMAC = SERVER2_MAC;
                                egressConnector = switchManager.getNodeConnector(node, SERVER2_CONNECTOR_NAME);
                                serverNumber = 0;
                            }
                        }
                                  
                        // Create flow table entry for further incoming packets
                        
                        // Match incoming packets of this TCP connection 
                        // (4 tuple source IP, source port, destination IP, destination port)
                        Match match = new Match();
                        match.setField(MatchType.DL_TYPE, (short) 0x0800);  // IPv4 ethertype
                        match.setField(MatchType.NW_PROTO, (byte) 6);       // TCP protocol id
                        match.setField(MatchType.NW_SRC, clientAddr);
                        match.setField(MatchType.NW_DST, dstAddr);
                        match.setField(MatchType.TP_SRC, (short) clientPort);
                        match.setField(MatchType.TP_DST, (short) dstPort);

                        // List of actions applied to the packet
                        List<Action> actions = new LinkedList<Action>();
                        
                        // Re-write destination IP to server instance IP
                        actions.add(new SetNwDst(serverInstanceAddr));
                        
                        // Re-write destination MAC to server instance MAC
                        actions.add(new SetDlDst(serverInstanceMAC));
                        
                        // Output packet on port to server instance
                        actions.add(new Output(egressConnector));
                        
                        // Create the flow
                        Flow flow = new Flow(match, actions);
                        
                        // Use FlowProgrammerService to program flow.
                        Status status = flowProgrammerService.addFlow(node, flow);
                        if (!status.isSuccess()) {
                            log.error("Could not program flow: " + status.getDescription());
                            return PacketResult.CONSUME;
                        }
                                               
                        // Create flow table entry for response packets from server to client
                        
                        // Match outgoing packets of this TCP connection 
                        match = new Match();
                        match.setField(MatchType.DL_TYPE, (short) 0x0800); 
                        match.setField(MatchType.NW_PROTO, (byte) 6);
                        match.setField(MatchType.NW_SRC, serverInstanceAddr);
                        match.setField(MatchType.NW_DST, clientAddr);
                        match.setField(MatchType.TP_SRC, (short) dstPort);
                        match.setField(MatchType.TP_DST, (short) clientPort);
                        
                        
                        // Re-write the server instance IP address to the public IP address
                        actions = new LinkedList<Action>();
                        actions.add(new SetNwSrc(publicInetAddress));
                        actions.add(new SetDlSrc(SERVICE_MAC));
                        
                        // Output to client port from which packet was received
                        actions.add(new Output(ingressConnector));
                        
                        flow = new Flow(match, actions);
                        status = flowProgrammerService.addFlow(node, flow);
                        if (!status.isSuccess()) {
                            log.error("Could not program flow: " + status.getDescription());
                            return PacketResult.CONSUME;
                        }
                        
                        // Forward initial packet to selected server
                      
                        log.trace("Reenviando paquete a " + serverInstanceAddr.toString() + " por el puerto " + egressConnector.getNodeConnectorIDString());
                        ethFrame.setDestinationMACAddress(serverInstanceMAC);
                        ipv4Pkt.setDestinationAddress(serverInstanceAddr);
                        inPkt.setOutgoingNodeConnector(egressConnector);                       
                        dataPacketService.transmitDataPacket(inPkt);
                        return PacketResult.CONSUME;
                    }
                    else 
                        floodPacket(inPkt);
                    	
                }
            }
        	floodPacket(inPkt);
        	
        }*/
        
        // We did not process the packet -> let someone else do the job.
        return PacketResult.IGNORED;
    }


}
