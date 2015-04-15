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

import org.apache.log4j.pattern.SequenceNumberPatternConverter;
import org.opendaylight.controller.protocol_plugin.openflow.core.internal.Controller;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Flood;
import org.opendaylight.controller.sal.action.Loopback;
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
import org.opendaylight.controller.sal.packet.ARP;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.packet.UDP;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.openflowjava.protocol.impl.core.TlsDetector;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.flow.node.supported.match.types.MatchTypeBuilder;
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














import aQute.bnd.service.diff.Tree.Data;
//import org.opendaylight.controller.sal.packet.UDP;
//import org.opendaylight.controller.
import static java.nio.charset.StandardCharsets.*;

public class DissectorHandler implements IListenDataPacket {
    
    private static final Logger log = LoggerFactory.getLogger(DissectorHandler.class);
    private boolean youtubeTraffic=false;
    private boolean webTraffic=false;
    private boolean VoIPTraffic=false;
    private int contadorTraficoWeb = 0;
    private boolean añadeFlujo = false;
    private int actualDstAddr;
    private int actualSrcAddr;
    private boolean primeravez = true;

    
	private IDataPacketService dataPacketService;
    private IFlowProgrammerService flowProgrammerService;
    private ISwitchManager switchManager;
    //
    private Map<Node, Map<Long, NodeConnector>> mac_to_port_per_switch = new HashMap<Node, Map<Long, NodeConnector>>();
    NodeConnector dst_connector=null;
    
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
    
    
    /**
     * Función utilizada para inundar en caso de no tener la dirección destino
     * @param inPkt: paquete entrante al nodo
     */
    private void floodPacket(RawPacket inPkt) {
    	log.info("flooding packet");
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
    
    /**
     * Con esta función tratamos el paquete recibido.
     **/
    public PacketResult receiveDataPacket(RawPacket inPkt) {
    	if (inPkt == null) {
            return PacketResult.IGNORED;
        }
    	// The connector, the packet came from ("port")
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        // The node that received the packet ("switch")
        Node node = incoming_connector.getNode();
        log.trace("Packet from " + node.getNodeIDString() + " " + incoming_connector.getNodeConnectorIDString());
        Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);
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
            match.setField( new MatchField(MatchType.DL_DST, dstMAC) );
            match.setField( new MatchField(MatchType.DL_SRC, srcMAC) );
            /*if(l3Pkt instanceof ARP){
                match.setField(MatchType.DL_TYPE, (short) 0x0806);       // ARP protocol id
            }*/
            
            
            if (l3Pkt instanceof IPv4) {
                IPv4 ipv4Pkt = (IPv4) l3Pkt;
                Object l4Datagram = ipv4Pkt.getPayload();
                InetAddress srcIPaddr = intToInetAddress(ipv4Pkt.getSourceAddress());
                InetAddress dstIPaddr = intToInetAddress(ipv4Pkt.getDestinationAddress());
                
                int src = ipv4Pkt.getSourceAddress();
                int dst = ipv4Pkt.getDestinationAddress();
                
                // Esta es la clave para que añada el flujo!!!!!!!! no borrarrrrr
                match.setField(MatchType.DL_TYPE, (short) 0x0800);  // IPv4 ethertype
                match.setField(new MatchField(MatchType.NW_SRC, srcIPaddr));
                match.setField(new MatchField(MatchType.NW_DST, dstIPaddr));
                if (l4Datagram instanceof TCP){
                	TCP tcpDatagram = (TCP) l4Datagram;
                    int dstPort = tcpDatagram.getDestinationPort();
                    int srcPort = tcpDatagram.getSourcePort();
                    match.setField(MatchType.NW_PROTO, (byte) 6);       // TCP protocol id
                    match.setField(MatchType.TP_DST, (short) dstPort);                             	
                	webTraffic = isWebTraffic(tcpDatagram);
                	if(isWebTraffic(tcpDatagram)){
	                    if(dstPort==443 || srcPort==443 || dstPort==80 || srcPort==80){
	                        if(primeravez){
	                        	actualDstAddr = dst;
	                        	actualSrcAddr = src;
	                        	primeravez = false;
	                        	log.info("entra primera vez");
	                        }
		                    if(dst == actualDstAddr && src == actualSrcAddr) {
		                    	contadorTraficoWeb++;
		                    } else if(dst == actualSrcAddr && src == actualDstAddr){
		                    	contadorTraficoWeb++;
		                    } else {                 	
		                    	actualDstAddr = dst;
		                    	actualSrcAddr = src;
		                    	contadorTraficoWeb=1;
		                    }
	                    }
                	}
                	
                	//log.info("Payload del paquete TCP: "+Arrays.toString(tcpRawPayload));
                	//String tcpRawPayData = new String(tcpRawPayload, UTF_8);
                	//log.info("Payload de UDP en string: "+tcpRawPayData);
                    byte[] arrayPacketData = inPkt.getPacketData();
                	//String datosTCP = new String(arrayPacketData, UTF_8);
                	//log.info("A ver que se muestra: "+datosTCP);
                    youtubeTraffic = isYoutubeTraffic(arrayPacketData);
                    /*if(l4Datagram instanceof TlsDetector){
                        match.setField(MatchType.DL_TYPE, (short) 0x38);  // TLS ethertype
                    }*/
                }
                if (l4Datagram instanceof UDP){
                	UDP udpDatagram = (UDP) l4Datagram;
                    match.setField(MatchType.NW_PROTO, (byte) 17);       // UDP protocol id
                	//byte[] udpRawPayload = udpDatagram.getRawPayload();
                	//log.info("Payload del paquete TCP: "+Arrays.toString(udpRawPayload));
                    VoIPTraffic = isVoIPTraffic(udpDatagram);
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
                if(webTraffic){
                	webTraffic = false;
                	if(contadorTraficoWeb==3 || contadorTraficoWeb==4){
                		if(youtubeTraffic){
                			contadorTraficoWeb=0;
                			añadeFlujo=true;
                        	youtubeTraffic = false;
                        	log.info("Nuevo ToS para tráfico Youtube");
                            actions.add(new SetNwTos(1)); 
                		} else {
                			añadeFlujo = false;
                			floodPacket(inPkt);
                		}
                	} else if(contadorTraficoWeb==5){	
                		if(youtubeTraffic){
                			contadorTraficoWeb=0;
                			añadeFlujo=true;
                        	youtubeTraffic = false;
                        	log.info("Nuevo ToS para tráfico Youtube");
                            actions.add(new SetNwTos(1)); 
                		} else {
                			añadeFlujo = true;
                			contadorTraficoWeb=0;
                            actions.add(new SetNwTos(2)); 
                		}	
                	} else {
                        añadeFlujo=false;
                        floodPacket(inPkt);
            		}
                } else if (VoIPTraffic){
                	añadeFlujo = true;
                	VoIPTraffic = false;
                	actions.add(new SetNwTos(3));    
                } else {
                	añadeFlujo = true;
                }                
                
                if(añadeFlujo){
	                Flow f = new Flow(match, actions);
	                añadeFlujo = false;
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

            }
            else 
                floodPacket(inPkt);
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
    
    /**
     * Función que comprueba si el tráfico pertenece a un flujo de
     * streaming de video enviado por Youtube
     * @param arrayPacketData: es el paquete de datos en el que
     * buscaremos el string "googlevideo"
     * @return Nos devuelve una booleana indicando si el paquete es
     * de tráfico Youtube o no.
     */
    private boolean isYoutubeTraffic(byte[] arrayPacketData){
    	
    	boolean youtubeTraffic = false;
    	String datosTCP = new String(arrayPacketData, UTF_8);
        //log.info("Los datos del paquete son en UTF-8: "+datosDNS);
        if(datosTCP.contains("googlevideo")){
        	// ...añadir el ToS más adelante en el flujo en caso de "true"
        	youtubeTraffic=true;
        }
    	return youtubeTraffic;
    }
    /**
     * 
     * @param udpPacket
     * @return
     */
    private boolean isVoIPTraffic(UDP udpPacket){
    	
    	boolean VoIPTraffic = false;
    	
    	if( udpPacket.getDestinationPort()==4569 /*IAX --> UDP*/
    	 || udpPacket.getDestinationPort()==1720 /*H323 --> TCP*/
    	 || udpPacket.getDestinationPort()==2000 /*SCCP --> TCP*/ 
    	 || udpPacket.getDestinationPort()==9082 /*Prueba Skype --> UDP*/ ){
    		VoIPTraffic=true;
    	}

    	return VoIPTraffic;
    }
    
    /**
     * Función que comprueba si el tráfico es de tipo WEB
     * @param tcpPacket Paquete tcp recibido
     * @return devolvemos una booleana que informará si el paquete es http o no
     */
    private boolean isWebTraffic(TCP tcpPacket){
    	
    	boolean webTraffic = false;
    	int dstPort = tcpPacket.getDestinationPort();
    	int srcPort = tcpPacket.getSourcePort();
    	if(dstPort==80 || srcPort==80 || dstPort==443 || srcPort==443){
    		webTraffic=true;
    	}

    	return webTraffic;
    }

}
