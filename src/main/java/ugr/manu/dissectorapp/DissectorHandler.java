/**
Copyright (C) 2015 Manuel Sánchez López

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
*/

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

import org.opendaylight.controller.sal.action.Controller;
import org.apache.log4j.pattern.SequenceNumberPatternConverter;
//import org.opendaylight.controller.protocol_plugin.openflow.core.internal.Controller;
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
import org.opendaylight.controller.sal.packet.ICMP;
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
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev100924.DomainName;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.Address;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.flow.node.supported.match.types.MatchTypeBuilder;
//import org.opendaylight.yang.gen.v1.urn.opendaylight.openflow.augments.rev131002.NwTosAction;
//import org.opendaylight.yang.gen.v1.urn.opendaylight.openflow.augments.rev131002.NwTosActionBuilder;
import org.opendaylight.yangtools.yang.binding.DataContainer;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.projectfloodlight.openflow.protocol.match.MatchFields;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.InetAddresses;

import aQute.bnd.service.diff.Tree.Data;
import static java.nio.charset.StandardCharsets.*;

public class DissectorHandler implements IListenDataPacket {
    
    private static final Logger log = LoggerFactory.getLogger(DissectorHandler.class);
    private boolean youtubeTraffic=false;
    private boolean webTraffic=false;
    private boolean VoIPTraffic=false;
    private boolean icmpTraffic=false;
    private int contadorTraficoWeb = 0;
    private boolean añadeFlujo = false;
    private int actualDstAddr;
    private int actualSrcAddr;
    private boolean primeravez = true;
    private boolean servidorVideoYoutube = false;
    byte[] dirIP=new byte[4];
	InetAddress srcIPservidorVideoYoutube=null;
	List<InetAddress> srcIPservidorVideoYoutubeList = new ArrayList<InetAddress>();
	InetAddress addressDeURLaIP=null;

	String ipDNS=null;
	String urlVideoYoutube=null;
	InetAddress srcIPaddr=null;
	InetAddress dstIPaddr=null;
	List<InetAddress> direccionesServidoresDNSYoutube= new ArrayList<InetAddress>();


    
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
     *The function is a modification of an another function. The original
     *is property of SDNHUB.org and it's used under a GPLv3 License. All the credits for SDNHUB.org
     *The original code can be find in
     *https://github.com/sdnhub/SDNHub_Opendaylight_Tutorial/blob/master/adsal_L2_forwarding/src/main/java/org/opendaylight/tutorial/tutorial_L2_forwarding/internal/TutorialL2Forwarding.java
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
     *The function is a modification of an another function. The original
     *is property of SDNHUB.org and it's used under a GPLv3 License. All the credits for SDNHUB.org
     *The original code can be find in
     *https://github.com/sdnhub/SDNHub_Opendaylight_Tutorial/blob/master/adsal_L2_forwarding/src/main/java/org/opendaylight/tutorial/tutorial_L2_forwarding/internal/TutorialL2Forwarding.java
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
                srcIPaddr = intToInetAddress(ipv4Pkt.getSourceAddress());
                dstIPaddr = intToInetAddress(ipv4Pkt.getDestinationAddress());
                ///
                if(srcIPservidorVideoYoutubeList.contains(srcIPaddr) && srcIPaddr!=null){
                	servidorVideoYoutube=true;
                	log.info("Lista de direcciones de video Youtube: "+srcIPservidorVideoYoutubeList);
                } else{
                	log.info("srcIP: "+srcIPaddr+" ipDNS: "+srcIPservidorVideoYoutube);
                }
                
                
                // Esta es la clave para que añada el flujo!!!!!!!! no borrarrrrr
                match.setField(MatchType.DL_TYPE, (short) 0x0800);  // IPv4 ethertype
                match.setField(new MatchField(MatchType.NW_SRC, srcIPaddr));
                match.setField(new MatchField(MatchType.NW_DST, dstIPaddr));
                ////////////
               
                ////
                if (l4Datagram instanceof TCP){
                	TCP tcpDatagram = (TCP) l4Datagram;
                    int dstPort = tcpDatagram.getDestinationPort();
                    match.setField(MatchType.NW_PROTO, (byte) 6);       // TCP protocol id
                    //match.setField(MatchType.TP_DST, (short) dstPort);                             	
                	webTraffic = isWebTraffic(tcpDatagram);

                    /*if(l4Datagram instanceof TlsDetector){
                        match.setField(MatchType.DL_TYPE, (short) 0x38);  // TLS ethertype
                    }*/
                }
                if (l4Datagram instanceof UDP){
                	UDP udpDatagram = (UDP) l4Datagram;
                	byte[] udpRawPayload = udpDatagram.getRawPayload();
                	int srcPort=udpDatagram.getSourcePort(); // para comprobar si es DNS
                    byte[] arrayPacketData = inPkt.getPacketData();
                	//log.info("Payload del paquete UDP: "+Arrays.toString(arrayPacketData));
                	String udpRawPayDataISO = new String(udpRawPayload, ISO_8859_1);
                	udpRawPayDataISO=udpRawPayDataISO.replaceAll("", ".");
                	udpRawPayDataISO=udpRawPayDataISO.replaceAll("", ".");
                	//log.info("udpRawPayload en String "+udpRawPayDataISO);               	
                    youtubeTraffic = isYoutubeTraffic(arrayPacketData);
                	match.setField(MatchType.NW_PROTO, (byte) 17); //UDP protocol id

                    if(youtubeTraffic && srcPort==53){
                    	direccionesServidoresDNSYoutube.add(srcIPaddr);
                    	log.info("LIST YOUTUBE DNS: "+direccionesServidoresDNSYoutube);
                    	log.info("Payload del paquete UDP: "+Arrays.toString(udpRawPayload));
                    	log.info("En ISO sale: "+udpRawPayDataISO);
                    	srcIPservidorVideoYoutube=parseoDNS(udpRawPayload);
                    	if(!srcIPservidorVideoYoutubeList.contains(srcIPservidorVideoYoutube)){
                    		srcIPservidorVideoYoutubeList.add(srcIPservidorVideoYoutube);
                    	}
                    }
                    VoIPTraffic = isVoIPTraffic(udpDatagram);
                }
                if(l4Datagram instanceof ICMP){
                	log.info("Se está realizando un ping");
                	icmpTraffic=true;
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
                if(servidorVideoYoutube){
        			servidorVideoYoutube=false;
                	añadeFlujo=true;
                	log.info("Nuevo ToS para tráfico Youtube");                	
                	actions.add(new SetNwTos(8));
                    
                } else if(direccionesServidoresDNSYoutube.contains(srcIPaddr)){
                	añadeFlujo=false;
                	log.info("IP de servidor DNS Youtube; no añadir flujo");
                	//log.info("Holaaaaaaaaaaaaaaaaaaaaa youtube miraver");
                } else if(youtubeTraffic){
                	añadeFlujo=false;
                	youtubeTraffic=false;
                	//log.info("Holaaaaaaaaaaaaaaaaaaaaa youtube miraver");
                }else if(webTraffic){
                	añadeFlujo=true;
                	webTraffic=false;
                	//actions.add(new SetNwTos(2));
                }
                else if (VoIPTraffic){
                	añadeFlujo = true;
                	VoIPTraffic = false;
                	//actions.add(new SetNwTos(3));    
                } else if(icmpTraffic){
                	icmpTraffic=false;
                	//actions.add(new SetNwTos(4));
                	añadeFlujo=true;
                } else {
                	añadeFlujo = false;
                }                
                
                if(añadeFlujo){
                    actions.add(new Output(dst_connector));
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
	                log.info("Installed flow {} in node {}",f, incoming_node);
	                try {
	                    RawPacket destPkt = new RawPacket(inPkt);
	                    destPkt.setOutgoingNodeConnector(dst_connector);
	                    this.dataPacketService.transmitDataPacket(destPkt);
	                    //log.info("Datos de paquete transmitido dentro de floodpacket: "+this.dataPacketService.decodeDataPacket(destPkt).toString());
	                } catch (ConstructionException e2) {
	                }
                }
                else{
	                try {
	                    RawPacket destPkt = new RawPacket(inPkt);
	                    destPkt.setOutgoingNodeConnector(dst_connector);
	                    this.dataPacketService.transmitDataPacket(destPkt);
	                    //log.info("Datos de paquete transmitido dentro de floodpacket: "+this.dataPacketService.decodeDataPacket(destPkt).toString());
	                } catch (ConstructionException e2) {
	                }
                }

            }
            else 
                floodPacket(inPkt);
        }
        
        
        // We did not process the packet -> let someone else do the job.
        return PacketResult.IGNORED;
    }
    
    /**
     * Función que comprueba si el tráfico pertenece a un flujo de
     * streaming de video enviado por Youtube. Con esta función
     * detectamos el servidor DNS que envía la dirección IP del
     * servidor de video.
     * @param arrayPacketData: es el paquete de datos en el que
     * buscaremos el string "googlevideo"
     * @return Nos devuelve una booleana indicando si el paquete es
     * de tráfico Youtube o no.
     */
    private boolean isYoutubeTraffic(byte[] arrayPacketData){
    	
    	boolean youtubeTraffic = false;
    	String datosUDP = new String(arrayPacketData, UTF_8);
        //log.info("Los datos del paquete son en UTF-8: "+datosUDP);
        if(datosUDP.contains("googlevideo")){
        	// ...añadir el ToS más adelante en el flujo en caso de "true"
        	log.info("Es Youtube");
        	youtubeTraffic=true;
        }
    	return youtubeTraffic;
    }
    /**
     * Función encargada de parsear los paquetes DNS con el objeto
     * de encontrar la dirección IP del servidor encuadrada dentro
     * de las respuestas de este tipo de paquetes.
     * @param udpRawPayload: paquete UDP en el que se encuentra
     * incluido el paquete DNS
     * @return srcIPservidorVideoYoutube: dirección IP del servidor.
     */
    private InetAddress parseoDNS(byte[] udpRawPayload){
    	String udpRawPayDataISO = new String(udpRawPayload, ISO_8859_1);
    	byte[] numPeticiones= new byte[2];
    	byte[] numRespuestas = new byte[2];
    	byte[] Type;
    	byte[] Class;
    	boolean urlencontrada=false;
    	int longitudPeticiones=12;
    	int longitudRespuestas=0;
    	int longitudURL=0;
    	numPeticiones[0]=udpRawPayload[4];
    	numPeticiones[1]=udpRawPayload[5];
    	numRespuestas[0]=udpRawPayload[6];
    	numRespuestas[1]=udpRawPayload[7];
    	int numQueries=0;
    	int numAnswers=0;
    	numQueries=numPeticiones[1];
    	numAnswers=numRespuestas[1];
    	log.info("Numero de peticiones: "+numQueries+" numero respuestas: "+numAnswers);
    	if(numAnswers!=0){
    		for(int j=0;j<numQueries;j++){
	    		urlencontrada=false;
    			for(int i=longitudPeticiones;i<udpRawPayload.length-2;i++){ // La i cambia por si encontramos una petición y hay más para que se incremente hasta la siguiente
    	    		if(udpRawPayload[i+1]==0 && !urlencontrada){
    	    			log.info("Primer 0 encontrado");
    	    			if(udpRawPayload[i+2]==0){
    	    				log.info("Segundo 0 encontrado");
    	    				longitudPeticiones=i+8;
    	    				log.info("número de petición "+j);
    	    				j++;
    	    				urlVideoYoutube=udpRawPayDataISO.substring(13, i+1);
    	    				longitudURL=urlVideoYoutube.length();
    	    				urlencontrada=true;
    	    				log.info("La url es: "+urlVideoYoutube+" y la longitud es "+longitudURL+" y vamos por el byte: "+longitudPeticiones);
    	    				//urlencontrada=true;
    	    			}
    	    		}
    	    	}
    		}
			longitudRespuestas=longitudPeticiones;
    		for(int j=0; j<numAnswers;j++){
    			Type = new byte[numAnswers];
    			Type[j]=udpRawPayload[longitudRespuestas+1];
    			log.info("Type: "+Type[j]);
    			Class = new byte[numAnswers];
    			Class[j]=udpRawPayload[longitudRespuestas+3];
    			log.info("Class: "+Class[j]);
    			if(Type[j]==5){
    				longitudRespuestas=longitudRespuestas+14+(longitudURL-17);// para pasar a la siguiente respuesta, El primary Name tiene 17 bytes menos parece
    			}
    			if(Type[j]==1){
    				byte[] ipAddr=new byte[4];
    				ipAddr[0]=udpRawPayload[longitudRespuestas+10];
    				ipAddr[1]=udpRawPayload[longitudRespuestas+11];
    				ipAddr[2]=udpRawPayload[longitudRespuestas+12];
    				ipAddr[3]=udpRawPayload[longitudRespuestas+13];
    				try {
						srcIPservidorVideoYoutube = srcIPservidorVideoYoutube.getByAddress(ipAddr);
						log.info("La IP que hemos conseguido hasta ahora es: "+srcIPservidorVideoYoutube);
					} catch (UnknownHostException e) {
						e.printStackTrace();
					}
    			}
			}
    	}
    	log.info("IP del servidor de Video Youtube encontrada: "+srcIPservidorVideoYoutube);
    	return srcIPservidorVideoYoutube;
    }
    
    /**
     * Función que comprueba si es tráfico VoIP
     * @param udpPacket paquete udp que vamos a analizar
     * @return devolvemos una booleana que informará si el paquete es VoIP o no
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
