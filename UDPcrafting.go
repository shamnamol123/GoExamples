package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
   	"github.com/google/gopacket/pcap"
)

var (
	snapshotLen  int32         = 1600
	promiscuous                = false
  )
  
func main(){
   device:="devname"
   handle, err := pcap.OpenLive(device, snapshotLen, true, blockForever)
		if err1 != nil {
		  glog.Infof("Error while listening:%v",err)
     }
      
    packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := <-packetSource.Packets(){
      udpH, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			ipv4, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

      ip := &layers.IPv4{
          SrcIP:    ip4.DstIP,
          DstIP:    ip4.SrcIP,
          Protocol: layers.IPProtocolUDP,
      }
     udp := &layers.UDP{
           SrcPort: udpH.DstPort,
           DstPort: udpH.SrcPort,
      }
      
    /* This is needed for computing the checksum when serializing */
    
   udp.SetNetworkLayerForChecksum(ip)

   buf := gopacket.NewSerializeBuffer()
   opts := gopacket.SerializeOptions{
      ComputeChecksums: true,
      FixLengths:       true,
    }
    
    udp.SerializeTo(buf, opts)
    
    if err := gopacket.SerializeLayers(buf, opts, udp); err != nil {
       fmt.Printf("%v", err)
    } else {
        /*Write to the device*/
        handle.WritePacketData(buf.Bytes())
    }
 }
}
