#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/olsr-module.h" 
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("OlsrStatic15NodesWithOverhead");

uint32_t controlPackets = 0;
uint64_t controlBytes = 0;

void ControlPacketTracer(Ptr<const Packet> packet) {
    controlPackets++;
    controlBytes += packet->GetSize();
}

int main(int argc, char *argv[])
{
    Time::SetResolution(Time::NS);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    NodeContainer nodes;
    nodes.Create(15);

    // Mobilidade fixa
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < 15; ++i) {
        positionAlloc->Add(Vector(i * 50.0, 0.0, 0.0));
    }
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // WiFi
    WifiHelper wifi;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode", StringValue("OfdmRate6Mbps"));

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(channel.Create());

    // captura PCAP
    wifiPhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);
    
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, nodes);

    // Internet + OLSR
    OlsrHelper olsr;
    InternetStackHelper stack;
    stack.SetRoutingHelper(olsr);
    stack.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    UdpEchoServerHelper echoServer(9);
    ApplicationContainer serverApps = echoServer.Install(nodes.Get(14));
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(20.0));

    UdpEchoClientHelper echoClient(interfaces.GetAddress(14), 9);
    echoClient.SetAttribute("MaxPackets", UintegerValue(100));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(0.2)));
    echoClient.SetAttribute("PacketSize", UintegerValue(64));

    ApplicationContainer clientApps = echoClient.Install(nodes.Get(0));
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(20.0));

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        Ptr<Node> node = nodes.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ptr<Ipv4RoutingProtocol> rp = ipv4->GetRoutingProtocol();
        Ptr<olsr::RoutingProtocol> olsrRouting = DynamicCast<olsr::RoutingProtocol>(rp);
        if (olsrRouting) {
            // OLSR usa principalmente mensagens HELLO, TC e MID
            olsrRouting->TraceConnectWithoutContext("TxHello", MakeCallback(&ControlPacketTracer));
            olsrRouting->TraceConnectWithoutContext("TxTc", MakeCallback(&ControlPacketTracer));
            olsrRouting->TraceConnectWithoutContext("TxMid", MakeCallback(&ControlPacketTracer));
        }
    }

    wifiPhy.EnablePcap("olsr-control", devices);

    Simulator::Stop(Seconds(21.0));
    Simulator::Run();

    monitor->CheckForLostPackets();
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
    uint32_t rxPackets = 0, txPackets = 0;
    double totalDelay = 0.0;
    uint32_t countedFlows = 0;

    for (auto const &flow : stats) {
        txPackets += flow.second.txPackets;
        rxPackets += flow.second.rxPackets;
        if (flow.second.rxPackets > 0) {
            totalDelay += flow.second.delaySum.GetSeconds() / flow.second.rxPackets;
            countedFlows++;
        }
    }

    double pdr = (txPackets > 0) ? ((double)rxPackets / txPackets) * 100.0 : 0.0;
    double avgDelay = (countedFlows > 0) ? totalDelay / countedFlows : -1;

    std::cout << "=== Estatísticas Agregadas ===" << std::endl;
    std::cout << "Pacotes transmitidos: " << txPackets << std::endl;
    std::cout << "Pacotes recebidos:    " << rxPackets << std::endl;
    std::cout << "Taxa de entrega (PDR): " << pdr << " %" << std::endl;
    if (avgDelay >= 0)
        std::cout << "Latência média:        " << avgDelay << " s" << std::endl;
    else
        std::cout << "Latência média:        N/A" << std::endl;

    Simulator::Destroy();
    return 0;
}
