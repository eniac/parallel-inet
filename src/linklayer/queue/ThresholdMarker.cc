//
// Copyright (C) 2012 Opensim Ltd.
// Author: Tamas Borbely
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "ThresholdMarker.h"
#include "EtherFrame.h"
#include "IPv4Datagram.h"
#include "opp_utils.h"

Define_Module(ThresholdMarker);

ThresholdMarker::~ThresholdMarker()
{
}

void ThresholdMarker::initialize()
{
    AlgorithmicMarkerBase::initialize();

    K = par("K");
    useEcn = par("useEcn");
    packetCapacity = par("packetCapacity");
    if (K > packetCapacity) {
        throw cRuntimeError("Warning: packetCapacity < K. Setting capacity to K");
        packetCapacity = K;
    }

    // std::cout << "ThresholdMarker initialized with wq=" << wq << " minth=" << minth << " maxth=" << maxth << " maxp=" << maxp << " pkrate=" << pkrate << " useEcn=" << useEcn << " packetCapacity=" << packetCapacity << std::endl;
}

IPEcnCode ThresholdMarker::getEcn(const cPacket *packet)
{
    IPEcnCode ecn = IP_ECN_NOT_ECT;
    if (dynamic_cast<const EtherFrame *>(packet) != NULL) {
        // std::cout << "EtherFrame!!" << std::endl;
        const IPv4Datagram *ipv4pkt = dynamic_cast<IPv4Datagram *>(packet->getEncapsulatedPacket());
        if (ipv4pkt != NULL) {
            // std::cout << "ether packet from IPv4, ECN = " << ipv4pkt->getExplicitCongestionNotification() << std::endl;
            ecn = static_cast<IPEcnCode>(ipv4pkt->getExplicitCongestionNotification());
        }
    }
    return ecn;
}

void ThresholdMarker::setEcn(cPacket *packet, IPEcnCode ecn)
{
    cPacket *higherlayerpkt = packet->decapsulate();
    IPv4Datagram *ipv4pkt = check_and_cast<IPv4Datagram *>(higherlayerpkt); // guaranteed to be IPv4 packet
    ipv4pkt->setExplicitCongestionNotification(ecn);
    packet->encapsulate(ipv4pkt);

    // Test
    // std::cout << "Setting ECN = " << ecn << ", getting ECN = " << getEcn(packet) << std::endl;
}

bool ThresholdMarker::shouldDrop(cPacket *packet)
{
    if (getLength() >= packetCapacity) {
        return true;
    }
    return false;
}

void ThresholdMarker::markPacket(cPacket *packet)
{
    if (getLength() >= K) {
        if (useEcn) {
            IPEcnCode ecn = getEcn(packet);
            if (ecn != IP_ECN_NOT_ECT) {
                setEcn(packet, IP_ECN_CE);
            }
        }
    }
}
