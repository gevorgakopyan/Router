/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{

  bool
  SimpleRouter::validate_ip(const uint8_t *buf, int minlength)
  {
    ip_hdr *iphdr = (ip_hdr *)(buf);
    uint16_t recieved_cksum, expected_cksum;

    minlength += sizeof(ip_hdr);

    if (iphdr->ip_len < minlength)
    {
      std::cerr << "not min ip packet size" << std::endl;
      return false;
    }

    else if (iphdr->ip_len > IP_MAXPACKET)
    {
      std::cerr << "packet length is too long" << std::endl;
      return false;
    }

    if (iphdr->ip_ttl == 1)
    {
      std::cerr << "dropping: TTL" << std::endl;
      return false;
    }

    if (iphdr->ip_v != 4)
    {
      std::cerr << "not IPv4, ignoring" << std::endl;
      return false;
    }

    uint8_t ip_proto = ip_protocol(buf + sizeof(ethernet_hdr));
    ACLTableEntry acl_entry;
    bool found = true;
    if (ip_proto == ip_protocol_icmp)
    {
      try
      {
        acl_entry = m_aclTable.lookup(ntohl(iphdr->ip_src), ntohl(iphdr->ip_dst), iphdr->ip_p, ntohs(0), ntohs(0));
      }
      catch (const std::exception &e)
      {
        found = false;
      }

      if (found && acl_entry.priority > 0)
      {
        m_aclLogFile << acl_entry;
        if (acl_entry.action == "deny")
          return false;
      }
    }
    else
    {
      uint16_t hostPort = *(uint16_t *)(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      uint16_t destPort = *(uint16_t *)(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(uint16_t));
      try
      {
        acl_entry = m_aclTable.lookup(ntohl(iphdr->ip_src), ntohl(iphdr->ip_dst), iphdr->ip_p, ntohs(hostPort), ntohs(destPort));
      }
      catch (const std::exception &e)
      {
        found = false;
      }

      if (found && acl_entry.priority > 0)
      {
        m_aclLogFile << acl_entry;
        if (acl_entry.action == "deny")
          return false;
      }
    }

    recieved_cksum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    expected_cksum = cksum(iphdr, iphdr->ip_hl << 2);

    if (recieved_cksum != expected_cksum)
    {
      std::cerr << "checksum does not match, expected: " << expected_cksum << std::endl;
      return false;
    }

    if (findIfaceByIp(iphdr->ip_dst) != nullptr)
    {
      std::cerr << "packet is destined to one router's interfaces, ignoring" << std::endl;
      return false;
    }

    return true;
  }

  void
  SimpleRouter::processPacket(const Buffer &packet, const std::string &inIface)
  {
    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    const uint8_t *buf = packet.data();
    const ethernet_hdr *ehdr = (const ethernet_hdr *)buf;
    size_t minlength = sizeof(ethernet_hdr);
    uint16_t ethtype = ethertype(buf);
    Buffer copy_packet = Buffer(packet);
    uint8_t *copy_buff = copy_packet.data();

    if (ethtype == ethertype_ip)
    {
      if (!validate_ip(buf + sizeof(ethernet_hdr), minlength))
        return;

      ip_hdr *iphdr = (ip_hdr *)(buf + sizeof(ethernet_hdr));
      ip_hdr *copy_iphdr = reinterpret_cast<ip_hdr *>(copy_buff + sizeof(ethernet_hdr));
      ethernet_hdr *copy_ehdr = reinterpret_cast<ethernet_hdr *>(copy_buff);
      RoutingTableEntry next_hop = m_routingTable.lookup(iphdr->ip_dst);
      auto dest_iface = findIfaceByName(next_hop.ifName);

      copy_iphdr->ip_ttl--;
      copy_iphdr->ip_sum = 0;
      copy_iphdr->ip_sum = cksum(copy_iphdr, copy_iphdr->ip_hl << 2);

      auto arp_entry = m_arp.lookup(next_hop.gw);
      if (arp_entry == nullptr)
      {
        std::cerr << "not in cache, queing and sending ARP_REQ\n";
        auto arp_req = m_arp.queueArpRequest(iphdr->ip_dst, copy_packet, dest_iface->name);
        return;
      }

      memcpy(copy_ehdr->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
      memcpy(copy_ehdr->ether_shost, dest_iface->addr.data(), ETHER_ADDR_LEN);

      sendPacket(copy_packet, dest_iface->name);
    }
    else if (ethtype == ethertype_arp)
    {
      const arp_hdr *ahdr = reinterpret_cast<const arp_hdr *>(buf + sizeof(ethernet_hdr));
      bool isBroadcast = true;

      for (auto b : ehdr->ether_dhost)
      {
        if ((b & 1) != 1)
        {
          isBroadcast = false;
          break;
        }
      }

      if (ntohs(ahdr->arp_op) == arp_op_request)
      {
        std::cerr << "ARP REQUEST" << std::endl;

        if (!isBroadcast && findIfaceByIp(ahdr->arp_tip) == nullptr)
        {
          if (isBroadcast)
          {
            std::cerr << "packet not destined for router" << std::endl;
            return;
          }
          else
          {
            std::cerr << "packet not broadcast: " << std::endl;
            return;
          }
        }

        Buffer copy_packet = Buffer(packet);
        uint8_t *copy_buff = copy_packet.data();

        ethernet_hdr *copy_ehdr = reinterpret_cast<ethernet_hdr *>(copy_buff);
        arp_hdr *copy_ahdr = reinterpret_cast<arp_hdr *>(copy_buff + sizeof(ethernet_hdr));

        memcpy(copy_ehdr->ether_dhost, ahdr->arp_sha, ETHER_ADDR_LEN);
        memcpy(copy_ehdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(copy_ahdr->arp_tha, ahdr->arp_sha, ETHER_ADDR_LEN);
        memcpy(copy_ahdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);

        copy_ahdr->arp_sip = iface->ip;
        copy_ahdr->arp_tip = ahdr->arp_sip;
        copy_ahdr->arp_op = ntohs(arp_op_reply);

        sendPacket(copy_packet, iface->name);
        // std::cerr << "SENT ARP REPLY\n";

        // print_hdr_eth(copy_buff);
        // print_hdr_arp(copy_buff + sizeof(ethernet_hdr));
      }
      else if (ntohs(ahdr->arp_op) == arp_op_reply)
      {
        auto req = m_arp.insertArpEntry(
            Buffer(ahdr->arp_sha, ahdr->arp_sha + ETHER_ADDR_LEN), ahdr->arp_sip);

        if (req != nullptr)
        {
          for (auto buffer_packet : req->packets)
          {
            Buffer newPacket = Buffer(buffer_packet.packet);
            ethernet_hdr *e_hdr = reinterpret_cast<ethernet_hdr *>(newPacket.data());
            memcpy(e_hdr->ether_dhost, ahdr->arp_sha, ETHER_ADDR_LEN);
            memcpy(e_hdr->ether_shost, findIfaceByName(req->iface)->addr.data(), ETHER_ADDR_LEN);
            sendPacket(newPacket, req->iface);
          }
          m_arp.removeArpRequest(req);
        }
        else
        {
          std::cerr << "error inserting into arp cache" << std::endl;
          return;
        }
      }
      else
        std::cerr << "invalid opcode" << std::endl;
    }
    else
    {
      std::cerr << "unknown type, ignoring" << std::endl;
      return;
    }
  }

  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
    m_aclLogFile.open("router-acl.log");
  }

  void
  SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool
  SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  bool
  SimpleRouter::loadACLTable(const std::string &aclConfig)
  {
    return m_aclTable.load(aclConfig);
  }

  void
  SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void
  SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface)
                              { return iface.ip == ip; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface)
                              { return iface.addr == mac; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface)
                              { return iface.name == name; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void
  SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

} // namespace simple_router {
