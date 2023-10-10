/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "routing-table.hpp"
#include "core/utils.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

namespace simple_router
{
  /*
   * Lookup Code -------------------- Lookup (P)
   * lookup a packet received packet P to see where to forward itt = routingTable.stt
   * stt at stt of routing "table" in list form match = -1
   * sentinel for no match whilet!= NULL do
   *  if ((P.dstIP ANDt.mask) == t.destination ANDt.mask)
   *      // match prefix
   *  ift.match > match  then // longer match
   *    match =t.match  // remember best match length so far
   *    gateway =t.gateway // remember next hop
   *    interface =t.interface //remember interface to forward
   *
   * t =t.next (go to next element in list)
   *
   * Then you forward the packet by doing an ARP to the gateway on the interface corresponding to the longest match.
   * Your assignment says:
   *  "Check the ARP cache for the next-hop MAC address corresponding to the next-hop (agteway) IP.
   *  If it’s there, send it.
   *  Otherwise, send an ARP request for the next-hop IP (if one hasn’t been sent within the last second),
   *  and add the packet to the queue of packets waiting on this ARP request."
   */

  RoutingTableEntry
  RoutingTable::lookup(uint32_t ip) const
  {
    RoutingTableEntry next_hop_destination;
    bool match_exists = false;
    uint32_t curr_mask = 0;
    for (RoutingTableEntry entry : m_entries)
    {
      if ((ip & entry.mask) != (entry.dest & entry.mask))
        continue;

      if (!match_exists || entry.mask > curr_mask)
      {
        next_hop_destination = entry;
        match_exists = true;
        curr_mask = entry.mask;
      }
    }

    if (!match_exists)
      throw std::runtime_error("Routing entry not found");

    return next_hop_destination;
  }

  bool
  RoutingTable::load(const std::string &file)
  {
    fprintf(stderr,
            "Loading Routing Table from %s\n",
            file.c_str());

    FILE *fp;
    char line[BUFSIZ];
    char dest[32];
    char gw[32];
    char mask[32];
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    if (access(file.c_str(), R_OK) != 0)
    {
      perror("access");
      return false;
    }

    fp = fopen(file.c_str(), "r");

    while (fgets(line, BUFSIZ, fp) != 0)
    {
      sscanf(line, "%s %s %s %s", dest, gw, mask, iface);
      if (inet_aton(dest, &dest_addr) == 0)
      {
        fprintf(stderr,
                "Error loading routing table, cannot convt %s to valid IP\n",
                dest);
        return false;
      }
      if (inet_aton(gw, &gw_addr) == 0)
      {
        fprintf(stderr,
                "Error loading routing table, cannot convt %s to valid IP\n",
                gw);
        return false;
      }
      if (inet_aton(mask, &mask_addr) == 0)
      {
        fprintf(stderr,
                "Error loading routing table, cannot convt %s to valid IP\n",
                mask);
        return false;
      }

      addRoute({dest_addr.s_addr, gw_addr.s_addr, mask_addr.s_addr, iface});
    }
    return true;
  }

  void
  RoutingTable::addRoute(RoutingTableEntry entry)
  {
    m_entries.push_back(std::move(entry));
  }

  std::ostream &
  operator<<(std::ostream &os, const RoutingTableEntry &entry)
  {
    os << ipToString(entry.dest) << "\t\t"
       << ipToString(entry.gw) << "\t"
       << ipToString(entry.mask) << "\t"
       << entry.ifName;
    return os;
  }

  std::ostream &
  operator<<(std::ostream &os, const RoutingTable &table)
  {
    os << "Destination\tGateway\t\tMask\tIface\n";
    for (const auto &entry : table.m_entries)
    {
      os << entry << "\n";
    }
    return os;
  }

} // namespace simple_router
