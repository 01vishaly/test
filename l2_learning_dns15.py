# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch.

It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time
import pox.lib.packet as pkt
import binascii
import socket
import struct
import numpy as np
from array import *

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class LearningSwitch (object):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent


    #my changes for data collection
    self.c = 0
    self.start_time = {}
    self.count = {}
    self.tot_bytes = {}
    self.tot_ipd = {}
    #self.file_open = 0
    self.current_time = {}
    self.previous_time = {}
    self.tcp_hlen = {}
    self.tcp_dlen = {}
    self.plen = {}
    self.ipd = {}
    self.start_time = {}
    #self.tcpfin = {}
    self.tcppsh = {}
    self.tcprst = {}
    #self.tcpsyn = {}
    #self.tcpecn = {}
    self.tcpcwr = {}
    self.tcpurg = {}
    #self.tcpack = {}
    self.tcpeol = {}
    self.tcpmss = {}
    self.tcpwsopt = {}
    self.tcptsopt = {}
    self.tcpmptcp = {}
    self.tcpsack = {}
    self.tcpsckprm = {}
    
    # Our table
    self.macToPort = {}
    self.IPtoURL = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    prev_time = 0
    curr_time = 0
    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        
        #my changes :
        #if True:
          #self.file_open += 1 
          #training_data_file = open("250620.csv", "a")
          #training_data_file.write("cnt,smac,dmac,pkt1, pkt2, pkt3, pkt4, pkt5, sip,dip,sport, dport, ipd1, ipd2, ipd3, ipd4, ipd5, tot_bytes, tot_ipd, hdrlen1, hdrlen2, hdrlen3, hdrlen4, hdrlen5, pyld1,  pyld2,  pyld3,  pyld4, pyld5, rate0, rate1,rate2,rate3,rate4, totalrate,  website, srcip\r\n")       
        if packet.find('tcp') and not packet.find('dns'):
          #log.debug("retrieving features")
          #self.count += 1
          smac = packet.src
          smac = int(str(smac).replace(":", ""), 16)
          dmac = packet.dst
          dmac = int(str(dmac).replace(":", ""), 16)
          plen = packet.payload_len
          ippack = packet.find('ipv4')
          packedIP = socket.inet_aton(str(ippack.srcip))
          dec_sip = struct.unpack("!L", packedIP)[0]
          sip = ippack.srcip
          packedIP = socket.inet_aton(str(ippack.dstip))
          dec_dip = struct.unpack("!L", packedIP)[0]
          dip = ippack.dstip
          tcppack = packet.find('tcp')
          sport = tcppack.srcport
          dport = tcppack.dstport
          #between_pkts = 0
         
          
          #t = time.localtime()
          #current_time = time.strftime("%H:%M:%S", t)
          
           #log.debug("opening file")
          #open training data file
          
                          
          #format
          #count smac  dmac  sip  dip  sport	dport  between_pkts  plen  tot_bytes  tot_ipd url hdr_len  pyld_len		
                    
          #log.debug("writing to files")
          #writing
          EOL = False
          MSS = False
          WSOPT = False
          SACKPERM = False
          SACK = False
          TSOPT = False
          MPTCP = False
          
          if sip in self.IPtoURL:
            if self.count[sip] == 0:
              self.tot_bytes[sip] = self.tot_bytes[sip]+plen
              current_milli_time = int(round(time.time() * 1000))
              self.current_time[sip] = current_milli_time      
              between_pkts = self.current_time[sip]-self.previous_time[sip]
              self.tot_ipd[sip] += between_pkts
              self.count[sip] = self.count[sip]+1
              self.c = self.count[sip]
              self.ipd[sip] = array('i', [between_pkts])
              self.tcp_hlen[sip] = array('i', [tcppack.hdr_len]) 
              self.tcp_dlen[sip] = array('i', [tcppack.payload_len])
              self.plen[sip] =  array('i', [plen])
              #self.tcpfin[sip] = array('i', [tcppack.FIN])
              self.tcppsh[sip] = array('i', [tcppack.PSH])
              self.tcprst[sip] = array('i', [tcppack.RST])
              #self.tcpsyn[sip] = array('i', [tcppack.SYN])
              #self.tcpecn[sip] = array('i', [tcppack.ECN])
              self.tcpcwr[sip] = array('i', [tcppack.CWR])
              self.tcpurg[sip] = array('i', [tcppack.URG])
              #self.tcpack[sip] = array('i', [tcppack.ACK])
              
              
              ops = ''
              if tcppack.options:
                ops = ' opt : '+' , '.join(str(o) for o in tcppack.options)
          
            
                if 'EOL' in ops:
                  EOL = True
                if 'MSS' in ops:
                  MSS = True
                if 'WSOPT' in ops:
                  WSOPT = True
                if 'SACKPERM' in ops:
                  SACKPERM = True
                if 'SACK' in ops:
                  SACK = True
                if 'TSOPT' in ops:
                  TSOPT = True
                if 'MPTCP' in ops:
                  MPTCP = True  
              self.tcpeol[sip] = array('i', [EOL])
              self.tcpmss[sip] = array('i', [MSS])
              self.tcpwsopt[sip] = array('i', [WSOPT])
              self.tcptsopt[sip] = array('i', [TSOPT])
              self.tcpmptcp[sip] = array('i', [MPTCP])
              self.tcpsack[sip] = array('i', [SACK])
              self.tcpsckprm[sip] = array('i', [SACKPERM])
               
            elif self.count[sip] > 0 and self.count[sip] < 15:
              self.tot_bytes[sip] = self.tot_bytes[sip]+plen
              current_milli_time = int(round(time.time() * 1000))
              self.current_time[sip] = current_milli_time      
              between_pkts = self.current_time[sip]-self.previous_time[sip]
              self.tot_ipd[sip] += between_pkts
              self.count[sip] = self.count[sip]+1
              self.c = self.count[sip]
              self.ipd[sip].append(between_pkts)
              self.tcp_hlen[sip].append(tcppack.hdr_len)
              self.tcp_dlen[sip].append(tcppack.payload_len)
              self.plen[sip].append(plen)
              #self.tcpfin[sip].append(tcppack.FIN)
              self.tcppsh[sip].append(tcppack.PSH)
              self.tcprst[sip].append(tcppack.RST)
              #self.tcpsyn[sip].append(tcppack.SYN)
              #self.tcpecn[sip].append(tcppack.ECN)
              self.tcpcwr[sip].append(tcppack.CWR)
              self.tcpurg[sip].append(tcppack.URG)
              #self.tcpack[sip].append(tcppack.ACK)
              
              
              ops = ''
              if tcppack.options:
                ops = ' opt : '+' , '.join(str(o) for o in tcppack.options)
          
            
                if 'EOL' in ops:
                  EOL = True
                if 'MSS' in ops:
                  MSS = True
                if 'WSOPT' in ops:
                  WSOPT = True
                if 'SACKPERM' in ops:
                  SACKPERM = True
                if 'SACK' in ops:
                  SACK = True
                if 'TSOPT' in ops:
                  TSOPT = True
                if 'MPTCP' in ops:
                  MPTCP = True  
              self.tcpeol[sip].append(EOL)
              self.tcpmss[sip].append(MSS)
              self.tcpwsopt[sip].append(WSOPT)
              self.tcptsopt[sip].append(TSOPT)
              self.tcpmptcp[sip].append(MPTCP)
              self.tcpsack[sip].append(SACK)
              self.tcpsckprm[sip].append(SACKPERM)
            elif self.count[sip] == 15:  
              #log.debug("writing to filesfiles")
              current_milli_time = int(round(time.time() * 1000))
              rate = array('d', [self.plen[sip][0]/self.ipd[sip][0]])
              rate.append(self.plen[sip][1]/self.ipd[sip][1])
              rate.append(self.plen[sip][2]/self.ipd[sip][2])
              rate.append(self.plen[sip][3]/self.ipd[sip][3])
              rate.append(self.plen[sip][4]/self.ipd[sip][4])
              rate.append(self.plen[sip][5]/self.ipd[sip][5])
              rate.append(self.plen[sip][6]/self.ipd[sip][6])
              rate.append(self.plen[sip][7]/self.ipd[sip][7])
              rate.append(self.plen[sip][8]/self.ipd[sip][8])
              rate.append(self.plen[sip][9]/self.ipd[sip][9])
              rate.append(self.plen[sip][10]/self.ipd[sip][10])
              rate.append(self.plen[sip][11]/self.ipd[sip][11])
              rate.append(self.plen[sip][12]/self.ipd[sip][12])
              rate.append(self.plen[sip][13]/self.ipd[sip][13])
              rate.append(self.plen[sip][14]/self.ipd[sip][14])

              
              current_milli_time = int(round(time.time() * 1000))
              tot_rate = self.tot_bytes[sip]/((current_milli_time - self.start_time[sip])/1000)
              training_data_file = open("280620.csv", "a")
              training_data_file.write("%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %f,%f,%f,\
              %f,%f,%f,\
              %d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %f,%f,%f,\
              %f,%f,%f,\
              %d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %f,%f,%f,\
              %f,%f,%f,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %f,%f,%f,\
              %f,%f,%f,\
              %f,%f,%f,%f,%f,\
              %f,%f,%f,%f,%f,\
              %f,%f,%f,%f,%f,%f,\
              %f,%f,%f,\
              %f,%f,%f,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %d,%d,%d,%d,%d,\
              %s,%s\r\n\n"\
               % (self.count[sip], smac, dmac,\
               self.plen[sip][0], self.plen[sip][1], self.plen[sip][2], self.plen[sip][3], self.plen[sip][4],\
               self.plen[sip][5], self.plen[sip][6], self.plen[sip][7], self.plen[sip][8], self.plen[sip][9],\
               self.plen[sip][10], self.plen[sip][11], self.plen[sip][12], self.plen[sip][13], self.plen[sip][14],\
               np.std(self.plen[sip][0:5]), np.std(self.plen[sip][0:10]), np.std(self.plen[sip]),\
               sum(self.plen[sip][0:5])/5.0,sum(self.plen[sip][0:10])/10.0,sum(self.plen[sip])/15.0,\
               dec_sip, dec_dip, sport, dport,\
               self.ipd[sip][0], self.ipd[sip][1],self.ipd[sip][2],self.ipd[sip][3], self.ipd[sip][4],\
               self.ipd[sip][5], self.ipd[sip][6],self.ipd[sip][7],self.ipd[sip][8], self.ipd[sip][9],\
               self.ipd[sip][10], self.ipd[sip][11],self.ipd[sip][12],self.ipd[sip][13], self.ipd[sip][14],\
               np.std(self.ipd[sip][0:5]), np.std(self.ipd[sip][0:10]), np.std(self.ipd[sip]),\
               sum(self.ipd[sip][0:5])/5.0,sum(self.ipd[sip][0:10])/10.0,sum(self.ipd[sip])/15.0,\
               self.tot_bytes[sip], self.tot_ipd[sip],\
               self.tcp_hlen[sip][0], self.tcp_hlen[sip][1], self.tcp_hlen[sip][2], self.tcp_hlen[sip][3], self.tcp_hlen[sip][4],\
               self.tcp_hlen[sip][5], self.tcp_hlen[sip][6], self.tcp_hlen[sip][7], self.tcp_hlen[sip][8], self.tcp_hlen[sip][9],\
               self.tcp_hlen[sip][10], self.tcp_hlen[sip][11], self.tcp_hlen[sip][12], self.tcp_hlen[sip][13], self.tcp_hlen[sip][14],\
               np.std(self.tcp_hlen[sip][0:5]), np.std(self.tcp_hlen[sip][0:10]), np.std(self.tcp_hlen[sip]),\
               sum(self.tcp_hlen[sip][0:5])/5.0,sum(self.tcp_hlen[sip][0:10])/10.0,sum(self.tcp_hlen[sip])/15.0,\
               self.tcp_dlen[sip][0], self.tcp_dlen[sip][1], self.tcp_dlen[sip][2], self.tcp_dlen[sip][3], self.tcp_dlen[sip][4],\
               self.tcp_dlen[sip][5], self.tcp_dlen[sip][6], self.tcp_dlen[sip][7], self.tcp_dlen[sip][8], self.tcp_dlen[sip][9],\
               self.tcp_dlen[sip][10], self.tcp_dlen[sip][11], self.tcp_dlen[sip][12], self.tcp_dlen[sip][13], self.tcp_dlen[sip][14],\
               np.std(self.tcp_dlen[sip][0:5]), np.std(self.tcp_dlen[sip][0:10]), np.std(self.tcp_dlen[sip]),\
               sum(self.tcp_dlen[sip][0:5])/5.0,sum(self.tcp_dlen[sip][0:10])/10.0,sum(self.tcp_dlen[sip])/15.0,\
               rate[0], rate[1], rate[2], rate[3], rate[4],\
               rate[5], rate[6], rate[7], rate[8], rate[9],\
               rate[10], rate[11], rate[12], rate[13], rate[14],tot_rate,\
               np.std(rate[0:5]), np.std(rate[0:10]), np.std(rate),\
               sum(rate[0:5])/5.0,sum(rate[0:10])/10.0,sum(rate)/15.0,\
               #self.tcpfin[sip][0], self.tcpfin[sip][1],self.tcpfin[sip][2],self.tcpfin[sip][3],self.tcpfin[sip][4],\
               self.tcppsh[sip][0], self.tcppsh[sip][1], self.tcppsh[sip][2], self.tcppsh[sip][3], self.tcppsh[sip][4], \
               self.tcppsh[sip][5], self.tcppsh[sip][6], self.tcppsh[sip][7], self.tcppsh[sip][8], self.tcppsh[sip][9], \
               self.tcppsh[sip][10], self.tcppsh[sip][11], self.tcppsh[sip][12], self.tcppsh[sip][13], self.tcppsh[sip][14], \
               #np.std(self.tcppsh[sip][0:5]), np.std(self.tcppsh[sip][0:10]), np.std(self.tcppsh[sip]),\
               #sum(self.tcppsh[sip][0:5])/5.0,sum(self.tcppsh[sip][0:10])/10.0,sum(self.tcppsh[sip])/15.0,\
               self.tcprst[sip][0], self.tcprst[sip][1], self.tcprst[sip][2], self.tcprst[sip][3], self.tcprst[sip][4], \
               self.tcprst[sip][5], self.tcprst[sip][6], self.tcprst[sip][7], self.tcprst[sip][8], self.tcprst[sip][9], \
               self.tcprst[sip][10], self.tcprst[sip][11], self.tcprst[sip][12], self.tcprst[sip][13], self.tcprst[sip][14], \
               #np.std(self.tcprst[sip][0:5]), np.std(self.tcprst[sip][0:10]), np.std(self.tcprst[sip]),\
               #sum(self.tcprst[sip][0:5])/5.0,sum(self.tcprst[sip][0:10])/10.0,sum(self.tcprst[sip])/15.0,\
               #self.tcpsyn[sip][0], self.tcpsyn[sip][1], self.tcpsyn[sip][2], self.tcpsyn[sip][3], self.tcpsyn[sip][4], \
               #self.tcpecn[sip][0], self.tcpecn[sip][1], self.tcpecn[sip][2], self.tcpecn[sip][3], self.tcpecn[sip][4], \
               #self.tcpecn[sip][5], self.tcpecn[sip][6], self.tcpecn[sip][7], self.tcpecn[sip][8], self.tcpecn[sip][9], \
               #self.tcpecn[sip][10], self.tcpecn[sip][11], self.tcpecn[sip][12], self.tcpecn[sip][13], self.tcpecn[sip][14], \
               #np.std(self.tcpecn[sip][0:5]), np.std(self.tcpecn[sip][0:10]), np.std(self.tcpecn[sip]),\
               #sum(self.tcpecn[sip][0:5])/5.0,sum(self.tcpecn[sip][0:10])/10.0,sum(self.tcpecn[sip])/15.0,\
               self.tcpcwr[sip][0], self.tcpcwr[sip][1], self.tcpcwr[sip][2], self.tcpcwr[sip][3], self.tcpcwr[sip][4], \
               self.tcpcwr[sip][5], self.tcpcwr[sip][6], self.tcpcwr[sip][7], self.tcpcwr[sip][8], self.tcpcwr[sip][9], \
               self.tcpcwr[sip][10], self.tcpcwr[sip][11], self.tcpcwr[sip][12], self.tcpcwr[sip][13], self.tcpcwr[sip][14], \
               #np.std(self.tcpcwr[sip][0:5]), np.std(self.tcpcwr[sip][0:10]), np.std(self.tcpcwr[sip]),\
               #sum(self.tcpcwr[sip][0:5])/5.0,sum(self.tcpcwr[sip][0:10])/10.0,sum(self.tcpcwr[sip])/15.0,\
               self.tcpurg[sip][0], self.tcpurg[sip][1], self.tcpurg[sip][2], self.tcpurg[sip][3], self.tcpurg[sip][4], \
               self.tcpurg[sip][5], self.tcpurg[sip][6], self.tcpurg[sip][7], self.tcpurg[sip][8], self.tcpurg[sip][9], \
               self.tcpurg[sip][10], self.tcpurg[sip][11], self.tcpurg[sip][12], self.tcpurg[sip][13], self.tcpurg[sip][14], \
               #np.std(self.tcpurg[sip][0:5]), np.std(self.tcpurg[sip][0:10]), np.std(self.tcpurg[sip]),\
               #sum(self.tcpurg[sip][0:5])/5.0,sum(self.tcpurg[sip][0:10])/10.0,sum(self.tcpurg[sip])/15.0,\
               #self.tcpack[sip][0], self.tcpack[sip][1], self.tcpack[sip][2], self.tcpack[sip][3], self.tcpack[sip][4], \
               self.tcpeol[sip][0], self.tcpeol[sip][1], self.tcpeol[sip][2], self.tcpeol[sip][3], self.tcpeol[sip][4], \
               self.tcpeol[sip][5], self.tcpeol[sip][6], self.tcpeol[sip][7], self.tcpeol[sip][8], self.tcpeol[sip][9], \
               self.tcpeol[sip][10], self.tcpeol[sip][11], self.tcpeol[sip][12], self.tcpeol[sip][13], self.tcpeol[sip][14], \
               #np.std(self.tcpeol[sip][0:5]), np.std(self.tcpeol[sip][0:10]), np.std(self.tcpeol[sip]),\
               #sum(self.tcpeol[sip][0:5])/5.0,sum(self.tcpeol[sip][0:10])/10.0,sum(self.tcpeol[sip])/15.0,\
               self.tcpmss[sip][0], self.tcpmss[sip][1], self.tcpmss[sip][2], self.tcpmss[sip][3], self.tcpmss[sip][4], \
               self.tcpmss[sip][5], self.tcpmss[sip][6], self.tcpmss[sip][7], self.tcpmss[sip][8], self.tcpmss[sip][9], \
               self.tcpmss[sip][10], self.tcpmss[sip][11], self.tcpmss[sip][12], self.tcpmss[sip][13], self.tcpmss[sip][14], \
               #np.std(self.tcpmss[sip][0:5]), np.std(self.tcpmss[sip][0:10]), np.std(self.tcpmss[sip]),\
               #sum(self.tcpmss[sip][0:5])/5.0,sum(self.tcpmss[sip][0:10])/10.0,sum(self.tcpmss[sip])/15.0,\
               self.tcpwsopt[sip][0], self.tcpwsopt[sip][1], self.tcpwsopt[sip][2], self.tcpwsopt[sip][3], self.tcpwsopt[sip][4], \
               self.tcpwsopt[sip][5], self.tcpwsopt[sip][6], self.tcpwsopt[sip][7], self.tcpwsopt[sip][8], self.tcpwsopt[sip][9], \
               self.tcpwsopt[sip][10], self.tcpwsopt[sip][11], self.tcpwsopt[sip][12], self.tcpwsopt[sip][13], self.tcpwsopt[sip][14], \
               #np.std(self.tcpwsopt[sip][0:5]), np.std(self.tcpwsopt[sip][0:10]), np.std(self.tcpwsopt[sip]),\
               #sum(self.tcpwsopt[sip][0:5])/5.0,sum(self.tcpwsopt[sip][0:10])/10.0,sum(self.tcpwsopt[sip])/15.0,\
               self.tcptsopt[sip][0], self.tcptsopt[sip][1], self.tcptsopt[sip][2], self.tcptsopt[sip][3], self.tcptsopt[sip][4], \
               self.tcptsopt[sip][5], self.tcptsopt[sip][6], self.tcptsopt[sip][7], self.tcptsopt[sip][8], self.tcptsopt[sip][9], \
               self.tcptsopt[sip][10], self.tcptsopt[sip][11], self.tcptsopt[sip][12], self.tcptsopt[sip][13], self.tcptsopt[sip][14], \
               #np.std(self.tcptsopt[sip][0:5]), np.std(self.tcptsopt[sip][0:10]), np.std(self.tcptsopt[sip]),\
               #sum(self.tcptsopt[sip][0:5])/5.0,sum(self.tcptsopt[sip][0:10])/10.0,sum(self.tcptsopt[sip])/15.0,\
               self.tcpmptcp[sip][0], self.tcpmptcp[sip][1], self.tcpmptcp[sip][2], self.tcpmptcp[sip][3], self.tcpmptcp[sip][4], \
               self.tcpmptcp[sip][5], self.tcpmptcp[sip][6], self.tcpmptcp[sip][7], self.tcpmptcp[sip][8], self.tcpmptcp[sip][9], \
               self.tcpmptcp[sip][10], self.tcpmptcp[sip][11], self.tcpmptcp[sip][12], self.tcpmptcp[sip][13], self.tcpmptcp[sip][14], \
               #np.std(self.tcpmptcp[sip][0:5]), np.std(self.tcpmptcp[sip][0:10]), np.std(self.tcpmptcp[sip]),\
               #sum(self.tcpmptcp[sip][0:5])/5.0,sum(self.tcpmptcp[sip][0:10])/10.0,sum(self.tcpmptcp[sip])/15.0,\
               self.tcpsack[sip][0], self.tcpsack[sip][1], self.tcpsack[sip][2], self.tcpsack[sip][3], self.tcpsack[sip][4], \
               self.tcpsack[sip][5], self.tcpsack[sip][6], self.tcpsack[sip][7], self.tcpsack[sip][8], self.tcpsack[sip][9], \
               self.tcpsack[sip][10], self.tcpsack[sip][11], self.tcpsack[sip][12], self.tcpsack[sip][13], self.tcpsack[sip][14], \
               #np.std(self.tcpsack[sip][0:5]), np.std(self.tcpsack[sip][0:10]), np.std(self.tcpsack[sip]),\
               #sum(self.tcpsack[sip][0:5])/5.0,sum(self.tcpsack[sip][0:10])/10.0,sum(self.tcpsack[sip])/15.0,\
               self.tcpsckprm[sip][0],self.tcpsckprm[sip][1],self.tcpsckprm[sip][2],self.tcpsckprm[sip][3],self.tcpsckprm[sip][4],\
               self.tcpsckprm[sip][5],self.tcpsckprm[sip][6],self.tcpsckprm[sip][7],self.tcpsckprm[sip][8],self.tcpsckprm[sip][9],\
               self.tcpsckprm[sip][10],self.tcpsckprm[sip][11],self.tcpsckprm[sip][12],self.tcpsckprm[sip][13],self.tcpsckprm[sip][14],\
               #np.std(self.tcpsckprm[sip][0:5]), np.std(self.tcpsckprm[sip][0:10]), np.std(self.tcpsckprm[sip]),\
               #sum(self.tcpsckprm[sip][0:5])/5.0,sum(self.tcpsckprm[sip][0:10])/10.0,sum(self.tcpsckprm[sip])/15.0,\
               str(ippack.srcip), self.IPtoURL[sip]))
              log.debug("written to file : str(sip)" + " " + self.IPtoURL[sip])  
              self.previous_time[sip] = self.current_time[sip]
              self.count[sip] = 0
              self.tot_bytes[sip] = 0
              self.tot_ipd[sip] = 0
              self.c = 0
              msg = of.ofp_flow_mod()
              msg.match = of.ofp_match.from_packet(packet, event.port)
              msg.idle_timeout = 5
              msg.hard_timeout = 5
              msg.actions.append(of.ofp_action_output(port = port))
              msg.data = event.ofp # 6a
              self.connection.send(msg)
          
          #elif dip in self.IPtoURL:
            #training_data_file.write("%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\r\n" % (self.count, smac, dmac, plen, sip, dip, sport, dport, between_pkts, self.tot_bytes, self.tot_ipd, self.IPtoURL[dip], tcppack.hdr_len, tcppack.payload_len, current_milli_time))
          
          #log.debug("sending flow_mod, business as usual")
          #then business as usual
            tmp_msg = of.ofp_packet_out()
          #tmp_action = of.ofp_action_output(port = port)
          #tmp_msg.match = of.ofp_match.from_packet(packet, event.port)
          #tmp_msg.idle_timeout = 5
          #tmp_msg.hard_timeout = 5
            tmp_msg.actions.append(of.ofp_action_output(port = port))
            tmp_msg.data = event.ofp
            self.connection.send(tmp_msg)
          
          else:
            flood()
        elif packet.find('dns'):
          
          p = packet.find('dns')
          p.parsed
          
          def process_q(entry):
            #if(entry.qtype == pkt.dns.rr.A_TYPE):
            if True:
              log.info("add dns entry: %s %s" %(entry.rddata, entry.name))
              #log.info("rddata " + pkt.dns.get_rddata())	
              if "wikimedia" in str(entry.name):
                self.IPtoURL[entry.rddata] = "wikimedia"	
              elif "duckduckgo" in str(entry.name):
                self.IPtoURL[entry.rddata] = "duckduckgo"	
              #elif "gstatic" in str(entry.name):
              #  self.IPtoURL[entry.rddata] = "google"
              elif "twitter" in str(entry.name) or "t.co" in str(entry.name) or "twimg" in str(entry.name):
                self.IPtoURL[entry.rddata] = "twitter"
              elif "quora" in str(entry.name):
                self.IPtoURL[entry.rddata] = "quora"
              elif "whatsapp" in str(entry.name):
                self.IPtoURL[entry.rddata] = "whatsapp"
              elif "gateoverflow" in str(entry.name) or "gatecse" in str(entry.name):
                self.IPtoURL[entry.rddata] = "gateoverflow"	
              elif "flipkart" in str(entry.name):
                self.IPtoURL[entry.rddata] = "flipkart"
              elif "google.com" in str(entry.name):
                self.IPtoURL[entry.rddata] = "google"
              elif "facebook.com" in str(entry.name) or "fbcdn" in str(entry.name) or "fbsbx" in str(entry.name):
                self.IPtoURL[entry.rddata] = "facebook"
              
              
              #else:
              
              #self.IPtoURL[entry.rddata] = entry.name	
              
              #self.IPtoURL[entry.rddata] = entry.name
              self.tot_bytes[entry.rddata] = 0
              self.tot_ipd[entry.rddata] = 0
              self.current_time[entry.rddata] = 0
              current_milli_time = int(round(time.time() * 1000))         
              self.previous_time[entry.rddata] = current_milli_time
              self.start_time[entry.rddata] = current_milli_time
              self.count[entry.rddata] = 0
              self.c = 0
              #self.tcp_hlen = 0
             # self.tcp_dlen = 0
          
          for answer in p.answers:
            process_q(answer)
            
          for addition in p.additional:
            process_q(addition)
            
          for auth in p.authorities:
            process_q(auth)
            
          flood()
          
          
          
       
        else:
          self.c = 0
          #log.debug("installing flow for %s.%i -> %s.%i" %(packet.src, event.port, packet.dst, port))
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet, event.port)
          msg.idle_timeout = 10
          msg.hard_timeout = 10
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = event.ofp # 6a
          self.connection.send(msg)


class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent, ignore = None):
    """
    Initialize

    See LearningSwitch for meaning of 'transparent'
    'ignore' is an optional list/set of DPIDs to ignore
    """
    core.openflow.addListeners(self)
    self.transparent = transparent
    self.ignore = set(ignore) if ignore else ()

  def _handle_ConnectionUp (self, event):
    if event.dpid in self.ignore:
      log.debug("Ignoring connection %s" % (event.connection,))
      return
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay, ignore = None):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)

  core.registerNew(l2_learning, str_to_bool(transparent), ignore)
