local message_types = {
   [0x01] = "FLOW START",
   [0x03] = "FLOW STOP",
   [0x05] = "CONNECT",
   [0x06] = "CONNECT RESPONSE",
   [0x07] = "DISCONNECT",
   [0x08] = "SESSION START",
   [0x09] = "SESSION STOP",
   [0x10] = "TEMPLATE DATA",
   [0x13] = "FINAL TEMPLATE DATA ACK",
   [0x14] = "GET SESSIONS",
   [0x15] = "GET SESSIONS RESPONSE",
   [0x16] = "GET TEMPLATES",
   [0x17] = "GET TEMPLATES RESPONSE",
   [0x1a] = "MODIFY TEMPLATE",
   [0x1b] = "MODIFY TEMPLATE RESPONSE",
   [0x1d] = "START NEGOTIATION",
   [0x1e] = "START NEGOTIATION REJECT",
   [0x20] = "DATA",
   [0x21] = "DATA ACKNOWLEDGE",
   [0x23] = "ERROR",
   [0x30] = "REQUEST",
   [0x31] = "RESPONSE",
   [0x40] = "KEEP ALIVE",
}



function ipdr_proto_dissector (buffer, pinfo, tree)
   tree = tree:add(ipdr_proto, buffer(), "IPDR")
   
   tree:add_le(buffer(0,1), "Version: "..buffer(0,1):uint())
   
   local type = buffer(1,1):uint()
   local typename = message_types[type]
   if not typename then typename = "" end
   tree:add_le(buffer(1,1), "Message ID: "..type.." ("..typename..")")
   
   tree:add_le(buffer(2,1), "Session ID: "..buffer(2,1):uint())
   tree:add_le(buffer(3,1), "Message Flags: "..buffer(3,1):uint())
   local messagelen = buffer(4,4):uint()
   tree:add_le(buffer(4,4), "Message Length: "..messagelen)
   if messagelen > 8 then
      tree:add_le(buffer(8,messagelen-8), "Content")
   end
   
   if messagelen > buffer:len() then
      return - (messagelen - buffer:len())
   end
   
   return messagelen
end

-- This is a work around so that reloading this file with dofile()
-- works correctly.  If it's not done this way, then wireshark 1.0.0
-- crashes on reloading the file.
if ipdr_proto == nil then
   ipdr_proto = Proto("ipdr", "IPDR")
   ipdr_proto["dissector"] = function(buffer, pinfo, tree) 
                                return ipdr_proto_dissector(buffer,
                                                            pinfo, 
                                                            tree)
                             end
   local tcp_table = DissectorTable.get("tcp.port")
   tcp_table:add(4737, ipdr_proto)
end


