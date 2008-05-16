-- ipdr_proto = Proto("ipdr", "IPDR")

local message_types = {
   [0x05] = "CONNECT",
   [0x06] = "CONNECT RESPONSE",
   [0x07] = "DISCONNECT",
}

function ipdr_proto.dissector (buffer, pinfo, tree)
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

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(4737, ipdr_proto)

