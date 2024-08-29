local ID_PASSTHRU = 0x0210

local OPCODE_CONNECT	= 0x00
local OPCODE_SET_CONFIG	= 0x0B
local OPCODE_SET_FILTER	= 0x06

densodsti_protocol = Proto("DensoDSTi", "Denso DST-i protocol")

protocol_id =	ProtoField.uint16("DensoDSTi.id", "id", base.HEX)
length =		ProtoField.uint8 ("DensoDSTi.length", "length", base.HEX)
addr =			ProtoField.uint16("DensoDSTi.addr", "addr", base.HEX)
opCode =		ProtoField.uint8("DensoDSTi.opCode", "opCode", base.HEX)
data =			ProtoField.bytes("DensoDSTi.data", "data", base.SPACE)
checksum =		ProtoField.none("DensoDSTi.checksum", "checksum", base.HEX)

densodsti_protocol.fields = {protocol_id, length, addr, opCode, data, checksum}

function densodsti_protocol.dissector(buffer, pinfo, tree)
  local buffer_length = buffer:len()
  if buffer_length == 0 then return end

  pinfo.cols.protocol = densodsti_protocol.name
  
  local pid = buffer(0,2):uint()
  local opcode = buffer(5,1):uint()
  local opcode_text = ""
  if (opcode == OPCODE_CONNECT) then opcode_text = " (CONNECT)" end
  if (opcode == OPCODE_SET_CONFIG) then opcode_text = " (SET_CONFIG)" end
  if (opcode == OPCODE_SET_FILTER) then opcode_text = " (SET_FILTER)" end

  local subtree = tree:add(densodsti_protocol, buffer(), "Denso DST-i Data")
  local headerSubtree = subtree:add(densodsti_protocol, buffer(), "Header")
  local payloadSubtree = subtree:add(densodsti_protocol, buffer(), "Payload")

  headerSubtree:add(protocol_id,buffer(0,2))
  headerSubtree:add(length,		buffer(2,1))
  headerSubtree:add(addr,		buffer(3,2))
  headerSubtree:add(opCode,		buffer(5,1)):append_text(opcode_text)
  local opCodePosEnd = 6
  local data_end_pos_len = buffer_length-2-opCodePosEnd
  local dataBuf = buffer(6,data_end_pos_len)
  if (pid == ID_PASSTHRU and opcode == OPCODE_CONNECT)
  then
	connect_protocol_dissector(dataBuf:tvb(), pinfo, payloadSubtree)
  else
	payloadSubtree:add(data, dataBuf)
  end
  payloadSubtree:add(checksum,		buffer(data_end_pos_len+opCodePosEnd,2))
end

--- CONNECT dissector

connect_protocol = Proto("DensoDstiConnect", "Denso DST-i CONNECT")
ProtocolID = ProtoField.uint32("DensoDSTi.connect.protocol_id", "protocol_id", base.HEX)
Flags = ProtoField.uint32("DensoDSTi.connect.flags", "flags", base.HEX)

connect_protocol.fields = {ProtocolID, Flags}

function connect_protocol_dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "DENSODSTI.CONNECT"
	local subtree = tree:add(data, buffer())
	subtree:add_le(ProtocolID, buffer(0,4))
	subtree:add_le(Flags, buffer(4,4))
end

DissectorTable.get("usb.bulk"):add(0xffff, densodsti_protocol)
DissectorTable.get("usb.bulk"):add(0xff, densodsti_protocol)
