local ID_PASSTHRU = 0x0210

local OPCODE_CONNECT	= 0x00
local OPCODE_IOCTL	= 0x0B
local OPCODE_SET_FILTER	= 0x06

--- J2534 protocols
local J1850VPW =	0x01
local J1850PWM =	0x02
local ISO9141 =		0x03
local ISO14230 =	0x04
local CAN =			0x05
local ISO15765 =	0x06
local SCI_A_ENGINE =0x07
local SCI_A_TRANS =	0x08
local SCI_B_ENGINE =0x09
local SCI_B_TRANS =	0x0A
--- Proprietary Subaru protocols
local SSM_ISO9141 =	0x20001

densodsti_protocol = Proto("DensoDSTi", "Denso DST-i protocol")

protocol_id =	ProtoField.uint16("DensoDSTi.id", "id", base.HEX)
length =		ProtoField.uint8 ("DensoDSTi.length", "length", base.HEX)
address =		ProtoField.uint16("DensoDSTi.address", "address", base.HEX)
opCode =		ProtoField.uint8("DensoDSTi.opCode", "opCode", base.HEX)
data =			ProtoField.bytes("DensoDSTi.data", "data", base.SPACE)
checksum =		ProtoField.none("DensoDSTi.checksum", "checksum", base.HEX)

densodsti_protocol.fields = {protocol_id, length, address, opCode, data, checksum}

function densodsti_protocol.dissector(buffer, pinfo, tree)
  local buffer_length = buffer:len()
  if buffer_length == 0 then return end

  pinfo.cols.protocol = densodsti_protocol.name
  
  local pid = buffer(0,2):uint()
  local addr = buffer(3,2):uint()
  local opcode = buffer(5,1):uint()
  local opcode_text = ""
  if (opcode == OPCODE_CONNECT) then opcode_text = " (CONNECT)" end
  if (opcode == OPCODE_IOCTL) then opcode_text = " (IOCTL)" end
  if (opcode == OPCODE_SET_FILTER) then opcode_text = " (SET_FILTER)" end
  
  local data_len = buffer(2,1):uint()

  local subtree = tree:add(densodsti_protocol, buffer(), "Denso DST-i Data")
  local headerSubtree = subtree:add(densodsti_protocol, buffer(), "Header")
  local payloadSubtree = subtree:add(densodsti_protocol, buffer(), "Payload")

  headerSubtree:add(protocol_id,buffer(0,2))
  headerSubtree:add(length,		buffer(2,1))
  headerSubtree:add(address,		buffer(3,2))
  headerSubtree:add(opCode,		buffer(5,1)):append_text(opcode_text)
  local opCodePosEnd = 6
  local data_end_pos_len = buffer_length-2-opCodePosEnd
  local dataBuf = buffer(6,data_end_pos_len)
  
  if (pid == ID_PASSTHRU and opcode == OPCODE_CONNECT)
  then
	if     (addr == 0x007f)	then connect_protocol_dissector_req (dataBuf:tvb(), pinfo, payloadSubtree)
	elseif (addr == 0x00ff) then connect_protocol_dissector_resp(dataBuf:tvb(), pinfo, payloadSubtree)
	else
		payloadSubtree:add(data, dataBuf)
	end
  else
	payloadSubtree:add(data, dataBuf)
  end
  payloadSubtree:add(checksum,		buffer(data_end_pos_len+opCodePosEnd,2))
end

--- CONNECT dissector

connect_protocol = Proto("DensoDstiConnect", "Denso DST-i CONNECT")
protocolID = ProtoField.uint32("DensoDSTi.protocol_id", "protocol_id", base.HEX)
connect_flags = ProtoField.uint32("DensoDSTi.connect.flags", "flags", base.HEX)
resp_unk = ProtoField.uint8("DensoDSTi.resp_unk", "unk", base.HEX)
return_code = ProtoField.uint32("DensoDSTi.return_code", "returnCode", base.HEX)
channelID = ProtoField.uint32("DensoDSTi.channelID", "channelID", base.HEX)

connect_protocol.fields = {resp_unk, return_code, channelID, protocolID, connect_flags}

function connect_protocol_dissector_req(buffer, pinfo, tree)
	pinfo.cols.protocol = "DENSODSTI.CONNECT_REQ"
	
	local pid = buffer(0,4):le_uint()
	local pid_name = tostring(pid)
	
	
	if     (pid == J1850VPW) then		pid_name = " (J1850VPW)"
	elseif (pid == J1850PWM) then		pid_name = " (J1850PWM)"
	elseif (pid == ISO9141) then		pid_name = " (ISO9141)"
	elseif (pid == ISO14230) then		pid_name = " (ISO14230)"
	elseif (pid == CAN) then			pid_name = " (CAN)"
	elseif (pid == ISO15765) then		pid_name = " (ISO15765)"
	elseif (pid == SCI_A_ENGINE) then	pid_name = " (SCI_A_ENGINE)"
	elseif (pid == SCI_A_TRANS) then	pid_name = " (SCI_A_TRANS)"
	elseif (pid == SCI_B_ENGINE) then	pid_name = " (SCI_B_ENGINE)"
	elseif (pid == SCI_B_TRANS) then	pid_name = " (SCI_B_TRANS)"
	elseif (pid == SSM_ISO9141) then	pid_name = " (SSM_ISO9141)"
	end
	
	local subtree = tree:add(data, buffer())
	subtree:add_le(protocolID, buffer(0,4)):append_text(pid_name)
	subtree:add_le(connect_flags, buffer(4,4))
end

function connect_protocol_dissector_resp(buffer, pinfo, tree)
	pinfo.cols.protocol = "DENSODSTI.CONNECT_RESP"
	local subtree = tree:add(data, buffer())
	subtree:add_le(resp_unk, buffer(0,1))
	subtree:add_le(return_code, buffer(1,4))
	subtree:add_le(channelID, buffer(5,4))
end

DissectorTable.get("usb.bulk"):add(0xffff, densodsti_protocol)
DissectorTable.get("usb.bulk"):add(0xff, densodsti_protocol)
