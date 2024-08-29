local ID_PASSTHRU = 0x0210

local OPCODE_CONNECT	= 0x00
local OPCODE_DISCONNECT	= 0x01
local OPCODE_SET_FILTER	= 0x06
local OPCODE_IOCTL		= 0x0B

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

--- IOCTL IDs
local GET_CONFIG =							0x01
local SET_CONFIG =							0x02
local READ_VBATT =							0x03
local FIVE_BAUD_INIT =						0x04
local FAST_INIT=							0x05
local CLEAR_TX_BUFFER =						0x07
local CLEAR_RX_BUFFER =						0x08
local CLEAR_PERIODIC_MSGS =					0x09
local CLEAR_MSG_FILTERS =					0x0A
local CLEAR_FUNCT_MSG_LOOKUP_TABLE =		0x0B
local ADD_TO_FUNCT_MSG_LOOKUP_TABLE =		0x0C
local DELETE_FROM_FUNCT_MSG_LOOKUP_TABLE =	0x0D
local READ_PROG_VOLTAGE =					0x0E
local SW_CAN_NS = 0x8000
local SW_CAN_HS = 0x8001

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
  if (opcode == OPCODE_DISCONNECT) then opcode_text = " (DISCONNECT)" end
  if (opcode == OPCODE_SET_FILTER) then opcode_text = " (SET_FILTER)" end
  if (opcode == OPCODE_IOCTL) then opcode_text = " (IOCTL)" end
  
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
  elseif (pid == ID_PASSTHRU and opcode == OPCODE_DISCONNECT)
  then
	if     (addr == 0x007f)	then disconnect_protocol_dissector_req (dataBuf:tvb(), pinfo, payloadSubtree)
	elseif (addr == 0x00ff) then disconnect_protocol_dissector_resp(dataBuf:tvb(), pinfo, payloadSubtree)
	else
		payloadSubtree:add(data, dataBuf)
	end
  elseif (pid == ID_PASSTHRU and opcode == OPCODE_IOCTL)
  then
	if     (addr == 0x007f)	then ioctl_protocol_dissector_req (dataBuf:tvb(), pinfo, payloadSubtree)
	elseif (addr == 0x00ff) then ioctl_protocol_dissector_resp(dataBuf:tvb(), pinfo, payloadSubtree)
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
connect_protocolID = ProtoField.uint32("DensoDSTi.connect.protocol_id", "protocol_id", base.HEX)
connect_flags = ProtoField.uint32("DensoDSTi.connect.flags", "flags", base.HEX)
connect_unk = ProtoField.uint8("DensoDSTi.connect.unk", "unk", base.HEX)
connect_returnCode = ProtoField.uint32("DensoDSTi.connect.returnCode", "returnCode", base.HEX)
connect_channelID = ProtoField.uint32("DensoDSTi.connect.channelID", "channelID", base.HEX)

connect_protocol.fields = {connect_unk, connect_returnCode, connect_channelID, connect_protocolID, connect_flags}

function connect_protocol_dissector_req(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

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
	subtree:add_le(connect_protocolID, buffer(0,4)):append_text(pid_name)
	subtree:add_le(connect_flags, buffer(4,4))
end

function connect_protocol_dissector_resp(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	pinfo.cols.protocol = "DENSODSTI.CONNECT_RESP"
	local subtree = tree:add(data, buffer())
	subtree:add_le(connect_unk, buffer(0,1))
	local r = buffer(1,4):le_uint()
	subtree:add_le(connect_returnCode, buffer(1,4)):append_text(get_return_code_description(r))
	subtree:add_le(connect_channelID, buffer(5,4))
end

--- DISCONNECT dissector

disconnect_protocol = Proto("DensoDstiDisonnect", "Denso DST-i DISCONNECT")
disconnect_unk = ProtoField.uint8("DensoDSTi.disconnect.unk", "unk", base.HEX)
disconnect_returnCode = ProtoField.uint32("DensoDSTi.disconnect.returnCode", "returnCode", base.HEX)
disconnect_channelID = ProtoField.uint32("DensoDSTi.disconnect.channelID", "channelID", base.HEX)

disconnect_protocol.fields = {disconnect_unk, disconnect_returnCode, disconnect_channelID}

function disconnect_protocol_dissector_req(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	pinfo.cols.protocol = "DENSODSTI.DISCONNECT_REQ"
	
	local subtree = tree:add(data, buffer())
	subtree:add_le(disconnect_channelID, buffer(0,4))
end

function disconnect_protocol_dissector_resp(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	pinfo.cols.protocol = "DENSODSTI.DISCONNECT_RESP"
	local subtree = tree:add(data, buffer())
	subtree:add_le(connect_unk, buffer(0,1))
	local r = buffer(1,4):le_uint()
	subtree:add_le(connect_returnCode, buffer(1,4)):append_text(get_return_code_description(r))
end

--- IOCTL dissector

ioctl_protocol = Proto("DensoDstiIOCTL", "Denso DST-i IOCTL")
ioctl_unk = ProtoField.uint8("DensoDSTi.ioctl.unk", "unk", base.HEX)
ioctl_returnCode = ProtoField.uint32("DensoDSTi.ioctl.returnCode", "returnCode", base.HEX)
ioctl_channelID = ProtoField.uint32("DensoDSTi.ioctl.channelID", "channelID", base.HEX)
ioctl_id = ProtoField.uint32("DensoDSTi.ioctl.id", "id", base.HEX)
ioctl_lenght = ProtoField.uint32("DensoDSTi.ioctl.length", "length", base.HEX)
ioctl_param = ProtoField.uint32("DensoDSTi.ioctl.param", "param", base.HEX)
ioctl_value = ProtoField.uint32("DensoDSTi.ioctl.value", "value", base.DEC)

ioctl_protocol.fields = {ioctl_unk, ioctl_returnCode, ioctl_channelID, ioctl_id, ioctl_lenght, ioctl_param, ioctl_value}

function get_ioctl_id_name(id)
	local id_name = ""
	
	if		(id == GET_CONFIG) then id_name = " (GET_CONFIG)"
	elseif	(id == SET_CONFIG) then id_name = " (SET_CONFIG)"
	elseif	(id == READ_VBATT) then id_name = " (READ_VBATT)"
	elseif	(id == FIVE_BAUD_INIT) then id_name = " (FIVE_BAUD_INIT)"
	elseif	(id == FAST_INIT) then id_name = " (FAST_INIT)"
	elseif	(id == CLEAR_TX_BUFFER) then id_name = " (CLEAR_TX_BUFFER)"
	elseif	(id == CLEAR_RX_BUFFER) then id_name = " (CLEAR_RX_BUFFER)"
	elseif	(id == CLEAR_PERIODIC_MSGS) then id_name = " (CLEAR_PERIODIC_MSGS)"
	elseif	(id == CLEAR_MSG_FILTERS) then id_name = " (CLEAR_MSG_FILTERS)"
	elseif	(id == CLEAR_FUNCT_MSG_LOOKUP_TABLE) then id_name = " (CLEAR_FUNCT_MSG_LOOKUP_TABLE)"
	elseif	(id == ADD_TO_FUNCT_MSG_LOOKUP_TABLE) then id_name = " (ADD_TO_FUNCT_MSG_LOOKUP_TABLE)"
	elseif	(id == DELETE_FROM_FUNCT_MSG_LOOKUP_TABLE) then id_name = " (DELETE_FROM_FUNCT_MSG_LOOKUP_TABLE)"
	elseif	(id == READ_PROG_VOLTAGE) then id_name = " (READ_PROG_VOLTAGE)"
	elseif	(id == SW_CAN_NS) then id_name = " (SW_CAN_NS)"
	elseif	(id == SW_CAN_HS) then id_name = " (SW_CAN_HS)"
	end
	
	return id_name
end

function ioctl_protocol_dissector_req(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	pinfo.cols.protocol = "DENSODSTI.IOCTL_REQ"
	local subtree = tree:add(data, buffer())

	local chID = buffer(0,4):le_uint()
	local id = buffer(4,4):le_uint()
	
	local id_name = get_ioctl_id_name(id)

	subtree:add_le(ioctl_channelID, buffer(0,4))
	subtree:add_le(ioctl_id, buffer(4,4)):append_text(id_name)
	if (id == SET_CONFIG) then
		subtree:add_le(ioctl_lenght, buffer(8,4))
		ioctl_protocol_set_config_dissector(buffer(12, buffer_length-12):tvb(), pinfo, subtree)
	end
end

function ioctl_protocol_dissector_resp(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	pinfo.cols.protocol = "DENSODSTI.IOCTL_RESP"
	
	local id = buffer(5,4):le_uint()
	local id_name = get_ioctl_id_name(id)

	local subtree = tree:add(data, buffer())
	subtree:add_le(ioctl_unk, buffer(0,1))
	local r = buffer(1,4):le_uint()
	subtree:add_le(ioctl_returnCode, buffer(1,4)):append_text(get_return_code_description(r))
	subtree:add_le(ioctl_id, buffer(5,4)):append_text(id_name)

end

function ioctl_protocol_set_config_dissector(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length < 8 then return end

	local subtree = tree:add(data, buffer())

	for i = 0, buffer_length-2, 8
	do
		subtree:add_le(ioctl_param, buffer(i,4))
		subtree:add_le(ioctl_value, buffer(i+4,4))
	end
end

function get_return_code_description(code)
	local des = ""
	if (code == 0) then des = " (OK)" end
	return des
end

DissectorTable.get("usb.bulk"):add(0xffff, densodsti_protocol)
DissectorTable.get("usb.bulk"):add(0xff, densodsti_protocol)
