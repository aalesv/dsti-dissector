local ID_PASSTHRU = 0x0210

local OPCODE_CONNECT		= 0x00
local OPCODE_DISCONNECT		= 0x01
local OPCODE_WRITE			= 0x03
local OPCODE_SET_FILTER		= 0x06
local OPCODE_READ_VERSION	= 0x09
local OPCODE_GET_LAST_ERROR	= 0x0A
local OPCODE_IOCTL			= 0x0B

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
local SSM_ISO15765 =0x20004

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
--- Proprietary Subaru IDs
local SSM_SET_CONFIG =						0x10002

densodsti_protocol = Proto("DensoDSTi", "Denso DST-i protocol")

protocol_version =	ProtoField.uint16("DensoDSTi.version", "version", base.HEX)
length =		ProtoField.uint8 ("DensoDSTi.length", "length", base.DEC_HEX)
address =		ProtoField.uint16("DensoDSTi.address", "address", base.HEX)
opCode =		ProtoField.uint8("DensoDSTi.opCode", "opCode", base.HEX)
data =			ProtoField.bytes("DensoDSTi.data", "data", base.SPACE)
checksum =		ProtoField.none("DensoDSTi.checksum", "checksum", base.HEX)

densodsti_protocol.fields = {protocol_version, length, address, opCode, data, checksum}

function densodsti_protocol.dissector(buffer, pinfo, tree)
  local buffer_length = buffer:len()
  if buffer_length == 0 then return end

  pinfo.cols.protocol = densodsti_protocol.name
  
  local pid = buffer(0,2):uint()
  local addr = buffer(3,2):uint()
  local opcode = buffer(5,1):uint()
  local opcode_text = ""
  if	 (opcode == OPCODE_CONNECT) then opcode_text = " (CONNECT)"
  elseif (opcode == OPCODE_DISCONNECT) then opcode_text = " (DISCONNECT)"
  elseif (opcode == OPCODE_WRITE) then opcode_text = " (WRITE)"
  elseif (opcode == OPCODE_SET_FILTER) then opcode_text = " (SET_FILTER)"
  elseif (opcode == OPCODE_READ_VERSION) then opcode_text = " (READ_VERSION)"
  elseif (opcode == OPCODE_GET_LAST_ERROR) then opcode_text = " (GET_LAST_ERROR)"
  elseif (opcode == OPCODE_IOCTL) then opcode_text = " (IOCTL)"
  end
  
  local data_len = buffer(2,1):uint()

  local subtree = tree:add(densodsti_protocol, buffer(), "Denso DST-i Data")
  local headerSubtree = subtree:add(densodsti_protocol, buffer(0, 6), "Header")
  local payloadSubtree = subtree:add(densodsti_protocol, buffer(6, data_len), "Payload")

  headerSubtree:add(protocol_version,buffer(0,2))
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
  elseif (pid == ID_PASSTHRU and opcode == OPCODE_WRITE)
  then
	if     (addr == 0x007f)	then write_protocol_dissector_req (dataBuf:tvb(), pinfo, payloadSubtree)
	elseif (addr == 0x00ff) then write_protocol_dissector_resp(dataBuf:tvb(), pinfo, payloadSubtree)
	else
		payloadSubtree:add(data, dataBuf)
	end
  elseif (pid == ID_PASSTHRU and opcode == OPCODE_SET_FILTER)
  then
	if     (addr == 0x007f)	then set_filter_protocol_dissector_req (dataBuf:tvb(), pinfo, payloadSubtree)
	elseif (addr == 0x00ff) then set_filter_protocol_dissector_resp(dataBuf:tvb(), pinfo, payloadSubtree)
	else
		payloadSubtree:add(data, dataBuf)
	end
  elseif (pid == ID_PASSTHRU and opcode == OPCODE_GET_LAST_ERROR)
  then
	if     (addr == 0x007f)	then get_last_error_protocol_dissector_req (dataBuf:tvb(), pinfo, payloadSubtree)
	elseif (addr == 0x00ff) then get_last_error_protocol_dissector_resp(dataBuf:tvb(), pinfo, payloadSubtree)
	else
		payloadSubtree:add(data, dataBuf)
	end
  elseif (pid == ID_PASSTHRU and opcode == OPCODE_READ_VERSION)
  then
	if     (addr == 0x007f)	then read_version_protocol_dissector_req (dataBuf:tvb(), pinfo, payloadSubtree)
	elseif (addr == 0x00ff) then read_version_protocol_dissector_resp(dataBuf:tvb(), pinfo, payloadSubtree)
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
	local pid_name = get_protocol_description(pid)
	
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
ioctl_length = ProtoField.uint32("DensoDSTi.ioctl.length", "length", base.DEC_HEX)
ioctl_param = ProtoField.uint32("DensoDSTi.ioctl.param", "param", base.HEX)
ioctl_value = ProtoField.uint32("DensoDSTi.ioctl.value", "value", base.DEC_HEX)

ioctl_protocol.fields = {ioctl_unk, ioctl_returnCode, ioctl_channelID, ioctl_id, ioctl_length, ioctl_param, ioctl_value}

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
	elseif	(id == SSM_SET_CONFIG) then id_name = " (SSM_SET_CONFIG)"
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
		subtree:add_le(ioctl_length, buffer(8,4))
		ioctl_protocol_set_config_dissector(buffer(12, buffer_length-12):tvb(), pinfo, subtree)
	elseif (id == SSM_SET_CONFIG) then
		sbyte_array_protocol_dissector(buffer(8, buffer_length-8):tvb(), pinfo, subtree)
	elseif (id == FAST_INIT) then
		fast_init_protocol_dissector(buffer(8, buffer_length-8):tvb(), pinfo, subtree)
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
	
	--- Successful response contains payload
	---if (r == 0 and id == GET_CONFIG) then

	if (r == 0 and id == READ_VBATT) then
		vbatt_protocol_dissector(buffer(9, 4), pinfo, subtree)
	end

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

--- FAST_INIT dissector

fast_init_protocol = Proto("DensoDstiIOCTL_FAST_INIT", "Denso DST-i IOCTL FAST_INIT")
fast_init_unk = ProtoField.uint8("DensoDSTi.fast_init.unk", "unk", base.HEX)
fast_init_returnCode = ProtoField.uint32("DensoDSTi.fast_init.returnCode", "returnCode", base.HEX)
fast_init_channelID = ProtoField.uint32("DensoDSTi.fast_init.channelID", "channelID", base.HEX)

function fast_init_protocol_dissector(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	--- Next is PASSTHRU_MSG
	passthru_msg_protocol_dissector(buffer, pinfo, tree)
end

--- SBYTE_ARRAY dissector
sbyte_array_protocol = Proto("DensoDstiSBYTE_ARRAY", "Denso DST-i SBYTE_ARRAY")
sbyte_array_numOfBytes = ProtoField.uint32("DensoDSTi.sbyte_array.numOfBytes", "NumOfBytes", base.DEC_HEX)

sbyte_array_protocol.fields = {sbyte_array_numOfBytes}

function sbyte_array_protocol_dissector(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length < 5 then return end

	local subtree = tree
	subtree:add_le(sbyte_array_numOfBytes, buffer(0,4))
	subtree:add(data, buffer(4, buffer_length-4))
end

--- VBATT dissector
vbatt_protocol = Proto("DensoDstiVBATT", "Denso DST-i VBATT")
vbatt_value = ProtoField.uint32("DensoDSTi.vbatt.value", "value", base.DEC_HEX)

vbatt_protocol.fields = {vbatt_value}

function vbatt_protocol_dissector(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length < 4 then return end

	local subtree = tree
	subtree:add_le(vbatt_value, buffer(0,4))
	
end

--- PASSTHRU_MSG dissector
passthru_msg_protocol = Proto("DensoDstiPASSTHRU_MSG", "Denso DST-i PASSTHRU_MSG")
passthru_msg_ProtocolID = ProtoField.uint32("DensoDSTi.passthru_msg.ProtocolID", "ProtocolID", base.HEX)
passthru_msg_RxStatus = ProtoField.uint32("DensoDSTi.passthru_msg.RxStatus", "RxStatus", base.HEX)
passthru_msg_TxFlags = ProtoField.uint32("DensoDSTi.passthru_msg.TxFlags", "TxFlags", base.HEX)
passthru_msg_Timestamp = ProtoField.uint32("DensoDSTi.passthru_msg.Timestamp", "Timestamp", base.HEX)
passthru_msg_DataSize = ProtoField.uint32("DensoDSTi.passthru_msg.DataSize", "DataSize", base.DEC_HEX)
passthru_msg_ExtraDataIndex = ProtoField.uint32("DensoDSTi.passthru_msg.ExtraDataIndex", "ExtraDataIndex", base.HEX)
passthru_msg_Data = ProtoField.bytes("DensoDSTi.passthru_msg.Data", "MSG", base.SPACE)

passthru_msg_protocol.fields = {passthru_msg_ProtocolID,
								passthru_msg_RxStatus,
								passthru_msg_TxFlags,
								passthru_msg_Timestamp,
								passthru_msg_DataSize,
								passthru_msg_ExtraDataIndex,
								passthru_msg_Data}

function passthru_msg_protocol_dissector(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length < 24 then return end

	local pid = buffer(0,4):le_uint()
	local pid_name = get_protocol_description(pid)
	local data_size = buffer(16,4):le_uint()

	local subtree = tree ---:add(data, buffer())
	subtree:add_le(passthru_msg_ProtocolID, buffer(0,4)):append_text(pid_name)
	subtree:add_le(passthru_msg_RxStatus, buffer(4,4))
	subtree:add_le(passthru_msg_TxFlags, buffer(8,4))
	subtree:add_le(passthru_msg_Timestamp, buffer(12,4))
	subtree:add_le(passthru_msg_DataSize, buffer(16,4))
	subtree:add_le(passthru_msg_ExtraDataIndex, buffer(20,4))
	subtree:add_le(passthru_msg_Data, buffer(24,data_size))

end

--- GET_LAST_ERROR dissector
get_last_error_protocol = Proto("DensoDstiGET_LAST_ERROR", "Denso DST-i GET_LAST_ERROR")
get_last_error_unk = ProtoField.uint8("DensoDSTi.get_last_error.unk", "unk", base.HEX)
get_last_error_returnCode = ProtoField.uint32("DensoDSTi.get_last_error.returnCode", "returnCode", base.HEX)
get_last_error_length = ProtoField.uint32("DensoDSTi.get_last_error.length", "length", base.DEC_HEX)
get_last_error_message = ProtoField.string("DensoDSTi.get_last_error.error_message", "error_message", base.NONE)

get_last_error_protocol.fields = {get_last_error_unk, get_last_error_returnCode, get_last_error_length, get_last_error_message}

function get_last_error_protocol_dissector_req(buffer, pinfo, tree)
		pinfo.cols.protocol = "DENSODSTI.GET_LAST_ERROR_REQ"
end
function get_last_error_protocol_dissector_resp(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end
	
	pinfo.cols.protocol = "DENSODSTI.GET_LAST_ERROR_RESP"
		
	local msg_len = buffer(5, 4):le_uint()

	local subtree = tree:add(data, buffer())
	subtree:add_le(get_last_error_unk, buffer(0,1))
	subtree:add_le(get_last_error_returnCode, buffer(1,4))
	subtree:add_le(get_last_error_length, buffer(5, 4))
	subtree:add(get_last_error_message, buffer(9, msg_len))
end

--- WRITE dissector
write_protocol = Proto("DensoDstiWRITE", "Denso DST-i WRITE")
write_unk = ProtoField.uint8("DensoDSTi.write.unk", "unk", base.HEX)
write_returnCode = ProtoField.uint32("DensoDSTi.write.returnCode", "returnCode", base.HEX)
write_channelID = ProtoField.uint32("DensoDSTi.write.channelID", "channelID", base.HEX)
write_numMsg = ProtoField.uint32("DensoDSTi.write.numMsg", "numMsg", base.DEC_HEX)
write_timeout = ProtoField.uint32("DensoDSTi.write.timeout", "timeout", base.DEC_HEX)

write_protocol.fields = {write_unk, write_returnCode, write_channelID, write_numMsg, write_timeout}

function write_protocol_dissector_req(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length < 36 then return end

	pinfo.cols.protocol = "DENSODSTI.WRITE_REQ"
	
	local subtree = tree:add(data, buffer())
	subtree:add_le(write_channelID, buffer(0,4))
	subtree:add_le(write_numMsg, buffer(4,4))
	subtree:add_le(write_timeout, buffer(8,4))
	
	--- Next is PASSTHRU_MSG
	passthru_msg_protocol_dissector(buffer(12, buffer_length-12), pinfo, subtree)

end

function write_protocol_dissector_resp(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end
	
	local r = buffer(1,4):le_uint()

	pinfo.cols.protocol = "DENSODSTI.WRITE_RESP"
	
	local subtree = tree:add(data, buffer())
	subtree:add_le(write_unk, buffer(0,1))
	subtree:add_le(write_returnCode, buffer(1,4)):append_text(get_return_code_description(r))
	subtree:add_le(write_numMsg, buffer(5,4))

end

--- READ_VERSION dissector
read_version_protocol = Proto("DensoDstiREAD_VERSION", "Denso DST-i READ_VERSION")
read_version_unk = ProtoField.uint8("DensoDSTi.read_version.unk", "unk", base.HEX)
read_version_returnCode = ProtoField.uint32("DensoDSTi.read_version.returnCode", "returnCode", base.HEX)
read_version_length = ProtoField.uint32("DensoDSTi.read_version.length", "length", base.DEC_HEX)
read_version_version_string = ProtoField.string("DensoDSTi.read_version.error_message", "version_string", base.NONE)

read_version_protocol.fields = {read_version_unk, read_version_returnCode, read_version_length, read_version_version_string}

function read_version_protocol_dissector_req(buffer, pinfo, tree)
	pinfo.cols.protocol = "DENSODSTI.READ_VERSION_REQ"
end

function read_version_protocol_dissector_resp(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end
	
	pinfo.cols.protocol = "DENSODSTI.READ_VERSION_RESP"
	
	local subtree = tree:add(data, buffer())
	
	local r = buffer(1,4):le_uint()
	
	subtree:add_le(read_version_unk, buffer(0,1))
	subtree:add_le(read_version_returnCode, buffer(1,4)):append_text(get_return_code_description(r))
	
	if (r == 0) then
		local pos = 5
		for i=0, 2, 1
		do
			local str_len = buffer(pos,4):le_uint()
			subtree:add_le(read_version_length, buffer(pos,4))
			subtree:add_le(read_version_version_string, buffer(pos+4, str_len))
			pos = pos + 4 + str_len
		end
	end
	
end

--- SET_FILTER dissector
set_filter_protocol = Proto("DensoDstiSET_FILTER", "Denso DST-i SET_FILTER")
set_filter_unk = ProtoField.uint8("DensoDSTi.set_filter.unk", "unk", base.HEX)
set_filter_returnCode = ProtoField.uint32("DensoDSTi.set_filter.returnCode", "returnCode", base.HEX)
set_filter_channelID = ProtoField.uint32("DensoDSTi.set_filter.channelID", "channelID", base.HEX)
set_filter_filterType = ProtoField.uint32("DensoDSTi.set_filter.filterType", "filterType", base.HEX)
set_filter_type = ProtoField.uint32("DensoDSTi.set_filter.type", "type", base.HEX)
set_filter_filterID = ProtoField.uint32("DensoDSTi.set_filter.filterID", "filterID", base.HEX)
set_filter_msgID = ProtoField.uint32("DensoDSTi.set_filter.msgID", "msgID", base.DEC_HEX)

set_filter_protocol.fields = {set_filter_unk,
							  set_filter_returnCode,
							  set_filter_channelID,
							  set_filter_filterType,
							  set_filter_type,
							  set_filter_filterID,
							  set_filter_msgID}

function add_passthru_message(protocol, buffer, tree, name)
	local msg_len = get_passthru_msg_length(buffer(0,24))
	local msg = tree:add(protocol, buffer(0, 24+msg_len), name)
	passthru_msg_protocol_dissector(buffer(0, 24+msg_len), nil, msg)
end

function set_filter_protocol_dissector_req(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	pinfo.cols.protocol = "DENSODSTI.SET_FILTER_REQ"
	
	local ftype = buffer(4,4):le_uint()
	local ftype_name
	if 		(ftype == 1) then ftype_name = " (PASS_FILTER)"
	elseif	(ftype == 2) then ftype_name = " (BLOCK_FILTER)"
	elseif	(ftype == 3) then ftype_name = " (FLOW_CONTROL_FILTER)"
	end
	
	local subtree = tree:add(data, buffer())
	subtree:add_le(set_filter_channelID, buffer(0,4))
	subtree:add_le(set_filter_filterType, buffer(4,4)):append_text(ftype_name)
	local ftype_int = buffer(8,1):le_uint()
	subtree:add_le(set_filter_type, buffer(8,1)):append_text(get_internal_filter_type_description(ftype_int))
	
	local pos = 9
	if (ftype == 1) then
		local maskMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "Mask")	
		
		pos = pos + 24 + maskMsg_len
		local patternMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "FlowControl")
	elseif (ftype == 3) then
		local maskMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "Mask")	
		
		pos = pos + 24 + maskMsg_len
		local patternMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "Pattern")	
		
		pos = pos + 24 + patternMsg_len
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "FlowControl")
	end
end


function set_filter_protocol_dissector_resp(buffer, pinfo, tree)
	local buffer_length = buffer:len()
	if buffer_length == 0 then return end

	pinfo.cols.protocol = "DENSODSTI.SET_FILTER_RESP"

	local ftype = buffer(9,1):le_uint()

	local subtree = tree:add(data, buffer())
	subtree:add_le(set_filter_unk, buffer(0,1))
	subtree:add_le(set_filter_returnCode, buffer(1,4)):append_text(get_return_code_description(buffer(1,4):le_uint()))
	subtree:add_le(set_filter_msgID, buffer(5,4))
	local ftype_int = buffer(9,1):le_uint()
	subtree:add_le(set_filter_type, buffer(9,1)):append_text(get_internal_filter_type_description(ftype_int))
	
	local pos = 10
	if (ftype == 3) then
		local maskMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "Mask")	
		
		pos = pos + 24 + maskMsg_len
		local patternMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "FlowControl")
	elseif (ftype == 7) then
		local maskMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "Mask")	
		
		pos = pos + 24 + maskMsg_len
		local patternMsg_len = get_passthru_msg_length(buffer(pos,24))
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "Pattern")	
		
		pos = pos + 24 + patternMsg_len
		add_passthru_message(set_filter_protocol, buffer(pos, buffer_length-pos), subtree, "FlowControl")
	end

end

--- Utility
function get_protocol_description(pid)
	local pid_name = " "
	
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
	elseif (pid == SSM_ISO15765) then	pid_name = " (SSM_ISO15765)"
	end

	return pid_name 
end

function get_return_code_description(code)
	local des = ""
	if (code == 0) then des = " (OK)" end
	return des
end

function get_passthru_msg_length(buffer)
	local buffer_length = buffer:len()
	if buffer_length < 24 then return 0
	else return buffer(16,4):le_uint()
	end
end

function get_internal_filter_type_description(ftype)
	local type_name = " "
	if		(ftype == 3) then type_name = " (PASS_FILTER)"
	elseif	(ftype == 7) then type_name = " (FLOW_CONTROL_FILTER)"
	end
	return type_name
end

DissectorTable.get("usb.bulk"):add(0xffff, densodsti_protocol)
DissectorTable.get("usb.bulk"):add(0xff, densodsti_protocol)
