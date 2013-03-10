epson_video_proto = Proto("epson_video", "Epson Video Protocol")
evf = epson_video_proto.fields
evf.magic = ProtoField.string("epson_video.magic", "Magic")
evf.version = ProtoField.string("epson_video.version", "Version")
evf.serverip = ProtoField.ipv4("epson_video.serverip", "Server IP")
evf.cmd = ProtoField.uint32("epson_video.cmd", "Command")
evf.datasize = ProtoField.uint32("epson_video.datasize", "Datasize")
evf.type = ProtoField.uint8("epson_video.type", "Type")
evf.nrects = ProtoField.uint16("epson_video.nrects", "Rect Count")
evf.comp_ctl = ProtoField.uint8("epson_video.comp_ctl", "Compression Control", base.HEX)

function epson_video_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "EPSON VIDEO"
	local subtree = tree:add(epson_video_proto, buffer(), "Epson Video Protocol Data")

	if buffer(0,4):string() == "EPRD" then
		subtree:add(evf.magic,    buffer( 0, 4))
		subtree:add(evf.version,  buffer( 4, 4))
		subtree:add(evf.serverip, buffer( 8, 4))
		subtree:add(evf.cmd,      buffer(12, 4))
		subtree:add(evf.datasize, buffer(16, 4))
	else
		local _type = subtree:add(evf.type, buffer( 0, 1))

		if buffer(0,1):uint() == 0xc9 then
			_type:append_text(" (audio?)")
			subtree:add_le(evf.datasize, buffer(1,4))
		elseif buffer(0,1):uint() == 0x00 and buffer(1,1):uint() == 0x00 then
			_type:append_text(" (framebuffer update)")
			subtree:add(buffer( 1, 1), "pad: "    .. buffer( 1,1):uint())
			subtree:add(evf.nrects, buffer( 2, 2))
			subtree:add(buffer( 4, 2), "x: "      .. buffer( 4,2):uint())
			subtree:add(buffer( 6, 2), "y: "      .. buffer( 6,2):uint())
			subtree:add(buffer( 8, 2), "width: "  .. buffer( 8,2):uint())
			subtree:add(buffer(10, 2), "height: " .. buffer(10,2):uint())
			subtree:add(buffer(12, 4), "encoding: " .. buffer(12,4):uint())

			local encoding = buffer(12,4):uint()
			-- Tight encoding
			if encoding == 7 then
				subtree:add(evf.comp_ctl, buffer(16, 1))
				local bit = require('bit')
				-- jpeg compression (always 0x90 or maybe 0x91?)
				if bit.band(buffer(16,1):uint(), 0x90) then
					local compactlen_count = 1
					local compactlen = bit.band(buffer(17,1):uint(), 0x7F)

					if bit.band(buffer(17,1):uint(), 0x80) then
						compactlen =
							bit.bor(compactlen, bit.lshift(bit.band(buffer(18,1):uint(), 0x7F),7))
						compactlen_count = 2
						if bit.band(buffer(18,1):uint(), 0x80) then
							compactlen =
								bit.bor(compactlen,
								        bit.lshift(bit.band(buffer(19,1):uint(), 0xFF),14))
							compactlen_count = 3
						end
					end
					subtree:add(buffer(17, compactlen_count), "compact len: " .. compactlen)
				end
			end
		end
	end
end

epson_control_proto = Proto("epson_control", "Epson Control Protocol")

ecf = epson_control_proto.fields
ecf.magic = ProtoField.string("epson_control.magic", "Magic")
ecf.version = ProtoField.string("epson_control.version", "Version")
ecf.clientip = ProtoField.ipv4("epson_control.clientip", "Client IP")
ecf.cmdid = ProtoField.uint32("epson_control.cmdid", "CommandID")
ecf.datasize = ProtoField.uint32("epson_control.datasize", "Datasize")
ecf.record_count = ProtoField.uint32("epson_control.record_count", "Record Count")

-- request connection - fields
ecf.encryption = ProtoField.bool("epson_control.encryption", "Encryption")
ecf.encpassword = ProtoField.string("epson_control.encpassword", "EncPassword")
ecf.subnet = ProtoField.ipv4("epson_control.subnet", "Subnet Mask")
ecf.gateway = ProtoField.ipv4("epson_control.gateway", "Gateway")

ecf.width = ProtoField.uint16("epson_control.width", "Framebuffer Width")
ecf.height = ProtoField.uint16("epson_control.height", "Framebuffer Height")
ecf.bpp = ProtoField.uint8("epson_control.bpp", "Bits per pixel")
ecf.depth = ProtoField.uint8("epson_control.depth", "Depth")
ecf.bigendian = ProtoField.bool("epson_control.big_endian", "BigEndian")
ecf.truecolor = ProtoField.bool("epson_control.true_color", "TrueColor")
ecf.redmax = ProtoField.uint16("epson_control.redmax", "Red Max")
ecf.greenmax = ProtoField.uint16("epson_control.greenmax", "Green Max")
ecf.bluemax = ProtoField.uint16("epson_control.bluemax", "Blue Max")

ecf.redshift = ProtoField.uint8("epson_control.redshift", "Red Shift")
ecf.greenshift = ProtoField.uint8("epson_control.greenshift", "Green Shift")
ecf.blueshift = ProtoField.uint8("epson_control.blueshift", "Blue Shift")

ecf.namelength = ProtoField.uint32("epson_control.namelength", "Name Length")

-- connected - fields
ecf.projname = ProtoField.string("epson_control.proj_name", "Projector Name")
ecf.projstate = ProtoField.uint8("epson_control.proj_state", "Projector State")

-- clientinfo - fields
ecf.usekeyword = ProtoField.bool("epson_control.use_keyword", "Use Keyword")
ecf.displaytype = ProtoField.uint8("epson_control.display_type", "Display Type")


-- connection record
ecf.uniqinfo = ProtoField.ether("epson_control.uniq_info", "Uniq Info")
ecf.keyword = ProtoField.string("epson_control.keyword", "Keyword")
ecf.beamerip = ProtoField.ipv4("epson_control.beamerip", "Beamer IP")
		
CMD_EASYSEARCH		= 1
CMD_IPSEARCH		= 2
CMD_CLIENTINFO		= 3
CMD_REQCONNECT		= 4
CMD_CONNECTED		= 5
CMD_REQRESTART		= 6
CMD_FINISHRESTART	= 7
CMD_DISCONCLIENT	= 8
CMD_INTERRUPT		= 9
CMD_KEEPALIVE		= 10

CMD_SENDREQUESTS	= 12
CMD_CLIENTERROR		= 13
CMD_RESENDFULLSCRID   	= 14
CMD_DISPLAYWAIT		= 15
CMD_SENDKEY          	= 16

local cmdname = {
	[CMD_EASYSEARCH]	= "easysearch",
	[CMD_IPSEARCH]		= "ipsearch",
	[CMD_CLIENTINFO] 	= "clientinfo",
	[CMD_REQCONNECT]	= "reqconnect",
	[CMD_CONNECTED]		= "connected",
	[CMD_REQRESTART]	= "reqrestart",
	[CMD_FINISHRESTART]	= "finishrestart",
	[CMD_DISCONCLIENT]	= "disconclient",
	[CMD_INTERRUPT]		= "interrupt",
	[CMD_KEEPALIVE]		= "keepalive",
	[CMD_SENDREQUESTS]	= "sendrequests",
	[CMD_CLIENTERROR]	= "clienterror",
	[CMD_RESENDFULLSCRID]	= "resendfullscrid",
	[CMD_DISPLAYWAIT]	= "displaywait",
	[CMD_SENDKEY]		= "sendkey",

	[21]                    = "extra clientinfo?"
}

function epson_control_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "EPSON CONTROL"
	local subtree = tree:add(epson_video_proto, buffer(), "Epson Control Protocol Data")

	subtree:add(ecf.magic,   buffer(0, 4))
	subtree:add(ecf.version, buffer(4, 4))

	subtree:add(ecf.clientip, buffer(8,4))

	local cmdtree = subtree:add_le(ecf.cmdid, buffer(12, 4))
	local commandid = buffer(12,4):le_uint()
	cmdtree:append_text(string.format(" (%s)", (cmdname[commandid] or "unknown")))

	subtree:add_le(ecf.datasize, buffer(16, 4)):append_text(" bytes")
	local datasize = buffer(16,4):le_uint()
	if datasize <= 0 then
		return
	end

	local econ_header_size = 20
	-- FIXME: not always: e.g cmdid=21
	local record_count = buffer(20, 1):uint()
	local rectree = subtree:add(ecf.record_count, buffer(20, 1))

	if commandid == CMD_CLIENTINFO then
		cmdtree:add(ecf.projname, buffer(24, 32))
		local state = { [1] = "no use", [2] = "using", [3] = "app use" }
		cmdtree:add(ecf.projstate, buffer(56, 1))
			:append_text(" (" .. (state[buffer(56,1):uint()] or "") .. ")")
		cmdtree:add(ecf.usekeyword, buffer(57, 1))
		cmdtree:add(ecf.displaytype, buffer(58, 1))

	elseif commandid == CMD_REQCONNECT then
		cmdtree:add(ecf.encryption,  buffer(24, 1))
		cmdtree:add(ecf.encpassword, buffer(25, 8))
		cmdtree:add(ecf.subnet,      buffer(33, 4))
		cmdtree:add(ecf.gateway,     buffer(37, 4))

		-- 3 byte alignment
		local vnesoffset = 37 + 4 + 3
		local vnestree = cmdtree:add("VNES init")
		vnestree:add_le(ecf.width,  buffer(vnesoffset,   2))
		vnestree:add_le(ecf.height, buffer(vnesoffset+2, 2))

		local fmtoff = vnesoffset + 4
		vnestree:add(ecf.bpp,       buffer(fmtoff,   1))
		vnestree:add(ecf.depth,     buffer(fmtoff+1, 1))
		vnestree:add(ecf.bigendian, buffer(fmtoff+2, 1))
		vnestree:add(ecf.truecolor, buffer(fmtoff+3, 1))

		vnestree:add_le(ecf.redmax,   buffer(fmtoff+4, 2))
		vnestree:add_le(ecf.greenmax, buffer(fmtoff+6, 2))
		vnestree:add_le(ecf.bluemax,  buffer(fmtoff+8, 2))

		vnestree:add(ecf.redshift,   buffer(fmtoff+10, 1))
		vnestree:add(ecf.greenshift, buffer(fmtoff+11, 1))
		vnestree:add(ecf.blueshift,  buffer(fmtoff+12, 1))

		local pad = 3
		vnestree:add_le(ecf.namelength, buffer(fmtoff+16, 4))
	elseif commandid == CMD_CONNECTED then
		cmdtree:add(ecf.projname, buffer(24, 32))
		-- state: 1 == no_use, 2 == using, 3 == app_using
		local state = { [1] = "no use", [2] = "using", [3] = "app use" }
		cmdtree:add(ecf.projstate, buffer(56, 1))
			:append_text(" (" .. (state[buffer(56,1):uint()] or "") .. ")")
	elseif commandid == 21 then
		cmdtree:add(ecf.uniqinfo, buffer(20, 6))

		-- FIXME: verify all
		cmdtree:add_le(ecf.width,  buffer(20+46,   2)):append_text(" ?")
		cmdtree:add_le(ecf.height, buffer(20+46+2, 2)):append_text(" ?")


	elseif commandid == 22 then
		cmdtree:add(buffer(20+4, 2),   "x?: " .. buffer(20+4,2):le_uint())
		cmdtree:add(buffer(20+4+2, 2), "y?: " .. buffer(20+4+2,2):le_uint())
		cmdtree:add_le(ecf.width, buffer(20+8, 2))
		cmdtree:add_le(ecf.height, buffer(20+8+2, 2))
	elseif commandid == 25 then
		cmdtree:add(buffer(20+4,   4), "unknown1: " .. buffer(20+4,4):le_uint())
		cmdtree:add(buffer(20+4+4, 4), "unknown2: " .. buffer(20+4+4,4):le_uint())
	end

	local econ_command_size = 48

	if commandid ~= CMD_CLIENTINFO and
	   commandid ~= CMD_REQCONNECT and
	   commandid ~= CMD_CONNECTED and
	   commandid ~= CMD_CLIENTERROR and
	   commandid ~= CMD_RESENDFULLSCRID and
	   commandid ~= CMD_SENDKEY then
		econ_command_size = 4
	end

	local recoffset = econ_header_size + econ_command_size

	if record_count == 1 then
		rectree:add(ecf.uniqinfo, buffer(recoffset,    6))
		rectree:add(ecf.keyword,  buffer(recoffset+6, 16))
		rectree:add(ecf.beamerip, buffer(recoffset+22, 4))
	end

end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(3620, epson_control_proto)
tcp_table:add(3621, epson_video_proto)

udp_table = DissectorTable.get("udp.port")
udp_table:add(3620, epson_control_proto)
