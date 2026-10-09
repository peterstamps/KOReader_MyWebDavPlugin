--[[--
MyWebDav — WebDAV server plugin for KOReader.

Features:
- Non-blocking server loop (UIManager:scheduleIn)
- Blocking dialog with Stop button
- Live countdown timer notification
- Runtime accepts seconds (600) or MM:SS (12:30)
- Wi-Fi check before start
- Manual IP mode (optional)
- Basic authentication (RFC 7617)
- HTTP Range support for downloads
- Recursive DELETE
- LOCK / UNLOCK stubs

@module MyWebDav
--]]
--

local Dispatcher = require("dispatcher")
local InfoMessage = require("ui/widget/infomessage")
local Notification = require("ui/widget/notification")
local QRMessage = require("ui/widget/qrmessage")
local ButtonDialog = require("ui/widget/buttondialog")
local UIManager = require("ui/uimanager")
local Device = require("device")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local _ = require("gettext")
local LuaSettings = require("luasettings")
local DataStorage = require("datastorage")
local socket = require("socket")
local io = require("io")
local os = require("os")
local string = require("string")
local mime = require("mime")
local lfs = require("libs/libkoreader-lfs")

-- Load reader settings if not already available
if G_reader_settings == nil then
	G_reader_settings = require("luasettings"):open(DataStorage:getDataDir() .. "/settings.reader.lua")
end

-- Default home directory (used by KOReader, not directly by this plugin)
if G_reader_settings:hasNot("home_dir") then
	G_reader_settings:saveSetting("home_dir", ".")
end

-- Root directory exposed over WebDAV. Overridden by saved settings below.
local root_dir = "/mnt/ext1"

-- ---------------------------------------------------------------------------
-- Global server state
-- ---------------------------------------------------------------------------

server_running = false
server_socket = nil
server_stop_time = 0
webdav_forced_shutdown = false
webdav_stop_reason = "timer" -- "timer" | "button" | "request"
active_transfers = 0
server_dialog = nil

-- True = use user-supplied IP, false = use auto-detected
user_ip_enabled = false

-- Reference to KOReader UI (set in MyWebDav:init)
MyWebDav_ui = nil

-- Returns true if Wi-Fi is on. Uses NetworkMgr when available, otherwise
-- falls back to checking whether a non-loopback IP was detected.
local function is_wifi_on()
	local ok_mgr, NetworkMgr = pcall(require, "ui/network/manager")
	if ok_mgr and NetworkMgr and NetworkMgr.isWifiOn then
		local ok, res = pcall(function()
			return NetworkMgr:isWifiOn()
		end)
		if ok and res ~= nil then
			return res
		end
	end
	return real_ip ~= "127.0.0.1" and real_ip ~= "0.0.0.0"
end

-- Returns true if battery charge is below the given threshold (percent).
-- Returns nil if the power device is not available.
local function is_battery_low(threshold)
	threshold = threshold or 20
	local ok, powerd = pcall(function()
		return Device:getPowerDevice()
	end)
	if not ok or not powerd then
		return nil
	end
	local ok_cap, capacity = pcall(function()
		return powerd:getCapacity()
	end)
	if not ok_cap or not capacity then
		return nil
	end
	return capacity < threshold, capacity
end

-- ---------------------------------------------------------------------------
-- Minimal HTML wrappers for browser responses
-- ---------------------------------------------------------------------------

local function html_header(title)
	return [[
            <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>]] .. title .. [[</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f2f2f2; }
        .container { max-width: 100%; margin: auto; padding: 10px; background-color: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; }
    </style>
</head>
<body>
    <div class="container">
    <h1>]] .. title .. [[</h1>
    ]]
end

local function html_footer()
	return [[
    </div>
    </body>
    </html>
    ]]
end

-- ---------------------------------------------------------------------------
-- Basic authentication (RFC 7617)
-- ---------------------------------------------------------------------------

local function base64encode(username, password)
	local credentials = username .. ":" .. password
	return "Authorization: Basic " .. mime.b64(credentials)
end

local function check_authentication(headers)
	local auth_header = headers["authorization"]
	if not auth_header then
		return false
	end
	local auth_type, encoded_credentials = string.match(auth_header, "^(%S+)%s+(%S+)$")
	if auth_type ~= "Basic" then
		return false
	end
	local decoded_credentials = mime.unb64(encoded_credentials)
	local user, pass = string.match(decoded_credentials, "(%S+):(%S+)")

	local webdav_parms = G_reader_settings:readSetting("webdav_parms")
	local webdav_username, webdav_password
	if webdav_parms then
		webdav_username = tostring(webdav_parms["username"])
		webdav_password = tostring(webdav_parms["password"])
	end

	if tostring(user) == tostring(webdav_username) and tostring(pass) == tostring(webdav_password) then
		auth_header_resp = base64encode(user, pass)
		return true
	end
	auth_header_resp = ""
	return false
end

-- Escape ampersands for XML payloads
local function escape_ampersands(xml_str)
	xml_str = xml_str:gsub("([^<>&]*)&(.-)([^<>&]*)", function(before, mid, after)
		if not mid:match("^[a-zA-Z#][a-zA-Z0-9]*$") then
			return before .. "&amp;" .. after
		end
		return before .. "&" .. mid .. after
	end)
	return xml_str
end

local function escape_spaces_in_path(path)
	return path:gsub(" ", "%%20")
end

-- URL decode
local function url_decode(str)
    str = str:gsub("+", " ")
    str = str:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return str
end


-- Path resolve and sanitize
local function resolve_path(url_path)
    local decoded = url_decode(url_path or ""):gsub("\\", "/"):match("^[^%?]*")
    decoded = decoded:gsub("/+", "/")
    if decoded:find("%.%.") or decoded:find("\0") then return nil, "Invalid path" end
    return decoded
end

local function isAnyPartHidden(path)
    -- Split the path into components (directories and filenames)
    for part in path:gmatch("[^/\\]+") do
        -- Check if any part starts with a dot (hidden file/folder)
        if part:sub(1, 1) == "." then
            return true  -- Found a hidden part in the path
        end
    end
    return false  -- No hidden parts in the path
end

-- Function to get WebDAV-like properties for a file
local function get_webdav_properties(file_path)
    -- Get file attributes using lfs.attributes
    local attributes = lfs.attributes(file_path)  
    if attributes then
        -- Get file size (similar to getcontentlength)
        local file_size = attributes.size
        -- Get last modified date (similar to getlastmodified)
        local last_modified = os.date("%a, %d %b %Y %H:%M:%S GMT", attributes.modification)
        -- Return the properties
        return {
            getcontentlength = file_size,
            getlastmodified = last_modified
        }
    else
        -- Return nil if the file doesn't exist
        return nil
    end
end

-- Create a simple  response with proper headers, body and auth_header_resp
local function webdav_send_response(client, status, content_type, xml, auth_header_resp)
    local response = "HTTP/1.1 " .. status .. "\r\n"
    response = response .. "Content-Type: " .. content_type .. ';charset: "utf-8"\r\n'    
    -- If a authorization header is provided, include it in the response headers
    if auth_header_resp then
        response = response .. auth_header_resp .. "\r\n" 
    end
    response = response .. "Accept-Encoding: gzip, deflate\r\n"
    response = response .. "Connection: Close\r\n"
    --response = response .. "Depth: 10\r\n"
    response = response .. "Apply-To-Redirect-Ref: T\r\n"
    if xml then
        response = response .. "Content-Length: " .. #escape_ampersands(xml) .. "\r\n"
	end
    response = response .. "\r\n" -- End of headers
    if xml then
		response = response .. escape_ampersands(xml) -- add the body content
	end
    client:send(response)
end

-- Helper function to construct root and virtual paths
local function get_root_virt_paths(path)
    local file_path = path
    local virtual_dir = 'http://' .. webdav_parms_ip_address .. ":" ..  tostring(port)
    if file_path then
		physical_path = root_dir  .. file_path
		virtual_path =  virtual_dir .. file_path
	else
		physical_path = root_dir
		virtual_path =  virtual_dir 
	end   
	if string.len(physical_path) == 0  then
	  physical_path = '.'
	end
    return physical_path, virt_path, virtual_dir
end

-- Function to handle PROPFIND (listing files)
local function handle_propfind(client_socket, path)
	local physical_path, virt_path, virtual_dir = get_root_virt_paths(path)
	local function check_file_or_directory(X)
		if not X then 
			return nil, "No file or directory specified"
		end
		local attr = lfs.attributes(X)		
		if not attr then
			return nil, "No such file or directory"
		end
		if attr.mode == "directory" then
			return "directory"
		elseif attr.mode == "file" then
			return "file"
		else
			return "unknown"
		end
	end	
	result, check_err = check_file_or_directory(physical_path)
	--print(result, check_err)
	if check_err then 
		return client_socket:send("HTTP/1.1 404 Not Found\r\n\r\n")   -- cannot use webdav_send_response here !
	end	
	--[[	if result then
		print("variable dir contains a " .. result)
	else
		print("Error: " .. check_err)
	end
	-]]
    local xml = '<?xml version="1.0" encoding="utf-8"?>'
    xml = xml .. '<D:multistatus xmlns:D="DAV:"  xmlns:Z="urn:schemas-microsoft-com:">'
    --  this part is required for Nautilus and other File explorting tools that support WebDav
	local href_file = virtual_dir .. string.sub(physical_path, #root_dir + 1, #physical_path)
	local path, display_name_file, extension = string.match(physical_path, "(.-)([^\\/]-%.?([^%.\\/]*))$")	
    local xml_tmpl = [[<D:response><D:href>%s</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>%s</D:displayname></D:prop></D:propstat></D:response>]] 				
	xml = xml .. string.format(xml_tmpl,  escape_spaces_in_path(href_file), escape_spaces_in_path(display_name_file) )      
	local files = {}
	if result ==  'directory'  then
		for file in lfs.dir(physical_path) do	
		   --print ("physical_path=", physical_path, ' file=', file)
		   if not (file:lower():match("%." .. 'sdr' .. "$") or  isAnyPartHidden(file) ) then -- skip directories with extention .sdr and hidden ones	
				local full_path = physical_path .. file	
				local properties = get_webdav_properties(full_path)
				if file ~= "." and file ~= ".." then
					if lfs.attributes(full_path, "mode") == "file" then
						local href_file = virtual_dir .. string.sub(full_path, #root_dir + 1, #full_path)
						local path, display_name_file, extension = string.match(physical_path, "(.-)([^\\/]-%.?([^%.\\/]*))$")	
						--print( path, display_name_file, extension)	
						xml_tmpl = [[<D:response><D:href>%s</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:resourcetype/><D:displayname>%s</D:displayname><D:getcontentlength>%s</D:getcontentlength><D:getlastmodified>%s</D:getlastmodified></D:prop></D:propstat></D:response>]] 				
						xml = xml .. string.format(xml_tmpl, escape_spaces_in_path(href_file), escape_spaces_in_path(display_name_file), properties.getcontentlength, properties.getlastmodified )			
					end
					if lfs.attributes(full_path, "mode") == "directory" then
							local href_file = virtual_dir .. string.sub(full_path, #root_dir + 1, #full_path)
							local path, display_name_file, extension = string.match(physical_path, "(.-)([^\\/]-%.?([^%.\\/]*))$")	
							--print( path, display_name_file, extension)	
							xml_tmpl = [[<D:response><D:href>%s</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>%s</D:displayname><D:getlastmodified>%s</D:getlastmodified><D:getcontenttype>application/octet-stream</D:getcontenttype></D:prop></D:propstat></D:response>]] 				
							xml = xml .. string.format(xml_tmpl, escape_spaces_in_path(href_file), escape_spaces_in_path(display_name_file), properties.getlastmodified)	
					end
				end
			end
		 end
	elseif result ==  'file'  then
		if not (physical_path:lower():match("%." .. 'sdr' .. "$") or  isAnyPartHidden(physical_path) ) then -- skip directories with extention .sdr and hidden ones
			local properties = get_webdav_properties(physical_path)
			local href_file = virtual_dir .. string.sub(physical_path, #root_dir + 1, #physical_path)
			local path, display_name_file, extension = string.match(physical_path, "(.-)([^\\/]-%.?([^%.\\/]*))$")	
			xml_tmpl = [[<D:response><D:href>%s</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:displayname>%s</D:displayname><D:getcontentlength>%s</D:getcontentlength><D:getlastmodified>%s</D:getlastmodified><D:getcontenttype>application/octet-stream</D:getcontenttype></D:prop></D:propstat></D:response>]] 				
			xml = xml .. string.format(xml_tmpl, escape_spaces_in_path(href_file), escape_spaces_in_path(display_name_file), properties.getcontentlength, properties.getlastmodified )	
		end
	end
    xml = xml .. "</D:multistatus>"
    -- print (xml)
	--local file = io.open("/home/peter/Downloads/xmlresponse.xml", "wb")
	-- Process the complete data
	-- Write data to the file
	--file:write(escape_ampersands(xml))
	--file:close()	 
	webdav_send_response(client_socket, "207 Multi-Status", "application/xml", xml, auth_header_resp)  
end



-- MKCOL: create directory
local function handle_mkcol(client_socket, path)
	local physical_path = get_root_virt_paths(path)
	local ok = lfs.mkdir(physical_path)
	if ok then
		webdav_send_response(client_socket, "201 Created", "application/xml", nil, auth_header_resp)
	else
		webdav_send_response(client_socket, "400 Bad Request", "application/xml", nil, auth_header_resp)
	end
end

-- COPY: copy a file
local function handle_copy(client_socket, path, headers)
	local _, _, virtual_dir = get_root_virt_paths(path)
	local destination = headers["destination"]
	if not destination then
		return webdav_send_response(client_socket, "400 Bad Request", "application/xml", nil, auth_header_resp)
	end

	local src_path = url_decode(root_dir .. path)
	local dst_path = url_decode(root_dir .. string.sub(destination, #virtual_dir + 1, #destination))

	local src = io.open(src_path, "rb")
	if not src then
		return webdav_send_response(client_socket, "404 Not Found", "application/xml", nil, auth_header_resp)
	end
	local dst = io.open(dst_path, "wb")
	if not dst then
		src:close()
		return webdav_send_response(
			client_socket,
			"500 Internal Server Error",
			"application/xml",
			nil,
			auth_header_resp
		)
	end

	while true do
		local chunk = src:read(16384)
		if not chunk then
			break
		end
		dst:write(chunk)
	end
	src:close()
	dst:close()

	webdav_send_response(client_socket, "201 Created", "application/xml", nil, auth_header_resp)
end

-- MOVE: rename or move a file
local function handle_move(client_socket, path, headers)
	local _, _, virtual_dir = get_root_virt_paths(path)
	local destination = headers["destination"]
	if not destination then
		return webdav_send_response(client_socket, "400 Bad Request", "application/xml", nil, auth_header_resp)
	end

	local src_path = root_dir .. path
	local dst_path = root_dir .. string.sub(destination, #virtual_dir + 1, #destination)

	local success = os.rename(src_path, dst_path)
	if success then
		webdav_send_response(client_socket, "200 OK", "application/xml", nil, auth_header_resp)
	else
		webdav_send_response(client_socket, "400 Bad Request", "application/xml", nil, auth_header_resp)
	end
end

-- Recursively remove a file or directory
local function remove_recursive(target)
	local mode = lfs.attributes(target, "mode")
	if mode == "file" then
		return os.remove(target) ~= nil
	elseif mode == "directory" then
		for entry in lfs.dir(target) do
			if entry ~= "." and entry ~= ".." then
				remove_recursive(target .. "/" .. entry)
			end
		end
		return lfs.rmdir(target)
	end
	return false
end

-- DELETE: remove a file or directory (recursively)
local function handle_delete(client_socket, path)
	local safe = resolve_path(path)
	if not safe then
		return webdav_send_response(client_socket, "400 Bad Request", "application/xml", nil, auth_header_resp)
	end
	local file_path = safe:sub(2)
	local full_path = root_dir .. "/" .. file_path
	if not lfs.attributes(full_path) then
		return webdav_send_response(client_socket, "404 Not Found", "application/xml", nil, auth_header_resp)
	end
	if remove_recursive(full_path) then
		webdav_send_response(client_socket, "204 No Content", "application/xml", nil, auth_header_resp)
	else
		webdav_send_response(client_socket, "403 Forbidden", "application/xml", nil, auth_header_resp)
	end
end

-- Stream a file to the client (supports HTTP Range requests)
local function webdav_download_file(file_name, client_socket, headers)
	local file_path = root_dir .. file_name
	local mode = lfs.attributes(file_path, "mode")
	if mode ~= "file" then
		local html = html_header("Error") .. [[<p>File not found: ]] .. file_path .. [[ </p>]] .. html_footer()
		return webdav_send_response(client_socket, "200 OK", "text/html", html, auth_header_resp)
	end

	local resolved = resolve_path(file_path)
	local file = io.open(resolved, "rb")
	if not file then
		return client_socket:send("HTTP/1.1 404 Not Found\r\n\r\n")
	end

	local properties = get_webdav_properties(resolved)
	local total_size = file:seek("end")

	-- Parse Range header if present
	local range_start, range_end
	local range_header = headers and headers["range"]
	if range_header then
		local s, e = range_header:match("bytes=(%d*)-(%d*)")
		if s then
			range_start = (s ~= "") and tonumber(s) or nil
			range_end = (e ~= "") and tonumber(e) or nil
		end
	end

	local status, start_pos, end_pos
	if range_start or range_end then
		if not range_start then
			range_start = math.max(0, total_size - (range_end or 0))
			range_end = total_size - 1
		else
			range_end = range_end or (total_size - 1)
			if range_end >= total_size then
				range_end = total_size - 1
			end
		end
		if range_start > range_end or range_start >= total_size then
			file:close()
			local response = "HTTP/1.1 416 Range Not Satisfiable\r\n"
				.. "Content-Range: bytes */"
				.. tostring(total_size)
				.. "\r\n"
				.. "\r\n"
			return client_socket:send(response)
		end
		status = "206 Partial Content"
		start_pos = range_start
		end_pos = range_end
	else
		status = "200 OK"
		start_pos = 0
		end_pos = total_size - 1
	end

	local length = end_pos - start_pos + 1
	file:seek("set", start_pos)

	local response = "HTTP/1.1 " .. status .. "\r\n"
	response = response .. "Content-Type: application/octet-stream\r\n"
	response = response .. "Accept-Ranges: bytes\r\n"
	response = response .. "Last-Modified: " .. properties.getlastmodified .. "\r\n"
	response = response .. "Date: " .. os.date("%a, %d %b %Y %H:%M:%S GMT") .. "\r\n"
	response = response .. "Server: MyWebDav\r\n"
	response = response .. "Content-Length: " .. tostring(length) .. "\r\n"
	if status == "206 Partial Content" then
		response = response
			.. "Content-Range: bytes "
			.. tostring(start_pos)
			.. "-"
			.. tostring(end_pos)
			.. "/"
			.. tostring(total_size)
			.. "\r\n"
	end
	response = response .. "\r\n"
	client_socket:send(response)

	local remaining = length
	while remaining > 0 do
		local chunk_size = math.min(16384, remaining)
		local chunk = file:read(chunk_size)
		if not chunk then
			break
		end
		client_socket:send(chunk)
		remaining = remaining - #chunk
	end
	file:close()
end

-- Dispatch a single HTTP request
local function handle_request_inner(client_socket)
	local request = client_socket:receive("*l")
	if not request then
		return
	end

	local method, path = request:match("([A-Z]+) (/[^ ]*)")

	local headers = {}
	while true do
		local line = client_socket:receive("*l")
		if not line or line == "" then
			break
		end
		local k, v = line:match("^(.-): (.+)$")
		if k and v then
			headers[k:lower()] = v
		end
	end

	if method == "OPTIONS" then
		local allowed = "PUT, GET, COPY, MOVE, DELETE, OPTIONS, PROPFIND, MKCOL, HEAD, LOCK, UNLOCK"
		local response = "HTTP/1.1 200 OK\r\n"
			.. "Content-Type: text/plain\r\n"
			.. "Allow: "
			.. allowed
			.. "\r\n"
			.. "DAV: 1\r\n"
			.. "Content-Length: 0\r\n"
			.. "\r\n"
		client_socket:send(response)
		return
	end

	if not check_authentication(headers) then
		client_socket:send('HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Default realm"\r\n\r\n')
		return
	end

	-- Total Commander and some clients expect 100 Continue before sending
	-- large PUT bodies. Without this they abandon the request immediately.
	if headers["expect"] and headers["expect"]:lower() == "100-continue" then
		client_socket:send("HTTP/1.1 100 Continue\r\n\r\n")
	end

	if path then
		path = url_decode(path)
	end

	if path == "/stop" then
		local html = html_header("WebDAV server") .. [[<p>Server is shutting down. Goodbye!</p>]] .. html_footer()
		webdav_send_response(client_socket, "200 OK", "text/html", html, auth_header_resp)
		webdav_forced_shutdown = true
		webdav_stop_reason = "request"
		return
	end

	if method == "PROPFIND" then
		handle_propfind(client_socket, path, headers)
	elseif method == "MKCOL" then
		handle_mkcol(client_socket, path)
	elseif method == "COPY" then
		handle_copy(client_socket, path, headers)
	elseif method == "MOVE" then
		handle_move(client_socket, path, headers)
	elseif method == "DELETE" then
		handle_delete(client_socket, path)
	elseif method == "GET" then
		if path then
			webdav_download_file(path, client_socket, headers)
		else
			local html = html_header("Bad request.") .. [[<p>Invalid file request</p>]] .. html_footer()
			webdav_send_response(client_socket, "400 Bad Request", "text/html", html, auth_header_resp)
		end
	elseif method == "HEAD" then
		local physical_path = root_dir .. (path or "/")
		local mode = lfs.attributes(physical_path, "mode")
		if not mode then
			client_socket:send("HTTP/1.1 404 Not Found\r\n\r\n")
		elseif mode == "file" then
			local properties = get_webdav_properties(physical_path)
			local response = "HTTP/1.1 200 OK\r\n"
				.. "Content-Type: application/octet-stream\r\n"
				.. "Last-Modified: "
				.. properties.getlastmodified
				.. "\r\n"
				.. "Content-Length: "
				.. tostring(properties.getcontentlength)
				.. "\r\n"
				.. "\r\n"
			client_socket:send(response)
		else
			client_socket:send("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		end
	elseif method == "PUT" then
		local file_path = path
		local _, file_to_upload = string.match(file_path, "(.-)([^\\/]-%.?([^%.\\/]*))$")

		if file_to_upload and file_to_upload:lower() == "stop.txt" then
			webdav_send_response(client_socket, "201 Created", "application/xml", nil, auth_header_resp)
			webdav_forced_shutdown = true
			webdav_stop_reason = "request"
			return
		end

		local full_filename = root_dir .. file_path
		if not full_filename then
			client_socket:send("HTTP/1.1 500 Internal Server Error\r\n\r\n")
			return
		end

		local length = tonumber(headers["content-length"])
		if not length then
			return webdav_send_response(client_socket, "411 Length Required", "application/xml", nil, auth_header_resp)
		end

		local file = io.open(full_filename, "wb")
		if not file then
			return webdav_send_response(
				client_socket,
				"500 Internal Server Error",
				"application/xml",
				nil,
				auth_header_resp
			)
		end

		local received = 0
		local last_flush = 0
		while received < length do
			local chunk = client_socket:receive(math.min(16384, length - received))
			if not chunk then
				break
			end
			file:write(chunk)
			received = received + #chunk
			-- Flush every 2 MB so the final close() is not a long stall
			if received - last_flush >= 2 * 1024 * 1024 then
				file:flush()
				last_flush = received
			end
		end
		file:flush()
		file:close()

		if received < length then
			os.remove(full_filename)
			return webdav_send_response(
				client_socket,
				"500 Internal Server Error",
				"application/xml",
				nil,
				auth_header_resp
			)
		end

		webdav_send_response(client_socket, "201 Created", "application/xml", nil, auth_header_resp)
	elseif method == "LOCK" then
		-- Consume the request body if present (we ignore it)
		local length = tonumber(headers["content-length"])
		if length and length > 0 then
			local received = 0
			while received < length do
				local chunk = client_socket:receive(math.min(4096, length - received))
				if not chunk then
					break
				end
				received = received + #chunk
			end
		end
		local lock_token = "opaquelocktoken:" .. tostring(os.time()) .. "-" .. tostring(math.random(100000, 999999))
		local xml_body = '<?xml version="1.0" encoding="utf-8"?>'
			.. '<D:prop xmlns:D="DAV:">'
			.. "<D:lockdiscovery>"
			.. "<D:activelock>"
			.. "<D:locktype><D:write/></D:locktype>"
			.. "<D:lockscope><D:exclusive/></D:lockscope>"
			.. "<D:depth>infinity</D:depth>"
			.. "<D:timeout>Second-3600</D:timeout>"
			.. "<D:locktoken><D:href>"
			.. lock_token
			.. "</D:href></D:locktoken>"
			.. "</D:activelock>"
			.. "</D:lockdiscovery>"
			.. "</D:prop>"
		local response = "HTTP/1.1 200 OK\r\n"
			.. 'Content-Type: application/xml; charset="utf-8"\r\n'
			.. "Lock-Token: <"
			.. lock_token
			.. ">\r\n"
			.. "Content-Length: "
			.. #xml_body
			.. "\r\n"
			.. "\r\n"
			.. xml_body
		client_socket:send(response)
		return
	elseif method == "UNLOCK" then
		webdav_send_response(client_socket, "204 No Content", "application/xml", nil, auth_header_resp)
		return
	else
		webdav_send_response(client_socket, "405 Method Not Allowed", "application/xml", nil, auth_header_resp)
	end
end

-- Wrap the handler in pcall and count active transfers
local function handle_request(client_socket)
	active_transfers = active_transfers + 1
	local ok, err = pcall(handle_request_inner, client_socket)
	active_transfers = active_transfers - 1
	if not ok then
		print("WebDAV handler error:", err)
	end
	if client_socket then
		pcall(function()
			client_socket:close()
		end)
	end
end

-- Format seconds as MM:SS
local function format_time(total_seconds)
	total_seconds = math.max(0, math.floor(tonumber(total_seconds) or 0))
	local m = math.floor(total_seconds / 60)
	local s = total_seconds % 60
	return string.format("%02d:%02d", m, s)
end

-- Parse runtime input: "750" (seconds) or "12:30" (12 min 30 sec)
local function parse_runtime(input)
	local str = tostring(input or ""):gsub("%s", "")
	if str == "" then
		return nil
	end
	local m, s = str:match("^(%d+):(%d+)$")
	if m and s then
		return tonumber(m) * 60 + tonumber(s)
	end
	return tonumber(str)
end

-- Forward declarations so the functions can call each other
local show_server_dialog
local stop_server

-- Blocking dialog with server info and Stop button
function show_server_dialog()
	local title = _("WebDAV server is running")
		.. "\n\n"
		.. _("Login: ")
		.. "http://"
		.. tostring(webdav_parms_ip_address)
		.. ":"
		.. tostring(port)
		.. "\n"
		.. _("User: ")
		.. tostring(username)

	local dialog = ButtonDialog:new({
		title = title,
		title_align = "center",
		tap_closes_dialog = false,
		buttons = {
			{
				{
					text = _("Stop WebDAV server"),
					callback = function()
						if active_transfers > 0 then
							UIManager:show(Notification:new({
								text = _("Transfer in progress, please wait"),
								timeout = 3,
							}))
						else
							webdav_forced_shutdown = true
							webdav_stop_reason = "button"
							stop_server("button")
						end
					end,
				},
			},
		},
	})

	dialog.onCloseWidget = function()
		if server_dialog == dialog then
			server_dialog = nil
		end
	end

	UIManager:show(dialog)
	return dialog
end

-- Live countdown timer (small notification at the top)
local timer_notification = nil

local function remove_timer_notification()
	if timer_notification then
		UIManager:close(timer_notification)
		timer_notification = nil
	end
end

local function refresh_timer_notification()
	if not server_running then
		remove_timer_notification()
		return
	end

	local remaining = (server_stop_time or 0) - os.time()
	if remaining < 0 then
		remaining = 0
	end
	local text = _("Auto-stop in: ") .. format_time(remaining)

	if timer_notification and timer_notification.setText then
		pcall(function()
			timer_notification:setText(text)
		end)
	else
		remove_timer_notification()
		timer_notification = Notification:new({
			text = text,
			timeout = 1,
		})
		UIManager:show(timer_notification)
	end
end

-- Periodic ticker: closes the KOReader menu, restores the dialog if it
-- disappeared, and updates the countdown.
local function update_dialog_countdown()
	if not server_running or webdav_forced_shutdown then
		remove_timer_notification()
		return
	end

	if MyWebDav_ui and MyWebDav_ui.menu then
		pcall(function()
			MyWebDav_ui.menu:closeMenu()
		end)
	end

	if not server_dialog then
		server_dialog = show_server_dialog()
	end

	refresh_timer_notification()
	UIManager:scheduleIn(1, update_dialog_countdown)
end

-- Stop
function stop_server(reason)
	if not server_running and not server_socket and not server_dialog then
		return
	end

	server_running = false

	if server_socket then
		pcall(function()
			server_socket:close()
		end)
		server_socket = nil
	end

	if server_dialog then
		local d = server_dialog
		server_dialog = nil
		pcall(function()
			UIManager:close(d, "full")
		end)
	end

	remove_timer_notification()

	local time = os.date("*t")
	print("Stopped at: ", os.date("%A, %m %B %Y | "), ("%02d:%02d:%02d"):format(time.hour, time.min, time.sec))
	print("WebDAV server has been stopped, reason: " .. tostring(reason))

	local msg
	if reason == "timer" then
		msg = _("WebDAV server stopped: time expired")
	elseif reason == "request" then
		msg = _("WebDAV server stopped by remote client")
	else
		msg = _("WebDAV server stopped")
	end

	UIManager:show(Notification:new({
		text = msg,
		timeout = 3,
	}))
end

-- Non-blocking server loop, runs every 50 ms
local function server_tick()
	if not server_running then
		return
	end

	if webdav_forced_shutdown then
		local reason = webdav_stop_reason or "button"
		webdav_forced_shutdown = false
		webdav_stop_reason = "timer"
		stop_server(reason)
		return
	end

	if os.time() >= server_stop_time then
		stop_server("timer")
		return
	end

	if server_socket then
		local client_socket = server_socket:accept()
		if client_socket then
			client_socket:settimeout(240)
			handle_request(client_socket)
		end
	end

	if webdav_forced_shutdown then
		local reason = webdav_stop_reason or "request"
		webdav_forced_shutdown = false
		webdav_stop_reason = "timer"
		stop_server(reason)
		return
	end

	UIManager:scheduleIn(0.05, server_tick)
end

-- Start
local function start_server()
	if server_running then
		print("Server is already running.")
		return
	end

	if user_ip_enabled then
		local saved = G_reader_settings:readSetting("webdav_parms") or {}
		webdav_parms_ip_address = tostring(saved["ip_address"] or "127.0.0.1")
	else
		webdav_check_socket()
		if real_ip and real_ip ~= "127.0.0.1" and real_ip ~= "0.0.0.0" then
			webdav_parms_ip_address = tostring(real_ip)
		end
		local saved = G_reader_settings:readSetting("webdav_parms") or {}
		saved.ip_address = tostring(webdav_parms_ip_address)
		G_reader_settings:saveSetting("webdav_parms", saved)
	end

	local bind_addr = "*"
	if user_ip_enabled and webdav_parms_ip_address and webdav_parms_ip_address ~= "" then
		bind_addr = tostring(webdav_parms_ip_address)
	end

	if Device:isKindle() then
		os.execute(
			string.format(
				"%s %s %s",
				"iptables -A INPUT -p tcp --dport",
				port,
				"-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
			)
		)
		os.execute(
			string.format(
				"%s %s %s",
				"iptables -A OUTPUT -p tcp --sport",
				port,
				"-m conntrack --ctstate ESTABLISHED -j ACCEPT"
			)
		)
	end

	local ok, sock_or_err = pcall(socket.bind, bind_addr, port)
	if not ok or not sock_or_err then
		UIManager:show(Notification:new({
			text = user_ip_enabled and _("Failed to bind to the manual IP. Check the address.")
				or _("Failed to start server: port busy?"),
			timeout = 4,
		}))
		return
	end

	server_socket = sock_or_err
	server_socket:settimeout(0)

	webdav_forced_shutdown = false
	server_running = true
	server_stop_time = os.time() + seconds_runtime

	print("WebDav server started on port " .. tostring(port) .. " for " .. tostring(seconds_runtime) .. " seconds.")
	local time = os.date("*t")
	print("Started at: ", os.date("%A, %m %B %Y | "), ("%02d:%02d:%02d"):format(time.hour, time.min, time.sec))

	server_dialog = show_server_dialog()
	UIManager:scheduleIn(1, update_dialog_countdown)
	UIManager:scheduleIn(0.05, server_tick)
end

local MyWebDav = WidgetContainer:extend({
	name = "MyWebDav",
	is_doc_only = false,
})

function MyWebDav:onDispatcherRegisterActions()
	Dispatcher:registerAction(
		"AutoStopServer_action",
		{ category = "none", event = "AutoStopServer", title = _("My Webdav Server"), general = true }
	)
	Dispatcher:registerAction(
		"MyWebDav_action",
		{ category = "none", event = "MyWebDav", title = _("My WebDav Server"), general = true }
	)
end

function MyWebDav:init()
	self:onDispatcherRegisterActions()
	self.ui.menu:registerToMainMenu(self)
	MyWebDav_ui = self.ui
end

function MyWebDav:addToMainMenu(menu_items)
	local webdav_parms = G_reader_settings:readSetting("webdav_parms")
	local webdav_parms_port, webdav_seconds_run, webdav_username, webdav_password

	-- In manual mode the user-supplied IP is authoritative.
	-- In auto mode we hit the network when Wi-Fi is on.
	if not user_ip_enabled and is_wifi_on() then
		webdav_check_socket()
		if real_ip and real_ip ~= "127.0.0.1" and real_ip ~= "0.0.0.0" then
			webdav_parms_ip_address = tostring(real_ip)
			local saved = G_reader_settings:readSetting("webdav_parms") or {}
			saved.ip_address = tostring(real_ip)
			G_reader_settings:saveSetting("webdav_parms", saved)
			webdav_parms = saved
		end
	end

	if webdav_parms then
		local stored_ip = tostring(webdav_parms["ip_address"])
		if user_ip_enabled then
			webdav_parms_ip_address = (stored_ip ~= "" and stored_ip) or "127.0.0.1"
		elseif real_ip and real_ip ~= "127.0.0.1" and real_ip ~= "0.0.0.0" then
			webdav_parms_ip_address = tostring(real_ip)
		elseif stored_ip ~= "127.0.0.1" and stored_ip ~= "" then
			webdav_parms_ip_address = stored_ip
		else
			webdav_parms_ip_address = "127.0.0.1"
		end

		webdav_parms_port = tonumber(webdav_parms["port"])
		webdav_seconds_run = tonumber(webdav_parms["seconds_runtime"])
		webdav_username = tostring(webdav_parms["username"])
		webdav_password = tostring(webdav_parms["password"])
	end

	menu_items.MyWebDav = {
		text = _("WebDav Server"),
		sorting_hint = "network",
		sub_item_table = {
			-- 1. Start / Stop toggle
			{
				text_func = function()
					if server_running and server_stop_time > 0 then
						local remaining = server_stop_time - os.time()
						if remaining < 0 then
							remaining = 0
						end
						return _("Server running — ") .. format_time(remaining) .. _(" left")
					end
					return _("Start WebDav server. Stops after ") .. format_time(seconds_runtime)
				end,
				keep_menu_open = false,
				enabled_func = function()
					return is_wifi_on()
				end,
				separator = true,
				callback = function()
					if not is_wifi_on() then
						UIManager:show(Notification:new({
							text = _("Wi-Fi is off. Turn it on to start the server."),
							timeout = 3,
						}))
						return
					end

					local low, capacity = is_battery_low(20)
					if low then
						UIManager:show(Notification:new({
							text = _("Battery below ") .. tostring(capacity) .. _(
								"% — server may be unstable. Charge the device."
							),
							timeout = 5,
						}))
					end

					start_server()
				end,
			},
			-- 2. Root folder
			{
				text_func = function()
					return _("Root folder: ") .. root_dir
				end,
				keep_menu_open = true,
				callback = function(touchmenu_instance)
					local PathChooser = require("ui/widget/pathchooser")
					local path_chooser = PathChooser:new({
						select_directory = true,
						select_file = false,
						path = root_dir,
						onConfirm = function(new_path)
							if new_path and lfs.attributes(new_path, "mode") == "directory" then
								root_dir = new_path
								local saved = G_reader_settings:readSetting("webdav_parms") or {}
								saved.root_dir = new_path
								G_reader_settings:saveSetting("webdav_parms", saved)
								UIManager:show(Notification:new({
									text = _("Root folder: ") .. new_path,
									timeout = 3,
								}))
								if touchmenu_instance then
									touchmenu_instance:updateItems()
								end
							else
								UIManager:show(Notification:new({
									text = _("Failed to select folder"),
									timeout = 3,
								}))
							end
						end,
					})
					UIManager:show(path_chooser)
				end,
			},
			-- 3. Manual IP toggle
			{
				text_func = function()
					if user_ip_enabled then
						return _("Manual IP: on")
					end
					return _("Manual IP: off")
				end,
				keep_menu_open = true,
				callback = function(touchmenu_instance)
					user_ip_enabled = not user_ip_enabled

					if user_ip_enabled then
						if not webdav_parms_ip_address or webdav_parms_ip_address == "" then
							webdav_parms_ip_address = tostring(real_ip or "127.0.0.1")
						end
					else
						if is_wifi_on() then
							webdav_check_socket()
							if real_ip and real_ip ~= "127.0.0.1" and real_ip ~= "0.0.0.0" then
								webdav_parms_ip_address = tostring(real_ip)
							end
						end
					end

					local saved = G_reader_settings:readSetting("webdav_parms") or {}
					saved.user_ip_enabled = user_ip_enabled
					saved.ip_address = tostring(webdav_parms_ip_address)
					G_reader_settings:saveSetting("webdav_parms", saved)

					UIManager:show(Notification:new({
						text = user_ip_enabled and _("Manual IP enabled") or _("Manual IP disabled (auto)"),
						timeout = 3,
					}))

					if touchmenu_instance then
						touchmenu_instance:updateItems()
					end
				end,
			},
			-- 5. Settings (IP only in manual mode)
			{
				text = _("Settings"),
				keep_menu_open = true,
				separator = true,
				callback = function(touchmenu_instance)
					if not user_ip_enabled and is_wifi_on() then
						webdav_check_socket()
						webdav_parms_ip_address = tostring(real_ip)
					end

					local MultiInputDialog = require("ui/widget/multiinputdialog")

					local fields = {}

					if user_ip_enabled then
						table.insert(fields, {
							text = tostring(webdav_parms_ip_address),
							input_type = "string",
							hint = _("IP address (manual mode)"),
						})
					end

					table.insert(fields, {
						text = tostring(webdav_parms_port),
						input_type = "number",
						hint = _("Port number (default 8080)"),
					})
					table.insert(fields, {
						text = tostring(webdav_seconds_run),
						input_type = "string",
						hint = _("Seconds (e.g. 600) or MM:SS (e.g. 12:30). Range 30-900."),
					})
					table.insert(fields, {
						text = tostring(webdav_username),
						input_type = "string",
						hint = _("Username for WebDav login"),
					})
					table.insert(fields, {
						text = tostring(webdav_password),
						text_type = "password",
						hint = _("Password"),
					})

					local url_dialog
					url_dialog = MultiInputDialog:new({
						title = user_ip_enabled and _("WebDav settings: ip, port, runtime, login")
							or _("WebDav settings: port, runtime, login"),
						fields = fields,
						buttons = {
							{
								{
									text = _("Cancel"),
									id = "close",
									callback = function()
										UIManager:close(url_dialog)
									end,
								},
								{
									text = _("OK"),
									callback = function()
										local get = url_dialog:getFields()
										local idx = 1

										local new_ip = tostring(webdav_parms_ip_address)
										if user_ip_enabled then
											new_ip = tostring(get[idx] or "")
											if not new_ip:match("^%d+%.%d+%.%d+%.%d+$") then
												UIManager:show(Notification:new({
													text = _("Invalid IP address"),
													timeout = 3,
												}))
												return
											end
											idx = idx + 1
										end

										local new_port = tonumber(get[idx])
										idx = idx + 1
										if not new_port or new_port < 1 or new_port > 65355 then
											new_port = 8080
										end

										local new_seconds_runtime = parse_runtime(get[idx])
										idx = idx + 1
										if
											not new_seconds_runtime
											or new_seconds_runtime < 30
											or new_seconds_runtime > 900
										then
											new_seconds_runtime = 60
										end

										local new_username = tostring(get[idx] or "")
										idx = idx + 1
										if new_username == "" then
											new_username = "admin"
										end

										local new_password = tostring(get[idx] or "")
										idx = idx + 1
										if new_password == "" then
											new_password = "1234"
										end

										webdav_parms_ip_address = new_ip
										port = tonumber(new_port)
										seconds_runtime = tonumber(new_seconds_runtime)
										username = new_username
										password = new_password

										G_reader_settings:saveSetting("webdav_parms", {
											root_dir = root_dir,
											ip_address = new_ip,
											user_ip_enabled = user_ip_enabled,
											port = tonumber(new_port),
											seconds_runtime = tonumber(new_seconds_runtime),
											username = new_username,
											password = new_password,
										})

										UIManager:close(url_dialog)
										MyWebDav:onUpdateWebDavSettings()
										if touchmenu_instance then
											touchmenu_instance:updateItems()
										end
									end,
								},
							},
						},
					})
					UIManager:show(url_dialog)
					url_dialog:onShowKeyboard()
				end,
			},
			-- 5. QR code for quick connection
			{
				text = _("QR code for login"),
				keep_menu_open = true,
				callback = function()
					-- Refresh IP right before showing the QR, unless manual mode
					if not user_ip_enabled and is_wifi_on() then
						webdav_check_socket()
						if real_ip and real_ip ~= "127.0.0.1" and real_ip ~= "0.0.0.0" then
							webdav_parms_ip_address = tostring(real_ip)
						end
					end

					UIManager:show(QRMessage:new({
						text = "http://" .. tostring(webdav_parms_ip_address) .. ":" .. tostring(port),
						width = Device.screen:getWidth(),
						height = Device.screen:getHeight(),
					}))
				end,
			},
			-- 6. Login
			{
				text_func = function()
					local mode = user_ip_enabled and _("manual") or _("auto")
					return _("Login at http://")
						.. tostring(webdav_parms_ip_address)
						.. ":"
						.. tostring(port)
						.. "  ("
						.. mode
						.. ")"
				end,
				enabled = false,
			},
		},
	}
end

function MyWebDav:onMyWebDav()
	UIManager:show(InfoMessage:new({
		text = _("Starting a WebDav Server"),
	}))
end

function MyWebDav:AutoStopServer()
	local text_part = "automatically"
	if webdav_forced_shutdown == true then
		text_part = "manually"
	end
	UIManager:show(InfoMessage:new({
		text = _("Webdav Server has been stopped " .. text_part .. ". You may close menu or start Webdav server again"),
	}))
end

function MyWebDav:onUpdateWebDavSettings()
	UIManager:show(InfoMessage:new({
		text = _("Settings saved"),
	}))
end

-- IP detection
function webdav_check_socket()
	real_ip = nil

	local t = socket.tcp()
	if t then
		t:settimeout(0.5)
		t:connect("1.1.1.1", 80)
		t:connect("8.8.8.8", 80)
		local ip, _, ip_type = t:getsockname()
		t:close()
		if ip and ip_type == "inet" and ip ~= "0.0.0.0" and ip ~= "127.0.0.1" then
			real_ip = ip
		end
	end

	if not real_ip then
		local f = io.popen("ifconfig 2>/dev/null")
		if f then
			local out = f:read("*a")
			f:close()
			local ip = out:match("inet%s+addr:%s*(%d+%.%d+%.%d+%.%d+)") or out:match("inet%s+(%d+%.%d+%.%d+%.%d+)")
			if ip and ip ~= "127.0.0.1" then
				real_ip = ip
			end
		end
	end

	if not real_ip then
		real_ip = "127.0.0.1"
	end
end

webdav_check_socket()

-- Defaults and persisted settings
if G_reader_settings:hasNot("webdav_parms") then
	local default_port = 8080
	local default_username = "admin"
	local default_password = "1234"
	local default_seconds_runtime = 60
	G_reader_settings:saveSetting("webdav_parms", {
		ip_address = tostring(real_ip),
		user_ip_enabled = false,
		port = tonumber(default_port),
		seconds_runtime = tonumber(default_seconds_runtime),
		username = tostring(default_username),
		password = tostring(default_password),
		root_dir = "/mnt/onboard",
	})
end

if G_reader_settings:has("webdav_parms") then
	local webdav_parms = G_reader_settings:readSetting("webdav_parms")
	if webdav_parms then
		webdav_parms_ip_address = tostring(webdav_parms["ip_address"] or real_ip)
		user_ip_enabled = webdav_parms["user_ip_enabled"] == true
		port = tonumber(webdav_parms["port"])
		seconds_runtime = tonumber(webdav_parms["seconds_runtime"])
		username = tostring(webdav_parms["username"])
		password = tostring(webdav_parms["password"])
		if webdav_parms["root_dir"] and webdav_parms["root_dir"] ~= "" then
			root_dir = tostring(webdav_parms["root_dir"])
		end
	end
end

print(
	"Defaults: ip: "
		.. tostring(real_ip)
		.. ", port: "
		.. tostring(port)
		.. ", runtime (seconds): "
		.. tostring(seconds_runtime)
)

return MyWebDav
