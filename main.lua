--[[--
This is a plugin to Start and Stop a WebDav Server.

@module MyWebDav
--]]--

local BD = require("ui/bidi")
local Dispatcher = require("dispatcher")  -- luacheck:ignore
local InfoMessage = require("ui/widget/infomessage")
local UIManager = require("ui/uimanager")
local QRMessage = require("ui/widget/qrmessage")
local Device = require("device")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local _ = require("gettext")
local C_ = _.pgettext
local T = require("ffi/util").template
local LuaSettings = require("luasettings")
local DataStorage = require("datastorage")
local socket = require("socket")
-- loads the URL module 
local url = require("socket.url")
local io = require("io")
local os = require("os")
local string = require("string")
local http = require("socket.http")
http.TIMEOUT = 60  -- Set a larger timeout (in seconds)
local ltn12 = require("ltn12")
local mime = require("mime")
local lfs = require("libs/libkoreader-lfs")

-- Get the ereader settings when not defined
if G_reader_settings == nil then
    G_reader_settings = require("luasettings"):open(
        DataStorage:getDataDir().."/settings.reader.lua")
end

-- Set the default Home folder = base ebooks folder on the ereader when not defined

if G_reader_settings:hasNot("home_dir") then
	G_reader_settings:saveSetting("home_dir", ".")
end


-- Get the base ebooks folder on the ereader to start the search for ebooks
local root_dir =  G_reader_settings:readSetting("home_dir")

-- print("'" .. root_dir .. "'")

-- Generate HTML header
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
        input { width: 100%; padding: 10px; margin: 10px 0; }
        input[type=submit] { width: 50%; background-color: #4CAF50;padding: 10px; margin: 10px 0; }
        input[type=number] { width: 50px;padding: 5px; margin: 5px 0; }
        #prevBtn, #nextBtn, #jumpBtn { width: 10%; background-color: #4CAF50;padding: 10px; margin: 10px 0; }
        a {color: blue; text-decoration: none;}
        input[type=submit]:hover { background-color: #45a049;}
        button { padding: 10px; width: 100%; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #45a049; }
        .error { color: red; font-size: 14px; margin: 10px 0; }
        .show-password { margin-top: 10px; }
    </style>
    <script>
        function validateFile() {
            const fileInput = document.getElementById('fileUpload');
            const files = fileInput.files;
            const allowedExtensions = /(\.gz)|(\.zip)|(\.tar)$/i;

            for (let i = 0; i < files.length; i++) {
                if (allowedExtensions.test(files[i].name)) {
                    alert("Error: .gz, .zip and .tar files are not allowed.\nUpload only supported files!");
                    fileInput.value = ''; // Clear the input
                    return false; // Prevent form submission
                }
            }
            return true; // Allow form submission
        }
    </script>  
</head>
<body>
    <html>
    <head>
    <title></title>
    <style>
        body {font-family: Arial, sans-serif;}
        table {border-collapse: collapse; width: 100%;}
        table, th, td {border: 1px solid black; text-align:left}
        th, td {padding: 8px;}
       
        .nav {margin-top: 20px;padding: 5px;}
    </style>
    <script>
    </script>
    </head>

    <body>
        <div class="container">
        <div class="nav">
    </div><br>
    <h1>]] .. title .. [[</h1>
    ]]
end

-- Generate HTML footer
local function html_footer()
    return [[
    </div>
    </body>
    </html>
    ]]
end


-- Function to base64 encode the username and password for Authentication
local function base64encode(username, password)
    local credentials = username .. ':' .. password -- OF met haakjes?? Authorization: Basic [admin:****]
    local auth_header_resp = 'Authorization: Basic ' .. mime.unb64(credentials) -- ..']'
    return auth_header_resp
end

-- Function to check authentication
local function check_authentication(headers)
    local auth_header = headers["authorization"]
    -- print('auth_header: ', auth_header)
    if not auth_header then
        return false
    end
    -- Basic Authentication: Basic base64(username:password)
    local auth_type, encoded_credentials = string.match(auth_header, "^(%S+)%s+(%S+)$")
    --print('auth_type: ', auth_type, ' encoded_credentials:' , encoded_credentials)
    if auth_type ~= "Basic" then
        return false
    end
    local decoded_credentials = mime.unb64(encoded_credentials)
    -- print('decoded_credentials:' , decoded_credentials)
    local user, pass = string.match(decoded_credentials, "(%S+):(%S+)")
    --print('Received - user: ' .. user ..', pass: ' .. pass)
    local webdav_parms = G_reader_settings:readSetting("webdav_parms")
	local webdav_username, webdav_password
	if webdav_parms then
		webdav_username =  tostring(webdav_parms["username"]) 
		webdav_password =  tostring(webdav_parms["password"])
		username = nil -- prevents hanging old values
		password = nil
	end
	--if pass then print('Received - user: ' .. user ..', pass: ' .. pass) end
	--print('Stored - user: ' .. webdav_username ..', pass: ' .. webdav_password)
	--if password then print('Memory - user: ' .. username ..', pass: ' .. password) end
	if tostring(user) == tostring(webdav_username) and tostring(pass) == tostring(webdav_password) then 
		auth_header_resp = base64encode(user, pass)
		return true
	else
		auth_header_resp = ''
		return false
	end
    --return tostring(user) == tostring(webdav_username) and tostring(pass) == tostring(webdav_password)
end

local function escape_ampersands(xml_str)
    -- Pattern that matches '&' that are not part of an XML entity or tag
    xml_str = xml_str:gsub("([^<>&]*)&(.-)([^<>&]*)", function(before, mid, after)
        if not mid:match("^[a-zA-Z#][a-zA-Z0-9]*$") then
            -- Only replace '&' when it's not part of an XML entity
            return before .. "&amp;" .. after
        else
            return before .. "&" .. mid .. after
        end
    end)
    
    return xml_str
end

local function escape_spaces_in_path(path)
    -- Spaces in path / file names must be escaped for XML (URL encoding)
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



-- Function to handle MKCOL (create directory)
local function handle_mkcol(client_socket, path)
	local physical_path, virt_path, virtual_dir = get_root_virt_paths(path)
    --print("mkdir '" .. root_dir .. path .."'")
    local success, err = os.execute("mkdir '" .. root_dir  .. path .."'")
    if success then
        webdav_send_response(client_socket, "201 Created", "application/xml", xml, auth_header_resp)  
    else
        webdav_send_response(client_socket, "400 Bad Request", "application/xml", xml, auth_header_resp)  
        -- client_socket:send("HTTP/1.1 400 Bad Request\r\n\r\n")
    end
end

-- Function to handle COPY (copy file)
local function handle_copy(client_socket, path, headers)
	local physical_path, virt_path, virtual_dir = get_root_virt_paths(path)
    local destination = headers["destination"]
    if destination then
        local src_path = url_decode(root_dir  .. path)
        local dst_path = url_decode(root_dir  .. string.sub(destination, #virtual_dir + 1, #destination) )
		local src = io.open(src_path, "rb")
		if not src then return webdav_send_response(client_socket, "404 Not Found", "application/xml", xml, auth_header_resp) end
		local dst = io.open(dst_path, "wb")
		if not dst then src:close(); return webdav_send_response(client_socket, "500 Internal Server Error", "application/xml", xml, auth_header_resp) end
		while true do
			local chunk = src:read(1024)
			if not chunk then break end
			dst:write(chunk)
		end
		src:close(); dst:close()
		webdav_send_response(client_socket, "201 Created", "application/xml", xml, auth_header_resp)
    else
        webdav_send_response(client_socket, "400 Bad Request", "application/xml", xml, auth_header_resp) 
    end
	
end

-- Function to handle MOVE (move/rename file)
local function handle_move(client_socket, path, headers)
	local physical_path, virt_path, virtual_dir = get_root_virt_paths(path)
    local destination = headers["destination"]
    if destination then
        local src_path = root_dir  .. path
		--print('src_path', src_path)
		--print('dst_path', dst_path)           
        local dst_path = root_dir   .. string.sub(destination, #virtual_dir + 1, #destination) 
        local success, err = os.rename( src_path , dst_path)  -- Rename can be used for copying too
        if success then
			webdav_send_response(client_socket, "200 OK", "application/xml", xml, auth_header_resp)        
        else
			webdav_send_response(client_socket, "400 Bad Request", "application/xml", xml, auth_header_resp) 
        end
    else
        webdav_send_response(client_socket, "400 Bad Request", "application/xml", xml, auth_header_resp) 
    end
end

-- Function to handle DELETE (delete file)
local function handle_delete(client_socket, path)
    local file_path = path:sub(2)
    os.remove(root_dir .. '/' .. file_path)
	webdav_send_response(client_socket, "204 No Content", "application/xml", xml, auth_header_resp) 
end


-- Handle file download
local function webdav_download_file(file_name, client_socket)
	--local file_path = file_name
	local file_path=   root_dir .. file_name
	--print ('webdav_download_file=', file_path)
	local mode = lfs.attributes(file_path, "mode")
	if mode == "file" then
		local file = io.open(resolve_path(file_path), "rb")
		if not file then 
			return  client_socket:send("HTTP/1.1 404 Not Found\r\n\r\n") 
		end
		local properties = get_webdav_properties(resolve_path(file_path))
		local size = file:seek("end")
		--print('size=', size)
		file:seek("set")
		local response = "HTTP/1.1 200 OK\r\n"
		response = response .. "Content-Type: application/octet-stream\r\n"   
		response = response .. "Last-Modified: " .. properties.getlastmodified .. "\r\n"    
		response = response .. "Date: " .. os.date("%a, %d %b %Y %H:%M:%S GMT") .. "\r\n"    
		response = response .. "Server: MyUpload Server\r\n"    	
		response = response .. "Content-Length: " .. tostring(size) .. "\r\n"
		response = response .. "\r\n" -- End of headers
		client_socket:send(response)   
        -- send the data
		while true do
			local chunk = file:read(1024)
			if not chunk then break end
			client_socket:send(chunk)
		end
		file:close()	           
    else
		local html = html_header("Error") .. 
    	[[
        <p>File not found: ]] ..file_path .. [[ </p>]]  ..  html_footer()	    
		webdav_send_response(client_socket, "200 OK", "text/html", html, auth_header_resp)   
    end
end

-- Handle HTTP Requests
local function handle_request(client_socket)
    local request = client_socket:receive("*l")
    if not request then return end
        -- Parse URL
    local method, path = request:match("([A-Z]+) (/[^ ]*)")  
   
    -- Read the rest of the request headers
    local headers = {}
    while true do
        local line = client_socket:receive("*l")
        if not line or line == "" then
            break
        end
        local k, v = line:match("^(.-): (.+)$")       
        if k and v then
            headers[k:lower()] = v   
            --print("headers k=", k , ' v=', v)     
        end 
    end

    if method == "OPTIONS" then    
		-- WebDAV allows the following methods: PUT, GET, COPY, MOVE, DELETE, OPTIONS, PROPFIND, MKCOL, HEAD
		local allowed_methods = "PUT, GET, COPY, MOVE, DELETE, OPTIONS, PROPFIND, MKCOL, HEAD"
		--local allowed_methods = "PUT, GET, COPY, MOVE, OPTIONS, PROPFIND, MKCOL, HEAD"
		-- Send HTTP response header with 200 OK and the allowed methods
		local response = "HTTP/1.1 200 OK\r\n" ..
						 "Content-Type: text/plain\r\n" ..
						 "Allow: " .. allowed_methods .. "\r\n" ..
						 "DAV: 1\r\n" ..
						 "Content-Length: 0\r\n" ..
						 "\r\n"
		-- Send the response to the client
		client_socket:send(response)      
	end

	if not check_authentication(headers) then
        client_socket:send("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Default realm\"\r\n\r\n") -- WWW-Authenticate: Basic realm="Default realm"
        return
    end
	-- sanitise path 
	if path then
		path = url_decode(path) -- remove url escaping from path e.g %20 
	end
    
    if path == "/stop" then
		webdav_send_response(client_socket, "503 Service Unavailable", "application/xml", xml, auth_header_resp)  -- first send the stop page the stop server
    	webdav_forced_shutdown = true -- force shutdown of server
    	return
    end    
	--print('method: ', method, ' path=', path)
    -- Handle different WebDAV methods
    if method == "PROPFIND" then
		handle_propfind(client_socket, path)
    elseif method == "MKCOL" then
        handle_mkcol(client_socket, path)
    elseif method == "COPY" then    -- total commander App is not working properly for this command
        handle_copy(client_socket, path, headers)
    elseif method == "MOVE" then    -- total commander App is not working properly for this command
        handle_move(client_socket, path, headers)
    elseif method == "DELETE" then
        handle_delete(client_socket, path)
    elseif method == "GET" then
        -- List Directory (Basic WebDAV)
        local file_name = root_dir .. path
		if file_name then
            webdav_download_file(path, client_socket)
        else
		    local html = html_header("Bad request.") .. 
		    [[
			<p>Invalid file request</p> 
			]]  ..  html_footer()
			webdav_send_response(client_socket, "400 Bad Request", "text/html", html, auth_header_resp)					
			return	
        end        
    elseif method == "HEAD" then
        -- List Directory (Basic WebDAV)
        local dir_path = path   
        --print("HEAD, dir_path ", dir_path)
        local file = io.popen('ls "' .. root_dir .. path .. '"')
        local file_list = file:read("*a")
        --print(file_list)
        file:close()
        webdav_send_response(client_socket, "200 OK", "text/plain", file_list, auth_header_resp)          
    elseif method == "PUT" then	
		local physical_path, virt_path, virtual_dir = get_root_virt_paths(path) 
        -- Upload file
        --print ("path: ", path)
        local file_path = path
		local path, file_to_upload, extension = string.match(file_path, "(.-)([^\\/]-%.?([^%.\\/]*))$")	
		if file_to_upload:lower() == 'stop.txt' then
			webdav_send_response(client_socket, "503 Service Unavailable", "application/xml", xml, auth_header_resp)  -- first send the stop page the stop server
			webdav_forced_shutdown = true -- force shutdown of server	
			return
		end
		local full_filename = root_dir .. file_path
        --print ("full_filename: ", full_filename)	
		if not full_filename then		
			client_socket:send("HTTP/1.1 500 Internal Server Error\r\n\r\n")
			client_socket:close()
			return
		end	
		-- Read and Write the body of the request
		-- Get the content length, which tells us how much data to expect
		local length = tonumber(headers["content-length"])
		if not length then 		
			return webdav_send_response(client_socket, "411 Length Required", "application/xml", xml, auth_header_resp)
		end
		local file = io.open(full_filename, "wb")
		if not file then 	
			return webdav_send_response(client_socket, "500 Internal Server Error", "application/xml", xml, auth_header_resp) 
		end
		local received = 0	
		while received < length do
			local chunk = client_socket:receive(math.min(1024, length - received))
			if not chunk then break end
			file:write(chunk)
			received = received + #chunk
		end
		file:close()
		webdav_send_response(client_socket, "201 Created", "application/xml", xml, auth_header_resp)			
    else
		webdav_send_response(client_socket, "405 Method Not Allowed", "application/xml", xml, auth_header_resp)    
    end
    client_socket:close()
end

lastTimeProcessed = os.clock()

local function IsTimeToProcess(currentTime)
    span = currentTime - lastTimeProcessed
    if span >= 1 then
        lastTimeProcessed = currentTime
        return true
    end

    return false
end

local function is_ipv4( frame )
    local s = frame.args[1] or ''
    s = s:gsub("/[0-9]$", ""):gsub("/[12][0-9]$", ""):gsub("/[3][0-2]$", "")
    
    if not s:find("^%d+%.%d+%.%d+%.%d+$") then
        return nil
    end
    
    for substr in s:gmatch("(%d+)") do
        if not substr:find("^[1-9]?[0-9]$")
                and not substr:find("^1[0-9][0-9]$")
                and not substr:find( "^2[0-4][0-9]$")
                and not substr:find("^25[0-5]$") then
            return nil
        end
    end
    
    return '1'
end

-- Start the server
local function start_server()
	webdav_forced_shutdown = false
    if server_running then
        print("Server is already running.")
        return
    end
    -- Make a hole in the Kindle's firewall
    if Device:isKindle() then
        os.execute(string.format("%s %s %s",
            "iptables -A INPUT -p tcp --dport", port,
            "-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"))
        os.execute(string.format("%s %s %s",
            "iptables -A OUTPUT -p tcp --sport", port,
            "-m conntrack --ctstate ESTABLISHED -j ACCEPT"))
    end
    	
    server_socket = assert(socket.bind('*', port))
    server_socket:settimeout(0)  -- Non-blocking

    print("WebDav server started to run on port " .. tostring(port) .. ' for ' .. tostring(seconds_runtime) ..  ' seconds.')
    local date = os.date('*t')
	local time = os.date("*t")
	print('Started at: ', os.date("%A, %m %B %Y | "), ("%02d:%02d:%02d"):format(time.hour, time.min, time.sec))
    server_running = true
   
    
	local function wait(s)
	  local lastvar
	  for i=1, s do
			lastvar = os.time()
			while lastvar == os.time() do
				-- print(lastvar)
				local client_socket, err = server_socket:accept()
				if client_socket then
					client_socket:settimeout(2)
					handle_request(client_socket)
					client_socket:close()
				end			
			end
		 if webdav_forced_shutdown == true then
		   break
		 end			
	  end
	end
	wait(seconds_runtime) -- in seconds the the WebDav Server will stop automatically to save battery
	if server_socket then
		-- Close the hole in the Kindle's firewall
		if Device:isKindle() then
			os.execute(string.format("%s %s %s",
				"iptables -D INPUT -p tcp --dport", port,
				"-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"))
			os.execute(string.format("%s %s %s",
				"iptables -D OUTPUT -p tcp --sport", port,
				"-m conntrack --ctstate ESTABLISHED -j ACCEPT"))
		end		
		server_running = false
		server_socket:close()
		date = os.date('*t')
		time = os.date("*t")
		print('Stopped at: ', os.date("%A, %m %B %Y | "), ("%02d:%02d:%02d"):format(time.hour, time.min, time.sec))
		print('WebDav server has been stopped listing at http://' .. tostring(ip) .. ':' .. tostring(port) )
	end

 -- The loop WITHOUT using a Timer looks look this	  
 --   while server_running do
 --       local client_socket, err = server_socket:accept()
 --       if client_socket then
 --           client_socket:settimeout(2)
 --           handle_request(client_socket)
 --           client_socket:close()
 --       end
 --   end
end

-- Stop the server
local function stop_server()
    if not server_running then
        print("Server is not running.")
        return
    end
    server_running = false
    if server_socket then
        server_socket:close()
    end
    print("WebDav server has been stopped.")
end

-- Example Usage:
-- start_server()  -- Start the server
-- stop_server()  -- Stop the server




local MyWebDav = WidgetContainer:extend{
    name = "MyWebDav",
    is_doc_only = false,
}

function MyWebDav:onDispatcherRegisterActions()
    Dispatcher:registerAction("AutoStopServer_action", {category="none", event="AutoStopServer", title=_("My Webdav Server"), general=true,})
    Dispatcher:registerAction("MyWebDav_action", {category="none", event="MyWebDav", title=_("My WebDav Server"), general=true,})
end

function MyWebDav:init()
    self:onDispatcherRegisterActions()
    self.ui.menu:registerToMainMenu(self)
end

function MyWebDav:addToMainMenu(menu_items)
    webdav_check_socket()	
	local webdav_parms = G_reader_settings:readSetting("webdav_parms")
	local webdav_parms_port, webdav_seconds_run, webdav_username, webdav_password
	if webdav_parms then 
	    webdav_parms_ip_address =  tostring(real_ip)
		webdav_parms_port = tonumber(webdav_parms["port"])
		webdav_seconds_run = tonumber(webdav_parms["seconds_runtime"])
		webdav_username =  tostring(webdav_parms["username"]) 
		webdav_password =  tostring(webdav_parms["password"]) 
	end
    menu_items.MyWebDav = {
        text = _("WebDav Server"),
        -- sorting_hint = "more_tools",
        sub_item_table = { 
		    {  
                text = "Is Wifi ON? Then start WebDav", 
                enabled=false,
                separator=false,
              }, 
              {
                text = "Menu locked? WebDav is running!",
                enabled=false,
                separator=false,
              }, 
				{  
                text = "Login at http://" .. webdav_parms_ip_address .. ":" ..  tostring(port), 
                enabled=false,
                separator=true,
              },  
				{  
                text = "QRcode for login" , 
                enabled=true,
                separator=true,
				callback = function()
					UIManager:show(QRMessage:new{
						text = "http://" .. webdav_parms_ip_address .. ":" ..  tostring(port),
						width = Device.screen:getWidth(),
						height = Device.screen:getHeight()
					})
				end,         
              },                            
				{  
                text = "IP 127.0.0.1 shown? Wifi was OFF at start KOreader" , 
                enabled=false,
                separator=true,
              },                   
			{   text = _("Start WebDav server. Stops after " .. tostring(seconds_runtime) .."s" ),
                keep_menu_open = true,
                callback = function()  
		
					-- start the server 		
					start_server()				    			
                end,
            },   
     
		   {
				text = _("Settings"),				
				keep_menu_open = true,
				callback = function(touchmenu_instance)
					local MultiInputDialog = require("ui/widget/multiinputdialog")
					local url_dialog
				
					url_dialog = MultiInputDialog:new{
						title = _("WebDav settings: ip, port, runtime, username, password"),
						fields = {
						{
								text = webdav_parms_ip_address,
								input_type = "string",
								hint = _("nil or 127.0.0.1? Set to IP address of ereader!"),
							},						
							{  
								text = webdav_parms_port,
								input_type = "number",
								hint = _("Port number (default 8080)"),
							},
							{
								text = webdav_seconds_run,
								input_type = "number",
								hint = _("Runtime range 60-900 seconds (default 60)."),
							},	
							{
								text = webdav_username,
								input_type = "string",
								hint = _("Username for login into WebDav server"),
							},	
							{
								text = webdav_password,
								input_type = "string",
								hint = _("password"),
							},							
						},
						buttons =  {
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
											MyWebDav:onUpdateWebDavSettings()
											local fields = url_dialog:getFields()
											if not fields[1] ~= "" then
												local ip_address = tonumber(fields[1])
												
												--print('>>>',ip_address)
												if not ip_address then
													 --default ip_address
													 ip_address = '127.0.0.1'												
												elseif not is_ipv4(ip_address)  then
													 ip_address = '127.0.0.1'
												end																							
												local new_port = tonumber(fields[2])
												if not new_port or new_port < 1 or new_port > 65355 then
													--default port
													 new_port = 8080
												end
												local new_seconds_runtime = tonumber(fields[3])
												if not new_seconds_runtime or new_seconds_runtime < 30 or new_seconds_runtime > 900 then
													--default port
													 new_seconds_runtime = 60
												end	
												local new_username = tonumber(fields[4])
												if not new_username or new_username == " "  then
													--default new_username
													 new_username = 'admin'
												end													
												local new_password = tonumber(fields[5])
												if not new_password or new_password == " "  then
													--default new_password
													 new_password = '1234'
												end																													
												G_reader_settings:saveSetting("webdav_parms", {ip_address = tostring(ip_address), port = tonumber(new_port), seconds_runtime = tonumber(new_seconds_runtime), username = tostring(new_username), password = tostring(new_password) })
												-- after save make these values the actual ones
												--port = tonumber(new_port)
												--seconds_runtime = tonumber(new_seconds_runtime)
												--username = tostring(new_username)
												--password = tostring(new_password)
											end
											UIManager:close(url_dialog)
											if touchmenu_instance then touchmenu_instance:updateItems() end
										end,
										
								},
							},
						},
					}
					UIManager:show(url_dialog)
					url_dialog:onShowKeyboard()
				end,
			},
              
        }
    }

end

function MyWebDav:onMyWebDav()
    local popup = InfoMessage:new{
        text = _("Starting a WebDav Server"),
    }
    UIManager:show(popup)
end

function MyWebDav:AutoStopServer()
    local text_part = 'automatically'
	if webdav_forced_shutdown == true then
		text_part = 'manually' 
	end
    local popup = InfoMessage:new{
        text = _("Webdav Server has been stopped " .. text_part ..". You may close menu or start Webdav server again"),
    }
    UIManager:show(popup)
end

function MyWebDav:onWifiIsOff()
    local popup = InfoMessage:new{
        text = _("Switch Wifi ON before starting WebDav!"),
    }
    UIManager:show(popup)
end

function MyWebDav:onUpdateWebDavSettings()
    local popup = InfoMessage:new{
        text = _("Now restart KOReader for changes to take effect!"),
    }
    UIManager:show(popup)
end

function webdav_check_socket()
	-- to get your IP address
	local s = socket.udp()
	local result = s:setpeername("pool.ntp.org",80) -- accesses a Dutch time server
	if not result then
	  s:setpeername("north-america.pool.ntp.org",80)-- accesses a North America time server
	end
	local ip, lport, ip_type = s:getsockname() -- The method returns a string with local IP address, a number with the local port, and a string with the family ("inet" or "inet6"). In case of error, the method returns nil.

	if ip and ip_type == 'inet' then 
		real_ip = ip
	else
	  ip = "127.0.0.1"
	  real_ip = "127.0.0.1"  
	end
end

webdav_check_socket()

if G_reader_settings == nil then
    G_reader_settings = require("luasettings"):open(
        DataStorage:getDataDir().."/settings.reader.lua")
end


if G_reader_settings:hasNot("webdav_parms") then
	-- Default Configuration
	-- Default WebDav Configuration
	local default_ip_address = "*"
	local default_port = 8080
	local default_username = "admin"
	local default_password = "1234"
	local default_seconds_runtime = 60  -- standard is 1 minute
    G_reader_settings:saveSetting("webdav_parms", {ip_address = tostring(real_ip), port = tonumber(default_port), seconds_runtime = tonumber(default_seconds_runtime), username = tostring(default_username), password = tostring(default_password) })
end

if G_reader_settings:has("webdav_parms") then
	local webdav_parms = G_reader_settings:readSetting("webdav_parms")
	local webdav_parms_port, webdav_seconds_run, webdav_username, webdav_password
	if webdav_parms then 
	    webdav_parms_ip_address = tostring(webdav_parms["ip_address"])
		port = tonumber(webdav_parms["port"])
		seconds_runtime = tonumber(webdav_parms["seconds_runtime"])
		username =  tostring(webdav_parms["username"])
		password =  tostring(webdav_parms["password"])
	end
end

print('Defaults: ip: ' .. tostring(real_ip) .. ', port: ' .. tostring(port) ..', runtime (seconds): ' .. tostring(seconds_runtime) )



return MyWebDav
