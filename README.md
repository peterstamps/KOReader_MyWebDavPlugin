Download at https://github.com/peterstamps/KOReader_MyWebDavPlugin

The valid license for this open source plugin is AGPL Version 3.0

IMPORTANT!
See the installation instructions before use. 
They are below in this document/on this page.


INTRODUCTION

This WEBDAV SERVER plugin allows you to use any Webdav client App or File Explorers with Webdav support to browse through the content of the Home folder of your device running KOReader. You can wirelessly (only via Wifi) upload, download, delete, copy and move eBooks and any type of files. You can also create a new folder and delete a folder after first deleting the content in that folder.

The default is Login username is "admin" with password "1234" (without the double quotes!).

RECOMMENDED WEBDAV CLIENTS 
NOTE: if you have problems then try another Webdav client. I had for example problems with WinSCP while Cyberduck worked fine on Windows 11.
On my smart phone I use this  Total Commander App as it works perfect: https://play.google.com/store/search?q=total+commander+for+android&c=apps
and the WebDav plugin: https://play.google.com/store/apps/details?id=com.ghisler.tcplugins.WebDAV


Android Apps:  Total Commander App with additional Webdav plugin (preferred!), File Manager App (but it some functions do not work properly See release notes!)
Windows 11:  Cyberduck (preferred), WinScp (but sometimes it requires extra refreshes and too many clicks to view results... strange random behaviour)
Linux: Nautilus, PCManFM (also a filemanager), others with WebDav support
Mac: Cyberduck
On All devices: KOReader, yes it has a WebDav client that you might already use: go to Cloud Storage under the main menu with the tools icon.
If you use KOReader on Android you can access ebooks that are located on your ereader which runs KOreader with the Webdav Server!


The starting point after login is a view of all content in the Home folder that you have chosen and set in you KOReader. Their is an exception: hidden files and folders ending with their name as .sdr are NOT shown at all.

If your KOReader is running on the same device as where Calibre is running then you might see the folder structure that Calibre uses.
In the screen prints in github you will see examples of such structure. Note: the structure on you KOReader might be different.
For example when sending ebooks with default settings from Calibre to a KOBO device the structure will look like Home folder > Author folder > eBook files such as epub, kepub.epub, pdf and so on.


Upload happens wirelessly via your home Wifi or via the Hotspot on your phone or via any network as long as the device with the Browser and the device with KOReader can connect to each other over the same LAN. The connection is over HTTP only on the port number set in the plugin. 
The plugin has a function to generate a QRcode for the Login on your smart phone or PC for example. 
An own defined username and password can be set as well. 

Before starting the plugin make sure Wifi is ON and the device with KOreader is connected to your LAN.
That is required in order to obtain an IP address which is used to make a connection from a browser to your device. 

The plugin starts a webdav server on the KOReader device at the defined port (default 8080). 
That webdav server runs for the number op seconds you have set (default 60 seconds = 1 min maximum 15 min) and stops automatically to save you a battery drain! 
You can also manually Stop the Wedav Server via a Webdav client. This overrules the runtime. 
You do this as follows:
- enter /stop after the url http://<ip-address-webdavserver>:8080  So it should look like: http://192.168.1.11:8080/stop
OR
- upload, copy or move a file with the name: stop.txt. 
  The file itself will not be uploaded, copied or moved. The Webdav server stops immediately

ebooks will appear automatically in the folder that you have set as Home folder. 
So that could be any folder that KOReader can access on the device and that provides write access.

BTW: this is not an wireless upload via VPN or a third party... Nobody else is needed or involved. Just you and your LAN. 
If you use the standard available Hotspot function of the smart phone of your friend and you connect your ereader with the KOReader installed to that Hotspot then you have a LAN to work with. Then connect via a browser to the URL shown by the Webdav server and you both can exchange ebooks directly via upload/download as you are both on the same LAN.

See the github folder with the screen prints to get an overview.

This plugin was developed on Ubuntu 24 and works on Ubuntu 24, Raspberry Pi 4 with Bookworm and Samsung/Android Smartphones when KOReader is installed.
It should also work on KOBO and from version 1.1 probably also on Kindle. Note: Kindle has a firewall installed that blocked previous versions of this Plugin. By adding a firewall rule I hope that it will work on Kindle as well. However I am not sure as I cannot test that.


WHAT TO DO IF YOU CANNOT ACCESS FROM A WEBDAV CLIENT THE WEBDAV SERVER? 

Check the following points:
1. Is Wifi ON? -> Switch on Wifi
2. Is device connected to the LAN? -> Login to your LAN with the KOReader device as an IP is required. Check IP
3. Is Plugin Settings menu function NOT showing your LAN IP but just 127.0.0.1? -> Use Plugin menu Reset function, Restart KOReader or the device when needed and check Steps 1 and 2 after a restart!
4. Is the Upload Server running? -> Your Menu should be blocked else (re-)start the WebDav Server
5. Is your Webdav client showing "Service unvailable" -> Check if the WebDav server is still running (see point 4) as the runtime might be over (automatic stop is activated)!
6. You still cannot connect after checking above points? -> Is there a firewall blocking the connection? That firewall can be running on your router, your webdav client device and/or your KOReader device. The port you have set may not be blocked by the firewall. Maybe some ereader devices with build-in firewall do not allow you to connect to your LAN. If the latter is the case you might be stuck. See the note about Kindle firewall before.
7. Has the plugin crashed? -> You might Restart after a Reset


INSTALLATION
1. Connect via USB cable your KOReader device with a PC or equal device.

2. Locate the folder where KOReader is installed, e.g. on Kobo: /mnt/onboard/.adds/koreader/ 
The plugins directory will be: /mnt/onboard/.adds/koreader/plugins

3. Create in the plugins directory a sub directory called MyWebDav.koplugin 
Like this: /mnt/onboard/.adds/koreader/plugins/MyWebDav.koplugin

4. Now unzip MyWebDav.koplugin.zip and copy following two files into 
   the new sub directory called /mnt/onboard/.adds/koreader/plugins/MyWebDav.koplugin
   These two files are:
   _meta.lua (mandatory)
   main.lua (mandatory)
   README.md (optional)
   stop.txt (optional)

5. Check if these two mandatory files are in that Folder. No other files are required and no other sub-directories as well.

6. Installation is done. 

7. Now start KOReader and the Plugin WebDav Server for the First time, check the IP address and hereafter you MUST RESTART KOReader AGAIN so that the new settings are activated!

See / search also Reddit KOReader for latest news and updates.

See also the screen prints folder in github at: https://github.com/peterstamps/KOReader_MyWebDavPlugin/tree/main/Screenprints

UPDATE NOTES

version: 1.0.1
- first release, reused a lot of the code of my other plugin see https://github.com/peterstamps/KOReader_MyUploadPlugin

version: 1.1
- Copy to Webdav server failed when using larger files as the file was read in memory before write happened. That is now changed and chunks are read and written.
- Copy using the File Manager App on Android does not work okay. The file is copied with (zero) 0 bytes. Use an other app like Total Commander App with the Webdav plugin to copy files.

version: 1.2
- A copy was actually treated as a move. That is now corrected. 
- NOTE: The File Manager App on Android does not work okay for all actions! A Copy, Move or Download between Webdav server and a remote device does not work fine!. 
  For example a file is copied with (zero) 0 bytes. 
  The Total Commander App with the Webdav plugin on Andoid however works fine with all functions. Also Nautilus on Ubuntu and other will work fine.

