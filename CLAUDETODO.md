## Updates for GUI

# General
Let's remove "GUI" from the "Meshtastic GUI" window bar


# Connection tab
- lets make the device information box black background with green text (like in our monitor tab)
- we should print the device firmware version in the Device Information box
- If no position information is available put "N/A" rather than leaving this area blank.

# Mesh Nodes tab
- clicking the "Clear" button should also refresh the node list in addition to clearing the search bar
- Both the "Request Position" and "Request Telemetry" buttons just generate a pop-up that says "Feature not yet implemented. Go ahead and implement these features.
  -   Here are the meshtastic commands:
      --request-telemetry [TYPE]
                        Request telemetry from a node. With an argument,
                        requests that specific type of telemetry. You need to
                        pass the destination ID as argument with '--dest'. For
                        repeaters, the nodeNum is required.
      --request-position    Request the position from a node. You need to pass the
                        destination ID as an argument with '--dest'. For
                        repeaters, the nodeNum is required.
- The distance column is completely blank for all nodes. This should populate when the first connecting the device and when clicking the "Refresh Nodes" button. 
- There seems to be a rounding issue with batter percentages (some are showing 101%) 

# Messages tab
- lets make the message history box box black background with green text (like in our monitor tab)
- Currently, Whenever a message is received that was sent out by someone to the whole mesh (Broadcast) it is recieved as an individual message from that node. Let's make an "active chat" for ^all that all of these go to. 
- direct messages the connected device are receiving are not appearing in the message history. Here's an example packet for one that did not appear: 
"id: 2045547816
rx_time: 1756835164
rx_snr: 9
hop_limit: 7
want_ack: true
rx_rssi: -48
hop_start: 7
public_key: "\236\337\370Ce4P\360C\342\252t\360%\307m\027D\003\022\247{w\000\227\271\214\302\216\202\366\037"
pki_encrypted: true
next_hop: 228
relay_node: 212
, 'fromId': '!a0cc74d4', 'toId': '!99bc8be4'}"



# Configuration tab
- remove the text "Configuration Sections"
- Remove the descripton in each of the configuration details such as "Device Configuration", "Lora Configuration", etc.
- Under the device section add these fields for these meshtastic commands: 
  --set-owner SET_OWNER
                        Set device owner name
  --set-owner-short SET_OWNER_SHORT
                        Set device owner short name



# Monitor tab
- let's change the name of this tab to "Console" 
- let's remove the "TX/RX Activity Console" text, it is not neccassary  
- There seems to be a bug where every once in a while a packet will print to the console twice. See the following examples:
[10:48:42] RX: Packet ID:1648208063 Node None→Broadcast (encrypted/unknown)
[10:48:58] RX: Packet ID:3686303392 Node None→Broadcast (portnum=NODEINFO_APP, size=74B, user="SaltBayGull")
[10:55:19] RX: Packet ID:1376089104 Node None→Broadcast (portnum=TELEMETRY_APP, size=24B, bat=47%, v=3.69V)
[10:55:19] RX: Packet ID:1376089104 Node None→Broadcast (portnum=TELEMETRY_APP, size=24B, bat=47%, v=3.69V)
[10:57:21] RX: Packet ID:2475454920 Zender/Mobile→Broadcast (portnum=TELEMETRY_APP, size=28B, bat=44%, v=3.67V)
[10:57:21] RX: Packet ID:2475454920 Zender/Mobile→Broadcast (portnum=TELEMETRY_APP, size=28B, bat=44%, v=3.67V)
[10:58:59] RX: Packet ID:18059676 Node None→Broadcast (portnum=POSITION_APP, size=27B, lat=37.9322, lon=-122.0280, alt=0m)
[10:58:59] RX: Packet ID:18059676 Node None→Broadcast (portnum=POSITION_APP, size=27B, lat=37.9322, lon=-122.0280, alt=0m)
[11:03:58] RX: Packet ID:504664700 Node None→Broadcast (portnum=NODEINFO_APP, size=73B, user="TRAP CAT")
[11:04:19] RX: Packet ID:3573459826 time2go0U7→Broadcast (portnum=TELEMETRY_APP, size=27B, bat=101%, v=4.89V)
[11:04:19] RX: Packet ID:3573459826 time2go0U7→Broadcast (portnum=TELEMETRY_APP, size=27B, bat=101%, v=4.89V)

- Let's add a "Help" button that will have a popup window that pupulates with text from the "--help" command. Don't print this in the console box.  