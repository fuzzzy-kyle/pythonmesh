## Updates for GUI

# everywhere


# Connection tab
- Only one connection method shall be selectable

# Mesh Nodes tab
- Clicking the "Clear" button next to the search tab should clear the search as well as show all the nodes in the list.
-Add an "All" option from the search drop down to search all node information

- The traceroute function doesn't seem to be actually working right now. it just reports the same information every time I run it (same exact time, hops etc.). Make sure this is actually functioning and doing a real traceroute to the selected node. Make sure to look at meshtastic's codebases to figure out an implementation of this.
https://github.com/meshtastic/python or https://github.com/meshtastic

# Messages tab
- I'm still not recieving any messages. again, refer to the meshtastic codebase to figure out why we arent receiving any.

# Configuration tab
- ok now the "Refresh Config", "Save to device", etc. buttons are visible on every single tab. These should only be on the "Configuration" tab. also make sure they are just above the connection status at the bottom of the window. 


# Monitor (THIS IS A NEW TAB)
- add a "Monitor" tab that shows all tx/rx activity in a console. 
- Allow the user to pass meshtastic cli commands here. 
- give the option to export the session console history
