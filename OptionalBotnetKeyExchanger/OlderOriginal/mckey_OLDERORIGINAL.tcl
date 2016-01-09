#-+----------------------------------------------------------------
#
# Keymanager for mceggdrop by SlaSk.
#
# NOTE: 99.999% of people should NOT install this - you do NOT NEED IT!!!
#       It is a purely optional thing for those people who want to
#       do some unusual stuff with botnets.
#
# This script lets you avoid storingthe channel key in the config
#  file of each bot in your botnet.
# A designated "master" bot keeps the key and the remaining bots
#  query the master for the key. These bots keep the key in memory
#  at all times, this makes it harder (but not impossible) to steal
#  the key from a bot.
# Just remember - this means that the bots are sending the key
#  to each other in plaintext over the network - so you better be
#  sure these bots are not communicating over a snoopable network.
#
# 2004-06-14 Initial release.
#
#-+----------------------------------------------------------------

# Specify the bot holding the key for each channel.

#set mckey_master(#channel1) KeyBot1
#set mckey_master(#channel2) KeyBot2
#set mckey_master(#channel3) KeyBot3
#set mckey_master(#channelN) KetBotN


#-+----------------------------------------------------------------

# Call mckey:push to send the new key to all bots if you change it
# while the bots are running.

proc mckey:push { channel } {
global mcpskey

	putallbots "MCKEY_RESP $channel $mcpskey($channel)"
}


#-+----------------------------------------------------------------

# Intrabot communication.

bind bot - MCKEY_QUERY	mckey:bot_trigger
bind bot - MCKEY_RESP	mckey:bot_trigger

proc mckey:bot_trigger { from cmd arg } {
global botnick
global mcpskey
global mckey_master

	switch $cmd {
		MCKEY_QUERY {
			# putlog "MCKEY DEBUG: $from requested the key for $arg."

			if { $botnick == $mckey_master($arg) && [info exists mcpskey($arg)] } {
				putbot $from "MCKEY_RESP $arg $mcpskey($arg)"
			}
		}
		MCKEY_RESP {
			set channel [lindex $arg 0]
			set key     [lindex $arg 1]

			# putlog "MCKEY DEBUG: Received the key for $channel from $from."

			if { $from == $mckey_master($channel) } {
				set mcpskey($channel) $key
			}
		}
	}
}

#-+----------------------------------------------------------------

# Watch for links with a master bot.

bind link - * mckey:link_trigger

proc mckey:link_trigger { bot via } {
global mckey_master

	# putlog "MCKEY DEBUG: linked with $bot via $via"

	set mckey_sid [array startsearch mckey_master]

	while { [array anymore mckey_master $mckey_sid] } {

		set channel [array nextelement mckey_master $mckey_sid]
		set master  $mckey_master($channel)

		if { $bot == $master } {
			# putlog "MCKEY DEBUG: Requesting key for $channel from $master."
			putbot $master "MCKEY_QUERY $channel"
		}
	}

	array donesearch mckey_master $mckey_sid
}

#-+----------------------------------------------------------------

# Request keys on startup.

set mckey_sid [array startsearch mckey_master]

while { [array anymore mckey_master $mckey_sid] } {

	set channel [array nextelement mckey_master $mckey_sid]
	set master  $mckey_master($channel)

	if { [lsearch -exact [bots] $master] == -1 } {
		continue
	}

	if { $botnick != $mckey_master($channel) } {
		# putlog "MCKEY DEBUG: Requesting key for $channel from $master."
		putbot $master "MCKEY_QUERY $channel"
	}
}

array donesearch mckey_master $mckey_sid

#-+----------------------------------------------------------------

