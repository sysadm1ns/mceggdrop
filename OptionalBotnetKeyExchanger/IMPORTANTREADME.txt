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