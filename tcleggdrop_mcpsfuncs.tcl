#######################################################
# McEggdropTcl - MIRCRYPTION HELPER FUNCTIONS FOR EGGIES
# (cc) mouser 09/03-3/14 / heidel, bounty, slask, WtF
#  visit #mircryption@efnet for support
#
# Functions to make other eggdrop/windrop scripts able to encrypt and decrypt text if (and only if) appropriate
#
# started 9/6/03 by mouser
# updated 9/7/03 by zinc
# updated 9/8/03 by mouser+zinc
# updated 12/22/03 by mouser - compatible with +OK, better instructs, better behaved
# updated 12/22/03 by mouser - added mcreplyonlyinkind and mcreplyneverplaintext options
# updated 12/22/03 by mouser - added error reporting to user
# updated 12/23/03 by mouser - added more instructions to this file
# updated 12/23/03 by mouser - added ability to reply to meow (can be disabled)
# updated 12/23/03 by mouser - added putmsgmc and putnotcmc
# updated 12/23/03 by mouser - begun a new different system for taking over binds
# updated 12/24/03 by mouser - incorporating code from stdragon for new bind takeover
# updated 12/24/03 by mouser - fully working script can interface any eggdrop script w/ mircryption
# updated 12/25/03 by mouser - now handled pub > pubm precedence like builtin eggdrop does
# updated 12/25/03 by mouser - more efficient bind iteration
# updated 12/25/03 by mouser - added ability to specify output prefixes for channels
# updated 12/25/03 by mouser - added code to prevent trying to reroute putmsg and putnotc for eggdrops without them;
# updated 12/25/03 by mouser - minor bugs fixed
# updated 12/25/03 by mouser - now tested to work also on on windrop 1.6x+
# updated 12/29/03 by mouser - made it avoid double encryption if text is already encrypted
# updated 01/18/04 by mouser - added option to prevent private message encrypting
# updated 04/28/04 by mouser - added clearer instructions about # comments in user config section
#                            - added better information when it complains about not finding key to encrypt.
#                            - added code to force lowercasing of channel names, should solve some problems with other scripts
#                            - (all channel keys should now be specified in lowercase)
#                            - added warning that certain characters cannot be used in tcl strings (keys) without 'escaping' them.
# updated 05/08/04 by mouser - added mcdontlistentoplaintext flag to handle how it should reply to plaintext commands.
# updated 05/27/04 by mouser - it now knows to not encrypt ctcp stuffs
# updated 06/12/04 by slask  - bug fix for binds with masks containing spaces
# updated 06/12/04 by slask  - bugfix for checking of multiple matching binds (foreach abind was not executing)
# updated 06/12/04 by slask  - bugfix for handling incoming text with quotes
# updated 06/12/04 by slask  - bugfix where certain text was being encrypted that shouldnt be (:mynick INVITE somenich #somechannel)
# updated 06/22/04 by mouser - added support for long line splitting (see mcmaxlinelen below)
# updated 06/26/04 by mouser - added splitting at other punctuation not just spaces
# updated 08/24/04 by mouser - removed test functions encrypting of arbitrary text for fear it would help a chosen plaintext attack
# updated 11/17/04 by mouser - added reminder note about using ':'
# updated 11/18/04 by mouser - started adding support for encrypted ctcp, dcc, chat (but this is unfinished and not activated yet! - need some help here)
# updated 12/07/04 by mouser - added abilility to override default encryption for a nick/chan by using "NOCRYPT" as the key for that nick/chan
# updated 02/06/05 by mouser - added putlog commands to testbot functions for better diagnosis of problems
#                              added comments about script conflicts
#                              added flag check for - as well as -|-
# updated 02/12/05 by mouser - changed 'string equal' to 'string compare' to fix tcl older version issue
# updated 02/13/05 by mouser - adding support for plaintext blocking helper script
# updated 03/15/05 by heidel - fixed lastbind variable to hold the actual mask of the triggered bind instead of the +OK/mcps prefix
#                            - added mcbinds dcc command so owners can see which mc binds are currently registered
#                            - fixed topc bind to be triggered and processed correctly
# updated 05/23/05 by mouser - added fix provided by Parnic for regexp bug that didnt escape ) characters
# updated          by heidel - adding mclastbind variable to hold the actual word that triggered the bind (lastbind contains the +OK/mcps prefix)
# updated 07/01/05 by mouser - version # updated
# updated 07/18/05 by heidel - added heidel's fixes from 3/15 and his 7/16 new esay functions for partyline say replacement [mouser merged changes]
# updated 07/18/05 by heidel - nice new partyline esay and emsg, encrypted verion of say and msg
# updated 07/19/05 by bounty - added new cbc encryption code to mceggdrop, using existing tcl cbc libraries.  [bounty's cbc_functions integrated into to mcegdrop by mouser]
# updated 11/27/05 by heidel - fixed trigger count for mc binds table (visible through .mcbinds partyline command)
# updated 02/20/06 by mouser - improved (but not tested yet) ability to prevent text from being encrypted if prefixed with ' or NOCRYPT
# updated 08/27/06 by heidel - fixed esay and emsg for eggdrop 1.6.18
# updated 11/17/07 by heidel - fixed putmsg/putnotc
#                            - no longer suppressing error messages from triggered bind procs and invalid put commands
#                            - correctly handling options in put commands (e.g. putserv "test" -next)
# updated 3/19/14 by WtF     - fixed tcl functions of the form "set x y" to correctly be "set x $y"
#
# Credit+Special thanks to those who helped, including
#  heidel, slask, stdragon, and #egghelp channel (esp. Pixelz and slim)
#######################################################


#######################################################
# IMPORTANT INFO FOR UPGRADERS:
#
# Since around version 1.00.15 (06/12/04), tcleggdrop_mcpfuncs.tcl now requires that when specifying channel keys, you MUST
# specify your channel name in lowercase.
# 
# in other words, if your channel name is #MyChan
# and in previous versions you had:
#  set mcpskey(#MyChan)
# you should now change this to:
#  set mcpskey(#mychan)
#
# Failure to do so will result in the new mceggdrop not finding the key for your channel.
#######################################################


#######################################################
# CONFLICTS WITH OTHER SCRIPTS:
# If you find that your bot will not respond to encrypted messages, it might be that you
#  have another script which might be intercepting +OK messages before mceggdrop has a chance to.
# To see if this is the case, comment out the other scripts in your eggdrop config.
# Once you confirm it is a script conflict, try to find the "bind pub ... +OK" in the other script,
#  and determine if you still need it now that you have mceggdrop installed, if not, comment out the bind. 
# Nothing else about the script matters except for the bind statement.
# One way to fix the other script is if you find it using 'bind pub'
#  then modify it to use 'bind pubm' style binding, which allows other scripts to still bind:
# change from:  bind pub - "!command" function
# to:           bind pubm -|- "* !command" function
# Some examples of scripts that try to catch +OK and can conflict with mceggdrop:
#  newdir.tcl and dzsbot.tvl, both by b0unty, from ioftpd.com forums
#  scripts by "perceps"
#######################################################


#######################################################
# TO DO LIST AND KNOWN ISSUES
# This script is capable of parsing the installed binds
#  of other scripts, and manually triggering them.
# This is a somewhat complicated process, and the ORDER
#  in which the binds are triggered may possibly differ
#  from the order in which eggdrop normally triggers
#  the binds on plaintext.
# My tcl coding is inefficient - if you can improve
#  please do, and let us know.
# TODO
#  06/12/04 - strip :mynick in ":mynick PRIVMSG #channel :a message"
#  06/12/04 - support special command modifier prefixes in text (if mcs prefix not exist, then do normal)
#              mcs plain - always send plain
#              mcs cryptonly - always send crypted or not at all
#              mcs plainversion - send this IFF user queried us plain
#              mcs cryptversion - send this IFF user queried us crypted
#  02/07/04 - add flag to easily turn on all debug putlogs
#  05/16/05 - add bypass for KICK (could have : in it)
#######################################################


#######################################################
# version
set mceggdropversion "1.00.29"
#######################################################


#######################################################
# WHAT IS THIS FILE?
#
# This is an eggdrop tcl script which provides functions
#  that will help you to make your existing eggdrop
#  scripts be able to send and receive encrypted text.
# 
# Just add this script (tcleggdrop_mcpsfuncs.tcl) to
#  your eggdrop configuration file, BEFORE any other
#  script that uses these functions.
#
# See instructions below for how to modify your scripts
#  to let them use these functions.
#
# To help you test, you can type in channel from irc
#  !mctestbot some_extra_text_here_if_you_want
# This should evoke a response from the script, either
#  encrypted or not, depending on whether you typed
#  that encrypted or not.
#
# You can also broadcast a meow to the channel and this
#  script should reply.
#######################################################


#######################################################
# IMPORTANT SECURITY NOTICE!
# Please remember that giving your eggdrop bot the key
#  used on a channel can be a huge security risk if you
#  don't run your own shell, because it means the shell
#  owner will be able to examine your eggdrop files and
#  determine your channel key (Mircryption v2 will
#  make it easier to use alternate keys with bots to
#  reduce the risk).
#######################################################



#######################################################
# TO INSTALL THIS SCRIPT:
#
#   Modify the global passphrase configuration settings below
#    in this file (tcleggdrop_mcpsfuncs.tcl file), to set the
#    keys for the channels.  These keys are available to all
#    your scripts.
#
#   Modify the mcreplyonlyinkind, mcreplyneverplaintext,
#    and mcdontlistentoplaintext variables below to
#    configure how bot replies to plaintext commands.
#
#   Add this script (tcleggdrop_mcpsfuncs.tcl) to your eggdrop
#     configuration file; it must load *BEFORE* any other script.
#     that uses it(!).
#######################################################




#######################################################
# DIRECTIONS FOR MIRCRYPTIFYING YOUR EGGDROP SCRIPTS:
#
# Default Automagic Method:
#   If the mcautomagic variable is set to "true", and you make sure this
#    script is loaded before any other scripts in your eggdrop conf,
#    then it will automatically reroute all binds and putserv type messages
#    so that they will be able to understand encrypted messages and reply
#    with encrypted text, when appropriate to the channel.
#
# You can bypass encryption by using trueputquick trueputserv, etc.
#
########################################################


#######################################################
# DIRECTIONS FOR MIRCRYPTIFYING YOUR EGGDROP SCRIPTS:
#
# Alternative Manual Method:
# If you prefer to not have McEggdropTcl reroute your commands,
#  you can use this manual technique instead:
#
#1. Set the mcautomagic variable below to "false" to disable auto routing
#2. The following binds can be configured to work with encrypted incoming text:
#    bind msg <flags> <command> <proc>
#    bind pub <flags> <command> <proc>
#    bind msgm <flags> <mask> <proc>
#    bind pubm <flags> <mask> <proc>
#    bind notc <flags> <mask> <proc>
#    bind topc <flags> <mask> <proc>
#    bind ctcp <flags> <mask> <proc>   EXPERIMENTAL 11/18/04
#   For each of these binds in the script that you want
#    to work with encrypted incoming text, you can EITHER:
#      a) Change the word bind to mcbind
#      b) OR *add* a new statement with mcbinde instead of bind
#    When you use choose (a) the normal bind will be performed for you.
#    And if you *replace* bind with mcbinde, ONLY encrypted input will trigger.
#3. To have output encrypted when appropriate, change:
#    putserv to putservmc
#    putquick to putquickmc
#    puthelp to puthelpmc
#    putmsg to putmsgmc
#    putnotc to putnotcmc
#   These changes will make your script send encrypted output
#    if (and only if) the channel is configured to be encrypted
#   If you want certain replies to always been in plaintext, dont change them.
#4. There is no harm is setting mcautomagic to true even if you have some mcbind calls,
#    the mcbind and mcbinde bindings are still checked in automagic mode.
#######################################################



#######################################################
# IMPORTANT
# 11/17/04 - we found some people were using improper syntax for some putserv commands
#   that nevertheless worked on normal eggdrop but failed with mceggdrop:
# The proper syntax is like (note the use of the ':'):
#   putserv "PRIVMSG #chan :this is the message text"
# Without the ':' character (and a space before it), mceggdrop will not send it encrypted!!!
#######################################################



#######################################################
# OVERRIDING ENCRYPTION
# to override default encryption for a nick/chan, use "NOCRYPT" as the key for that nick/chan
# to override any encryption on output of any string, prefix output string with NOCRYPT or `
#######################################################



#######################################################
#DEFAULT maximum line length before splitting
# this should actually be set in the settings.ini file below
set mcmaxlinelen 275
#######################################################




#######################################################
# As of McEggdrop version 1.00.17 , all user settings are now kept in a separate file, so that you can
#  just replace upgrades to this file without disturbing your user configuration variables.
source scripts/tcleggdrop_mcps_sitesettings.ini
#######################################################








#######################################################
# user shouldnt have to change anything below here
#######################################################































#######################################################
# CAPTURING ENCRYPTED COMMANDS
bind pub - "mcps" mcpshandlepub
bind pub - "+OK" mcpshandlepubOK
bind msg - "mcps" mcpshandlemsg
bind msg - "+OK" mcpshandlemsgOK
bind notc - "mcps" mcpshandlenotc
bind notc - "+OK" mcpshandlenotcOK
bind topc - "% mcps *" mcpshandletopc
bind topc - "% +OK *" mcpshandletopcOK
#
#ATTN: DISABLED TILL I CAN CHECK THESE:
#bind ctcp - "mcps" mcpshandlectcp
#bind ctcp - "+OK" mcpshandlectcpOK
#bind chat - "mcps" mcpshandlechat
#bind chat - "+OK" mcpshandlechatOK
#bind dcc - "mcps" mcpshandledcc
#bind dcc - "+OK" mcpshandledccOK
#######################################################


#######################################################
# for keeping track of some stuff; what key was used
# on incoming textand whether user talking to us with
# mcps or +OK, and our list of special binds.
set mcbinds [list]
set incomingmckey ""
set incomingmcprefix ""
set dccidx ""
set dcckeyword ""
#######################################################


#######################################################
# we want mceggdrop to ignore strings with mircryption
#  style 2 (used for newsboard) encryption tags
set MCPS2_STARTTAG		"\xABm\xAB"
#######################################################


#######################################################
# replacement bind commands - used for manual rerouting
#  You can selectively use mcbind and mcbinde instead
#  regular bind command if you configure this script
#  to not automagically handle all binds.

proc mcbinde { table flags mask callback } { 
  # create an entry in our special mc bind table
  global mcbinds
  # add a 5 tuple containing [tablecommand flags mask proccallback]
  set mcbindentry [list $table $flags $mask 0 $callback]
  lappend mcbinds $mcbindentry
  # debugging
  # putlog "DEBUG mcbinde '$table' '$flags' '$mask' '$callback' mcbinds $mcbinds"
  return 0
}

proc mcbind { table flags mask callback } {
  # create an entry in our special mc bind table, AND create the normal bind
  #  this is useful because you can use it to do a bind and mcbinde with one command.
  global mcautomagic
  # create the original normal bind
  catch { eval bind $table $flags $mask $callback }
  if {$mcautomagic != "true"} {
    #invoke mcbinde to register the mcbind table entry (no point in doing this if we are automagically triggering on normal binds)
    mcbinde $table $flags $mask $callback
    }
  return 0
}
#######################################################





#######################################################
# Takeover putserv,etc. commmands if automagic=="true"

proc alias {name command} {
  # helper procedure for making easy aliases
  proc $name {args} "uplevel [list $command] \$args"
}

proc mcTakeoverPutCommands {} {
  # we can reroute all normal output commands if automagic == "true"
  global mcautomagic

  # dont take over if already taken over
  if { [info commands "_mcorig_putserv"] == "_mcorig_putserv" } {
   # restore to original
   rename putserv ""
   rename puthelp ""
   rename putquick ""
   if { [info commands "_mcorig_putmsg"] == "_mcorig_putmsg" } {
      rename putmsg ""
      rename _mcorig_putmsg putmsg
      }
   if { [info commands "_mcorig_putnotc"] == "_mcorig_putnotc" } {
      rename putnotc ""
      rename _mcorig_putnotc putnotc
      }
   rename _mcorig_putserv putserv
   rename _mcorig_puthelp puthelp
   rename _mcorig_putquick putquick
   }

  if {$mcautomagic == "true"} {
    # yes we should takeover put commands, first rename old ones
    rename putserv _mcorig_putserv 
    rename puthelp _mcorig_puthelp 
    rename putquick _mcorig_putquick 
    #now create our replacements
    alias putserv putservmc
    alias puthelp puthelpmc
    alias putquick putquickmc
    #for putmsg and putnotc which are not on all eggdrops
    if { [info commands "putmsg"] == "putmsg" || [info proc "putmsg"] == "putmsg"} {
      rename putmsg _mcorig_putmsg 
      alias putmsg putmsgmc
      }
    if { [info commands "putnotc"] == "putnotc" || [info proc "putnotc"] == "putnotc"} {
      rename putnotc _mcorig_putnotc
      alias putnotc putnotcmc
      }
    }
}

# Execute takeover if appropriate
mcTakeoverPutCommands
#######################################################







#######################################################
# TESTING COMMANDS WHICH CAN BE TRIGGERED BY ENC OR NORMAL
# !mctestbot is called with mcbind so it will always work
# !mctest2bot uses normal bind, so will only work
#  when mcautomagic is "true" and is good for testing it.
#  if you set mcreplyonlyinkind =="true" then this command
#  should reply in plaintext when triggered in plaintext,
#  and vice versa.
# !mctest3bot is useful for testing stackability of pubms
mcbind pub - "!mctestbot" mctestbot
bind pub - "!mctest2bot" mctest2bot
bind pubm -|- "* !mctest3bot" mctestbot
bind pubm -|- "* !mctest3bot" mctest2bot
#
# ATTN: new tests
bind msg -|- "!mctestbot" mctestbot_msg
bind notc -|- "!mctestbot" mctestbot_notc
bind dcc -|- "!mctestbot" mctestbot_dcc
bind chat -|- "!mctestbot" mctestbot_chat
#######################################################









#######################################################
# CAPTURING AND RE-ROUTING ENCRYPTED COMMANDS
proc mcpshandlepub {n uh h c t} {
  global incomingmcprefix
  # set prefix so we reply with same
  set incomingmcprefix "mcps"
  # now just invoke normal handler
  mcpshandlecommand "pub" $n $uh $h $c $t
}

proc mcpshandlepubOK {n uh h c t} {
  global incomingmcprefix
  # set prefix so we reply with same
  set incomingmcprefix "+OK"
  # now just invoke normal handler
  mcpshandlecommand "pub" $n $uh $h $c $t
}

proc mcpshandlemsg {n uh h t} {
  global incomingmcprefix
  set c $n
  # set prefix so we reply with same
  set incomingmcprefix "mcps"
  # now just invoke normal handler
  mcpshandlecommand "msg" $n $uh $h $c $t
}

proc mcpshandlemsgOK {n uh h t} {
  global incomingmcprefix
  set c $n
  # set prefix so we reply with same
  set incomingmcprefix "+OK"
  # now just invoke normal handler
  mcpshandlecommand "msg" $n $uh $h $c $t
}

proc mcpshandlenotc {n uh h t {c ""} } {
  global $botnick
  if {$c == ""} {set c $botnick }
  global incomingmcprefix
  # set prefix so we reply with same
  set incomingmcprefix "mcps"
  # now just invoke normal handler
  mcpshandlecommand "notc" $n $uh $h $c $t
}

proc mcpshandlenotcOK {n uh h t {c ""} } {
  global $botnick
  if {$c == ""} {set c $botnick }
  global incomingmcprefix
  # set prefix so we reply with same
  set incomingmcprefix "+OK"
  # now just invoke normal handler
  mcpshandlecommand "notc" $n $uh $h $c $t
}

proc mcpshandletopc {n uh h c t} {
  global incomingmcprefix
  # set prefix so we reply with same
  set incomingmcprefix "mcps"
  # remove encryption prefix from text [7/18/05]
  set t [join [lrange [split $t] 1 end]]
  # now just invoke normal handler
  mcpshandlecommand "topc" $n $uh $h $c $t
}

proc mcpshandletopcOK {n uh h c t} {
  global incomingmcprefix
  # set prefix so we reply with same
  set incomingmcprefix "+OK"
  # remove encryption prefix from text [7/18/05]
  set t [join [lrange [split $t] 1 end]]
  # now just invoke normal handler
  mcpshandlecommand "topc" $n $uh $h $c $t
}

proc mcpshandlectcp {n uh h c k t} {
  global incomingmcprefix
  global dcckeyword
  set dcckeyword $k
  # set prefix so we reply with same
  set incomingmcprefix "mcps"
  # now just invoke normal handler
  mcpshandlecommand "ctcp" $n $uh $h $c $k $t
}

proc mcpshandlectcpOK {n uh h c k t} {
  global incomingmcprefix
  global dcckeyword
  set dcckeyword $k
  # set prefix so we reply with same
  set incomingmcprefix "+OK"
  # now just invoke normal handler
  mcpshandlecommand "ctcp" $n $uh $h $c $k $t
}


proc mcpshandlechat {h c t} {
  global incomingmcprefix
  set n $c
  set uh $h
  # set prefix so we reply with same
  set incomingmcprefix "mcps"
  # now just invoke normal handler
  mcpshandlecommand "chat" $n $uh $h $c $t
}

proc mcpshandlechatOK {h c t} {
  global incomingmcprefix
  set n $c
  set uh $h
  # set prefix so we reply with same
  set incomingmcprefix "+OK"
  # now just invoke normal handler
  mcpshandlecommand "chat" $n $uh $h $c $t
}


proc mcpshandledcc {h i t} {
  global incomingmcprefix
  global dccidx
  set c $i
  set n $c
  set uh $h
  set dccidx $i
  # set prefix so we reply with same
  set incomingmcprefix "mcps"
  # now just invoke normal handler
  mcpshandlecommand "chat" $n $uh $h $c $t
}

proc mcpshandledccOK {h i t} {
  global incomingmcprefix
  global dccidx
  set c $i
  set n $c
  set uh $h
  set dccidx $i
  # set prefix so we reply with same
  set incomingmcprefix "+OK"
  # now just invoke normal handler
  mcpshandlecommand "chat" $n $uh $h $c $t
}
#######################################################



#######################################################
proc mcpshandlecommand {comtype n uh h c t} {
 #this command is meant to detect any encrypted commands
 # and route them to their appropriate place. it is
 # called on any lines begining with mcps
 global incomingmckey
 global mcautomagic
 set triggercount 0

 #putlog "DEBUG in mcpshandlecommand: $comtype $n $uh $h $c $t"
 
 #lowercase channelname
 set c [string tolower $c]

 # clear incomingmckey
 set incomingmckey ""

 # blank just return
 if {$t == ""} {
   # this is not an error, just blank line
   mcfixupglobalsonexit
   return
   }

 


 # ------------------------------------------- 
 #if it has prefix then decrypt 

 #check for mircryption meow handshake
 set meowcheck [lrange $t 0 1]
 if {$meowcheck == "meow meow"} {
   ReceiveMeow $n $uh $h $c $t
   mcfixupglobalsonexit
   return
   }

 # we would like to remember incomingmckey to the keyname of key that decrypted it
 set incomingmckey $c

 # try to decrypt presumably encrypted text
 set origt $t
 set t [mcpsdecrypt $c "mcps $t"]
 set firstword {lindex $t 0}
 set remainderwords {lrange $t 1 end}

 # was it decrypted? if not return with no response (ATTN: should we complain to user?)
 if {$t == ""} {
   # this is not an error, just blank line
   mcfixupglobalsonexit
   return
   }

 if {$t == $origt} {
   # bot could not understand what user said.
   # trueputserv "PRIVMSG $n :Error, couldn't find a mircryption key to decrypt your command."
   # Correction: this is not an error if there is no key for this channel
   mcfixupglobalsonexit
   return
   }
 # ------------------------------------------- 
 
 
 
 
 # ------------------------------------------- 
 # if its NOT prefix encrypted, then we decide whether we want to block it
 # ------------------------------------------- 


 # now run all appropriate binds
 incr triggercount [ mcpsrunbinds $comtype $n $uh $h $c $t ]

 # clear incomingkey global variable
 mcfixupglobalsonexit
 return 0
}


proc mcpsrunbinds {comtype n uh h c t} {
 # execute the appropriate binds
 global mcautomagic
 set triggercount 0
  
 # first try matching an exact match for the bind (this will be a pub,msg,notc,topc,ctcp,etc)
 set bindfilter $comtype

 # Iterate through any spcial stored mcbind list and when we find a matching bind, trigger it
 incr triggercount [ stdrag_triggermcbinds $comtype $bindfilter $n $uh $h $c $t ]
 # does user want us to invoke ALL NORMAL registered binds (this is the default)
 if {$mcautomagic == "true"} {
   incr triggercount [ stdrag_triggerbinds $comtype $bindfilter $n $uh $h $c $t ]
   }
  
 #Now if there were no matches, and this is a pub or msg, then we try the pubm versions
 if {$triggercount == 0} {
   if {$comtype == "pub" || $comtype =="msg"} {
     if {$comtype == "pub"} { set bindfilter "pubm" }
     if {$comtype == "msg"} { set bindfilter "msgm" }

     # Iterate through any spcial stored mcbind list and when we find a matching bind, trigger it
     incr triggercount [ stdrag_triggermcbinds $comtype $bindfilter $n $uh $h $c $t ]
     # does user want us to invoke ALL NORMAL registered binds (this is the default)
     if {$mcautomagic == "true"} {
       incr triggercount [ stdrag_triggerbinds $comtype $bindfilter $n $uh $h $c $t ]
       } 
     }
   }
 # return total number of binds performed
 return $triggercount
 }


proc mcfixupglobalsonexit {} {
  # we reset our global persistent variables (easier than reseting them on each invocation) before finishing
  #  processing an encrypted command, so that they start initialized before each text trigger
  global incomingmckey
  global incomingmcprefix
  set incomingmckey ""
  set incomingmcprefix ""
}
#######################################################










#######################################################
# STDRAGON FUNCTIONS - for iterating through binds to manually trigger them
# http://forum.egghelp.org/viewtopic.php?p=31744#31744

proc stdrag_triggerbinds { comtype bindfilter nick uhost hand chan text } { 
  # this procedure iterates through all registered binds, and manually triggers those that match
  # note it will only run the first matching pub or msg (since they are not stackable)
  # returns a count of the number of triggers executed

  # debugging
  #putlog "DEBUG in triggerbinds: $comtype $nick $uhost $hand $chan $text"
    
  # walk through all binds and look for matches
  set triggercount 0
  foreach abind [binds $bindfilter] { 
    # grab the the elements from current bind table entry
    foreach {table flags mask hits callback} $abind {
      set bindresult [stdrag_trybind $comtype $nick $uhost $hand $chan $text $table $flags $mask $hits $callback]
      if {$bindresult != 0} {
        incr triggercount 1
        # we stop iterating when we hit a matching pub or msg (but not if we hit a pubm or msgm, which are stackable)
        if {$table == "pub" || $table == "msg" } { break }
        }
      }
    }
  return $triggercount
}


proc stdrag_triggermcbinds { comtype bindfilter nick uhost hand chan text } { 
  # this procedure iterates through all special mcbinds, and manually triggers those that match
  # returns a count of the number of triggers executed
  global mcbinds
 
  # debugging
  # putlog "DEBUG in triggermcbinds: $comtype $nick $uhost $hand $chan $text"
    
  # walk through all binds and look for matches
  set triggercount 0
  for {set i 0} {$i < [llength $mcbinds]} {incr i} {
    set abind [lindex $mcbinds $i]
    # grab the the elements from current bind table entry
    # putlog "DEBUG mcbindentry is $abind"
    foreach {table flags mask hits callback} $abind {
      # skip any that dont match filter
      if {$bindfilter != "all" && $bindfilter != $table} { continue }
      set bindresult [stdrag_trybind $comtype $nick $uhost $hand $chan $text $table $flags $mask $hits $callback]
      if {$bindresult != 0} {
        incr triggercount 1
        # increase the binds hit counter
        set abind [lreplace $abind 3 3 [incr hits]]
        set mcbinds [lreplace $mcbinds $i $i $abind]
        # we stop iterating when we hit a matching pub or msg (but not if we hit a pubm or msgm, which are stackable)
        if {$table == "pub" || $table == "msg" } { break }
        }
      }
    }
  return $triggercount
}


proc stdrag_trybind { comtype nick uhost hand chan text table flags mask hits callback} { 
  # this procedure iterates through all registered binds, and manually triggers those that match
  # returns 1 if the trigger was executed, or 0 if not

  # debugging
  # putlog "DEBUG checking against: '$table' , '$flags' , '$mask' , '$hits' , '$callback'"

  # dont retrigger ourselves!
  if {$mask == "mcps" || $mask =="+OK"} { return 0 }

  # debugging
  # putlog "DEBUG at stage 0"

  # check if this is one of the kinds of binds we handle (ATTN: check case), if not continue to next entry
  if {$table != "pub" && $table != "pubm" && $table != "msg" && $table != "notc" && $table != "topc"} { return 0 }
  
  #ATTN: replace above with this when testing dcc, chat, ctcp stuff
  #if {$table != "pub" && $table != "pubm" && $table != "msg" && $table != "notc" && $table != "topc" && $table != "ctcp" && $table != "dcc" && $table != "chat"} { return 0 }

  # debugging
  # putlog "DEBUG at stage 1"

  # check if this is the kind of bind we want to match based on comtype; if they are equal its good
  set commandmatch 0
  if {$comtype == $table} { set commandmatch 1 }
  if {$comtype == "pub" && $table == "pubm"} { set commandmatch 1 }
  if {$comtype == "pubm" && $table == "pub"} { set commandmatch 1 }
  if {$comtype == "msg" && $table == "msgm"} { set commandmatch 1 }
  if {$comtype == "msgm" && $table == "msg"} { set commandmatch 1 }
  # if its not compatible, continue to next table entry
  if {$commandmatch == 0} { return 0 }

  # debugging
  # putlog "DEBUG at stage 2"

  # check the flags of the channel if it doesnt match, continue to next bind
  # ATTN: is 'string equal' incompatible? should we use 'string compare' instead?
  # if {![string equal "-|-" $flags] && ![matchattr $hand $flags $chan]} { return 0 } 
  # if {[string compare "-|-" $flags] && ![matchattr $hand $flags $chan]} { return 0 } 
  if {[string compare "-|-" $flags] && [string compare "-" $flags] && ![matchattr $hand $flags $chan]} { return 0 } 

  # now convert the bind mask to a regexp in preparation for comparing it to text
  set cmask [stdrag_bind_mask_to_regexp $table $mask]

  # debugging
  # putlog "DEBUG at stage 3 with converted table = $table mask = $mask and converted mask = $cmask  and text = $text"

  # compare the mask against chan .+ text if its pubm, or again text otherwise
  if {$table == "pubm"} {
       if {![regexp -nocase -- $cmask "$chan $text"]} {
         # putlog "DEBUG cmask did not match '$chan $text'"
         return 0
       }
   } elseif {$table == "topc"} {
       if {![regexp -nocase -- $cmask "$chan $text"]} {
         return 0
       }
   } elseif {$table == "msgm"} {
       if {![regexp -nocase -- $cmask "$text"]} {
         return 0
       }
   } else {
       if {![regexp -nocase -- $cmask $text]} {
       return 0
       }
   }

  # debugging
  # putlog "DEBUG at stage 4 with converted table = $table mask = $mask and converted mask = $cmask  and text = $text"

  
  # do NOT catch our plaintext blockers
  if {$callback == "mcpub_blocker"} { return 0 }
  if {$callback == "mcdcc_blocker"} { return 0 }
  if {$callback == "mcmsg_blocker"} { return 0 }
  if {$callback == "mcnotc_blocker"} { return 0 }
  if {$callback == "mctopc_blocker"} { return 0 }
  if {$callback == "mcctcp_blocker"} { return 0 }
  if {$callback == "mcchat_blocker"} { return 0 }

  # update the global lastbind variable with the mask of the current bind  [7/18/05]
  set olastbind $::lastbind
  set ::lastbind $mask

  # ok we got a matching bind we want to retrigger, so call it
  if {$table == "pub"} {
      # these commands dont want the initial trigger mask(command)
      set startpos [string length $mask]
      incr startpos
      set remaindertext [string range $text $startpos end]
      eval $callback [list $nick $uhost $hand $chan $remaindertext]
    } elseif {$table == "msg"} {
      # these commands dont want the initial trigger mask(command)
      set startpos [string length $mask]
      incr startpos
      set remaindertext [string range $text $startpos end]
      eval $callback [list $nick $uhost $hand $remaindertext]
    } elseif {$table == "pubm"} {
      eval $callback [list $nick $uhost $hand $chan $text]
    } elseif {$table == "msgm"} {
      eval $callback [list $nick $uhost $hand $text]
    } elseif {$table =="notc"} {
      eval $callback [list $nick $uhost $hand $text $chan]
    } elseif {$table =="ctcp"} {
      #ATTN: UNTESTED
      global dcckeyword
      eval $callback [list $nick $uhost $hand $chan $dcckeyword $text]
    } elseif {$table =="chat"} {
      #ATTN: UNTESTED
      eval $callback [list $hand $chan $text]
    } elseif {$table =="dcc"} {
      #ATTN: UNTESTED
      #eval $callback [list $hand $dccidx $text]
    } else {
      eval $callback [list $nick $uhost $hand $chan $text]
    }

  set ::lastbind $olastbind

  # debugging
  # putlog "DEBUG at stage 5 - done with bind"
  return 1
} 


proc stdrag_bind_mask_to_regexp {table mask} { 
  # helper function to convert an eggdrop bind text mask into a regular expression pattern
  # OLD: regsub -all {\.|\(|\+|\^|\$|\\|\[|\|} $mask {\\&} mask 
  regsub -all {\.|\(|\)|\+|\^|\$|\\|\[|\|} $mask {\\&} mask
  regsub -all "\{" $mask {\\&} mask 
  regsub -all {\*} $mask {.*} mask 
  regsub -all {\?} $mask {.} mask 
  regsub -all {\%} $mask {[^\s]*} mask 
  regsub -all {~} $mask {[\s]+} mask 
  if {$table == "pub" || $table == "msg"} {
      #pub and msg binds only need to match start of text
      #ATTN: should this be \\s* instead of \\s+  ?
      return "^$mask\(\\s+.*\)?\$"
    } else {
    return "^$mask\$" 
    }
} 
#######################################################






#######################################################
proc encryptout {callcommand prefixkeyword dest inmsg {callcommandargs {}}} {
  # this is the generic encrypt+output command
  # it will also split long lines
  #
  # some callcommands such as "putserv" allow options "-next" as argument
  # after the output text. these can be given as a list in callcommandargs
  # and will be passed to the callcommand:
  #    callcommand text callcommandargs
  global mcmaxlinelen
  # we want to loop and split msg if it is too long
  set maxlinelen $mcmaxlinelen


  #putlog "DEBUG encryptout comes in with ='$inmsg'"

  while {$inmsg!=""} {
    # pick section of inmsg to display
    set len [ string length $inmsg ]

    # if it's short enough then just display it and we are done or
    # if text is already encrypted then we dont try to split
    if {$len<$maxlinelen || [string match "mcps *" $inmsg] || [string match "*«m«*" $inmsg] || [string match "\x96*" $inmsg] } {
      set msg $inmsg
      # remove it from inmsg
      set inmsg ""
      } else {
      # it's too long, so we must split it. start at maxlinelen, and then shorten to word boundry if possible
      set splitpos $maxlinelen
      while {$splitpos > 0} {
        set charatsplit [ string index $inmsg $splitpos ]
        if {$charatsplit == " " || $charatsplit == "," || $charatsplit == "." || $charatsplit == ";" || $charatsplit == "\t" || $charatsplit == "-" } { break }
        set splitpos [expr $splitpos - 1 ]
        }
      # if we couldnt find a better place to split then split at maxlinelen
      if {$splitpos<=0} { set splitpos $maxlinelen }
      # grab left to display
      set msg [ string range $inmsg 0 $splitpos ]
      set splitpos [expr $splitpos + 1 ]
      # advance over any whitespace we split on
      while {$splitpos <= $maxlinelen} {
        set charatsplit [ string index $inmsg $splitpos ]
        if {$charatsplit != " " && $charatsplit != "\t"} { break }
        set splitpos [expr $splitpos + 1 ]
        }
      set inmsg [ string range $inmsg $splitpos end ]
      }

    #putlog "DEBUG encryptout output ='$msg'"

    # encrypt text
    set newmsg [ mcpsencrypt $dest $msg ]
    #now send the rebuilt string
    if { $newmsg != "" } {
      set newtext "$prefixkeyword $dest :$newmsg"
      #now invoke it
      #putlog "DEBUG in encryptout command='$callcommand'  prefix='$prefixkeyword'  dest='$dest'  inmsg='$inmsg'  newmsg='$newmsg'  newtext='$newtext' callcommandargs='$callcommandargs'"
      eval $callcommand [list $newtext] $callcommandargs
      }
    } 
  }
#######################################################






#######################################################
# here are the replaement output functions - just call these instead of putserv, puthelp, putquick
# and your outgoing text will be encyrpted if a key exists for the channel, as described above.
proc putservmc {args} {
  set putlinetext [lindex $args 0]
  set putlineargs [lrange $args 1 end]
  # find the ':' which separates stuff like "NOTICE CHAN: HERE IS MY TEXT"
  set searchc ":"
  set colonpos [ string first $searchc $putlinetext ]
  if {$colonpos == -1 || $colonpos == 0} {
    # some raw commands to irc dont have : and they should be sent unencrypted
    eval trueputserv [list $putlinetext] $putlineargs
    return
    }
  # grab the initial 'PRIVMSG CHAN :'
  set partone [ string range $putlinetext 0 [expr $colonpos - 1 ] ]
  set partone [ split $partone " " ]
  # split into 'PRIVMSG'
  set prefixkeyword [lindex $partone 0]
  # and split into 'CHAN'
  set dest [lindex $partone 1]
  #now grab the actual text
  set msg [ string range $putlinetext [ expr $colonpos + 1 ] end ]
  # NEW REPLACEMENT
  encryptout trueputserv $prefixkeyword $dest $msg $putlineargs
  # encrypt it
  set newmsg [ mcpsencrypt $dest $msg ]
  #now send the rebuilt string
  if { $newmsg != "" } {
    set newtext "$prefixkeyword $dest :$newmsg"
    #trueputserv $newtext
    }
  }

proc puthelpmc {args} {
  set putlinetext [lindex $args 0]
  set putlineargs [lrange $args 1 end]
  # find the ':' which separates stuff like "NOTICE CHAN: HERE IS MY TEXT"
  set searchc ":"
  set colonpos [ string first $searchc $putlinetext ]
  if {$colonpos == -1 || $colonpos == 0} {
    # some raw commands to irc dont have : and they should be sent unencrypted
    eval trueputhelp [list $putlinetext] $putlineargs
    return
    }
  # grab the initial 'PRIVMSG CHAN :'
  set partone [ string range $putlinetext 0 [expr $colonpos - 1 ] ]
  set partone [ split $partone " " ]
  # split into 'PRIVMSG'
  set prefixkeyword [lindex $partone 0]
  # and split into 'CHAN'
  set dest [lindex $partone 1]
  #now grab the actual tyext
  set msg [ string range $putlinetext [ expr $colonpos + 1 ] end ]
  # NEW REPLACEMENT
  encryptout trueputhelp $prefixkeyword $dest $msg $putlineargs
  # encrypt it
  set newmsg [ mcpsencrypt $dest $msg ]
  #now send the rebuilt string
  if { $newmsg != "" } {
    set newtext "$prefixkeyword $dest :$newmsg"
    #trueputhelp $newtext
    }
  }

proc putquickmc {args} {
  set putlinetext [lindex $args 0]
  set putlineargs [lrange $args 1 end]
  # find the ':' which separates stuff like "NOTICE CHAN: HERE IS MY TEXT"
  # putlog "DEBUG in putquickmc $putlinetext"
  set searchc ":"
  set colonpos [ string first $searchc $putlinetext ]
  if {$colonpos == -1 || $colonpos == 0} {
    # some raw commands to irc dont have : and they should be sent unencrypted
    eval trueputquick [list $putlinetext] $putlineargs
    return
    }
  # grab the initial 'PRIVMSG CHAN'
  set partone [ string range $putlinetext 0 [expr $colonpos - 1 ] ]
  set partone [ split $partone " " ]
  # split into 'PRIVMSG'
  set prefixkeyword [lindex $partone 0]
  # and split into 'CHAN'
  set dest [lindex $partone 1]
  #now grab the actual tyext
  set msg [ string range $putlinetext [ expr $colonpos + 1 ] end ]
  # NEW REPLACEMENT
  encryptout trueputquick $prefixkeyword $dest $msg $putlineargs
  # encrypt it
  set newmsg [ mcpsencrypt $dest $msg ]
  #now send the rebuilt string
  if { $newmsg != "" } {
    set newtext "$prefixkeyword $dest :$newmsg"
    #trueputquick $newtext
    }
  }

proc putmsgmc {dest msg} {
  # send mesg
  set prefixkeyword "PRIVMSG"
  # NEW REPLACEMENT
  encryptout trueputhelp $prefixkeyword $dest $msg
  # encrypt it
  set newmsg [ mcpsencrypt $dest $msg ]
  #now send the rebuilt string
  if { $newmsg != "" } {
    set newtext "$prefixkeyword $dest :$newmsg"
    #trueputmsg dest $newtext
    }
  }

proc putnotcmc {dest msg} {
  # send mesg
  set prefixkeyword "NOTICE"
  # NEW REPLACEMENT
  encryptout trueputhelp $prefixkeyword $dest $msg
  # encrypt it
  set newmsg [ mcpsencrypt $dest $msg ]
  #now send the rebuilt string
  if { $newmsg != "" } {
    set newtext "$prefixkeyword $dest :$newmsg"
    #trueputnotc dest $newtext
    }
  }
#######################################################



#######################################################
# These call the appropriate plaintext put command depending on whether we are rerouting them automagically
proc trueputserv {args} {
  global mcautomagic
  if {$mcautomagic != "true"} { eval putserv $args } else { eval _mcorig_putserv $args }
  }

proc trueputhelp {args} {
  global mcautomagic
  if {$mcautomagic != "true"} { eval puthelp $args } else { eval _mcorig_puthelp $args }
  }

proc trueputquick {args} {
  global mcautomagic
  if {$mcautomagic != "true"} { eval putquick $args } else { eval _mcorig_putquick $args }
  }

proc trueputmsg {dest msg} {
  global mcautomagic
  if {$mcautomagic != "true"} { putmsg $dest $msg } else { _mcorig_putmsg $dest $msg }
  }

proc trueputnotc {dest msg} {
  global mcautomagic
  if {$mcautomagic != "true"} { putnotc $dest $msg } else { _mcorig_putnotc $dest $msg }
  }
#######################################################



#######################################################
proc mcpsdecrypt {c t} {
 # mcpsdecrypt (channelname text..)
 #  this will return the DECRYPTED version of text IFF it begins with mcps and IF a channel key is defined in mcpskey(channelname) or normal text if not
 #give ourselves access to mcpskey global
 global mcpskey

 #lowercase channelname
 set c [string tolower $c]

 #grab first word
 set firstword [lindex $t 0]
 if {$firstword == "mcps" || $firstword == "+OK"} {
  # first word is mcps so its encrypted, so set t to everything after the mcps
  set t [lrange $t 1 end]
  # now find the key to use
  set chankey ""
  if {[info exists mcpskey(defaultd)] != 0} { set chankey $mcpskey(defaultd) }
  if {[info exists mcpskey($c)] != 0} { set chankey $mcpskey($c) }

  # now decrypt using the key
  if {$chankey != ""} {
    # new cbc style encryption and decryption
    if {[string match {cbc[:;]*} $chankey]} {
      # cbc decrpyt
      # we should first check if cbc_decrypt function exists
      if {[info commands cbc_decrypt] == [list]} { return "error, cbc_decrypt function script not installed, $t" }
      set chankeyfixed [string range $chankey 4 end]
      # strip off the leading *
      set t [string range $t 1 end]
      # now decrypt
      set t [cbc_decrypt $chankeyfixed $t]
      } else {
      # normal ocb decrypt
      set t [decrypt $chankey $t] 
      }
   }
  }
 return $t
}

proc mcpsencrypt {c t} {
  # mcpsencrypt (channelname text..)
  #  this will return the ENCRYPTED version of text (with mcps prepended) IFF a key is set for the channel or normal text if not
  #give ourselves access to mcpskey global
  global mcpskey
  global mcpsprefix
  global incomingmckey
  global incomingmcprefix
  global mcreplyonlyinkind
  global mcreplyneverplaintext
  global mcdontlistentoplaintext
  global lastbind
  global mcencryptnick

  #lowercase channelname
  set c [string tolower $c]
 
  #ctcp stuff (pings, version, etc) don't get encrypted
  set firstchar [string index $t 0]
  if { $firstchar == "\001" } { return $t }
 
  #check if we should be blocking reply to a plaintext command
  if {$incomingmcprefix == ""} {
     if {$mcdontlistentoplaintext == "true"} {
        set t "eggdrop reply blocked since command was issued in plaintext; this bot only responds to encrypted commands."
        return $t
        }
     if {$mcdontlistentoplaintext == "silent"} {
        set t ""
        return $t
        }
   } 


  # new 2/20/06  
  # skip strings prefixed with NOCRYPT
  if {[string match {NOCRYPT*} $t]} {
      set t [string range $t 7 end]
      return $t
   }

  # now find the key to use - this ONLY works with channel keys and does NOT use default key
  set chankey ""

  # if text is already encrypted then we dont try to re-encrypt
  if {[string match "mcps *" $t]} { return $t }
  if {[string match "*«m«*" $t]} { return $t }

  # plaintext escape
  #if {[string match "`*" $t]} { return $t }
  if {[string match "`*" $t]} { return [string range $t 1 end] }

  # based on lastbind we determine if this output is a response to a user or not
  #  the idea is that some events like timers will cause a script to send some output
  #  to the channel/user, and in such cases, we dont want the script to think it is replying
  #  to a plaintext request, so it needs to differentiate output generated by user text from other.
  set triggeredbytext "false"
  # putlog "..DEBUG encrypting $t with triggeredbytext = $triggeredbytext and lastbind = $lastbind"
  if {$lastbind == "PRIVMSG" || $lastbind == "rehash"} {
      # seems timer based events have lastbind = "PRIVMSG" | "rehash" ?
      set triggeredbytext "false"
    } elseif {$lastbind == "mcps"} {
      set triggeredbytext "true"
    } elseif {$lastbind == "+OK"} {
      set triggeredbytext "true"
    } else {
      # seems that timers and other events have lastbin = "PRIVMSG"
      set triggeredbytext "true"
    }


  # option to only reply encrypted if we received encrypted? (note we check triggeredbytext to see if this output is in response to user)
  if {$triggeredbytext == "true" && $incomingmckey == "" && $mcreplyonlyinkind == "true" && $mcreplyneverplaintext != "true"} { return $t }



  # ATTN: temporary fix to ignore incomingmckey until we figure out a proper way to clear it on each message
  set incomingmckey ""



  # if this is to a nick and mcencryptnick is "never" then we never encrypt it
  set firstcharc [ string index $c 0 ]
  if {$mcencryptnick == "never" && $firstcharc != "#"} {
    # ok this text does not go to a nick so we return without encrypting
    return $t;
    }

  # determine key for this output
  if {[info exists mcpskey($c)] != 0} { set chankey $mcpskey($c) }
  # if this is to a nick and mcencryptnick is "false" then *unless we have a specific key for nick* we dont encrypt it
  if {$mcencryptnick == "false" && $firstcharc != "#" && $chankey == ""} {
    # ok this text does not go to a nick so we return without encrypting
    return $t;
    }

  if {$chankey == ""} { 
    if {[info exists mcpskey($incomingmckey)] != 0} { set chankey $mcpskey($incomingmckey) }
    }
  if {$chankey == ""} {
    if {[info exists mcpskey(defaulte)] != 0} { set chankey $mcpskey(defaulte) }
    }

  # set outgoing prefix
  if {$incomingmcprefix != ""} {
      set outgoingprefix $incomingmcprefix
    } else {
      if {[info exists mcpsprefix($c)] != 0} { set outgoingprefix $mcpsprefix($c) } else { set outgoingprefix $mcpsprefix(defaultprefix) }
    }

  # skip encryption if key is a specific value "NOCRYPT"
  if {$chankey == "NOCRYPT"} { return $t }


  # now encrypt using the key
  if {$chankey != ""} {
    # new cbc style encryption and decryption
    if {[string match {cbc[:;]*} $chankey]} {
      # cbc encrypt
      # we should first check if cbc_decrypt function exists
      if {[info commands cbc_decrypt] == [list]} { return "error, cbc_encrypt function script not installed, text not encrypted." }
      set chankeyfixed [string range $chankey 4 end]
      set t [cbc_encrypt $chankeyfixed $t]
      set t "$outgoingprefix *$t"
      } else {
      # normal ocb encrypt
      set t [encrypt $chankey $t]
      set t "$outgoingprefix $t"
      }

   return $t
  }

 if {$mcreplyneverplaintext == "true"} {set t "eggdrop reply blocked since no key could be found for '$c'; add a key for that target, or a default key, or set mcreplyneverplaintext to false." }
 return $t
}
#######################################################









#######################################################
#TEST FUNCTIONS THAT CAN BE TRIGGERED WITH CRYPTED OR NORMAL COMMAND
# useful for teting if the script it set up properly.

proc mctestbot {nick uhost hand chan arg} {
  # this command should be triggered if the person types !mctestbot either crypted or noncrypted
  #  and it should replay crypted if a key is set for chan
# updated 08/24/04 by mouser - removed test functions encrypting of arbitrary text for fear it would help a chosen plaintext attack
#  putservmc "PRIVMSG $chan :mctestbot chan reply; received this text -> $arg"
#  putservmc "PRIVMSG $nick :mctestbot pm reply; received this text -> $arg"
  putservmc "PRIVMSG $chan :mctestbot chan reply; received some text"
  putservmc "PRIVMSG $nick :mctestbot pm reply; received some text"
  putlog "Received mctestbot command from $nick $chan";
  return 0
}

proc mctest2bot {nick uhost hand chan arg} {
  # this command should be triggered if the person types !mctestbot2 either crypted or noncrypted
  #  and it should replay crypted if a key is set for chan IFF mcautomagic is set "true"
  # See that the normal putserv is used, so reply will ONLY be crypt if mcautomagic == "true"
# updated 08/24/04 by mouser - removed test functions encrypting of arbitrary text for fear it would help a chosen plaintext attack
#  putserv "PRIVMSG $chan :mctest2bot chan reply; received this text -> $arg"
#  putserv "PRIVMSG $nick :mctest2bot pm reply; received this text -> $arg"
  putserv "PRIVMSG $chan :mctest2bot chan reply; received some text"
  putserv "PRIVMSG $nick :mctest2bot pm reply; received some text"
  putlog "Received mctest2bot command from $nick $chan";
  return 0
}


proc mctestbot_msg {nick uhost hand arg} {
  # this command should be triggered if the person types !mctestbot either crypted or noncrypted
  # updated 08/24/04 by mouser - removed test functions encrypting of arbitrary text for fear it would help a chosen plaintext attack
  #putservmc "PRIVMSG $nick :mctestbot pm reply; received some text through a MSG NOTICE: $arg"
  putservmc "PRIVMSG $nick :mctestbot pm reply; received some text through a MSG NOTICE."
  putlog "Received mctestbot_msg command from $nick";
  return 0
}

proc mctestbot_notc {nick uhost hand arg chan} {
  # this command should be triggered if the person types !mctestbot either crypted or noncrypted
# updated 08/24/04 by mouser - removed test functions encrypting of arbitrary text for fear it would help a chosen plaintext attack
#  putservmc "PRIVMSG $nick :mctestbot pm reply; received some text through a NOTC NOTICE: $arg"
  putservmc "PRIVMSG $nick :mctestbot pm reply; received some text through a NOTC NOTICE."
  putlog "Received mctestbot_notc command from $nick";
  return 0
}

proc mctestbot_dcc {hand idx text} {
  # this command should be triggered if the person types !mctestbot either crypted or noncrypted
# updated 08/24/04 by mouser - removed test functions encrypting of arbitrary text for fear it would help a chosen plaintext attack
  #putlog "Received dcc mctestbot: $text"
  putlog "Received mctestbot_dcc command from $idx,$hand,$text";
  return 0
}

proc mctestbot_chat {hand chan text} {
  # this command should be triggered if the person types !mctestbot either crypted or noncrypted
# updated 08/24/04 by mouser - removed test functions encrypting of arbitrary text for fear it would help a chosen plaintext attack
  #putservmc "PRIVMSG $chan :mctestbot chan CHAT reply: $text"
  putservmc "PRIVMSG $chan :mctestbot chan CHAT reply."
  putlog "Received mctestbot_chat command from $chan";
  return 0
}
#######################################################






#######################################################
proc getmcinfostring {stylemode} {
  # friendly function for making a string about variables info, useful for showing on load and meow
  # call with "brief" or "verbose"
  global mcreplyonlyinkind
  global mcreplyneverplaintext
  global mcdontlistentoplaintext
  global mcmeowreply
  global mcautomagic
  set mcinfostring ""

  if {$stylemode == "verbose" } {
      # verbose style
      if {$mcreplyonlyinkind == "true"} { set mcinfostring "replyinkind" } else { set mcinfostring "replyencrypt" }
      if {$mcreplyneverplaintext == "true"} { set mcinfostring "$mcinfostring noplainreply" }
      if {$mcmeowreply == "true"} { set mcinfostring "$mcinfostring meowreply" } else { set mcinfostring "$mcinfostring nomeows" }
      if {$mcautomagic == "true"} { set mcinfostring "$mcinfostring automagicon" } else { set mcinfostring "$mcinfostring automagicoff" }
      if {$mcdontlistentoplaintext == "true"} { set mcinfostring "$mcinfostring noplainlisten" }
      if {$mcdontlistentoplaintext == "silent"} { set mcinfostring "$mcinfostring noplainlistensilent" }
    } else {
      #brief style for l33t peeps
      if {$mcreplyonlyinkind == "true"} { set mcinfostring "rk" } else { set mcinfostring "re" }
      if {$mcreplyneverplaintext == "true"} { set mcinfostring "$mcinfostring np" }
      if {$mcmeowreply == "true"} { set mcinfostring "$mcinfostring mr" } else { set mcinfostring "$mcinfostring nm" }
      if {$mcautomagic == "true"} { set mcinfostring "$mcinfostring aon" } else { set mcinfostring "$mcinfostring aoff" }
      if {$mcdontlistentoplaintext == "true"} { set mcinfostring "$mcinfostring npl" }
      if {$mcdontlistentoplaintext == "silent"} { set mcinfostring "$mcinfostring npls" }
      }
  
  return $mcinfostring
}
#######################################################


#######################################################
# Fun procedure to let the script respond to meow broadcasts in mircryption
proc ReceiveMeow {n uh h c t} {
  global mcpskey
  global incomingmckey
  global incomingmcprefix
  global mcreplyonlyinkind
  global mcreplyneverplaintext
  global mcmeowreply
  global mceggdropversion
  set targnick [lindex $t 2]
  set teststring [lrange $t 4 end]
  set estatus "active"

  #lowercase channelname
  set c [string tolower $c]
 
  # script user can disable meows
  if {$mcmeowreply == "false"} { return }

  # script user can disable reply of crypt agreement
  if {$mcmeowreply != "nostatus"} {
    # now find the key to use - this ONLY works with channel keys and does NOT use default key
    set chankey ""

    if {[info exists mcpskey($c)] != 0} { set chankey $mcpskey($c) }
    if {$chankey == ""} { 
      if {[info exists mcpskey($incomingmckey)] != 0} { set chankey $mcpskey($incomingmckey) }
      }
    if {$chankey == ""} {
      if {[info exists mcpskey(defaultd)] != 0} { set chankey $mcpskey(defaultd) }
      }
    if {$chankey != ""} {
      # now see if meow key was decrypted by us correctly, if so we know we have same key as sender
      set decryptedstring [decrypt $chankey $teststring]
      if {$decryptedstring == "meow"} { set estatus "crypting (key match)" }
      if {$decryptedstring != "meow"} { set estatus "crypting (key mismatch)" }
      }
    if {$chankey == ""} { set estatus "no encryption key for this channel" }
    }

  set mcinfostring [ getmcinfostring "brief" ]
  trueputserv "NOTICE $n :mcps meow meowreply $targnick $c \[$mceggdropversion\] McEggdrop -> $estatus - \[$mcinfostring\]"
}
#######################################################











# Heidel 7/18/05 - let owners list available binds
#######################################################
# Owners can list all registered mc binds via .mcbinds
# in the bots partyline.
proc dcc_mcbinds {h i t} {
    putdcc $i "Command bindings (mc):"
    set match [lindex [split $t] 0]
    set all [string match -nocase "all" [lindex [split $t] 1]]
    if {[string match -nocase "all" $match]} {
        set match ""
        set all 1
    }
    set binds [list]
    set btl [string length "TYPE"]
    set bfl [string length "FLGS"]
    set bml [string length "COMMAND"]
    set bhl [string length "HITS"]
    foreach bind $::mcbinds {
        foreach {bt bf bm bh bc} $bind {
            # check if type, command or binding field match a given pattern
            if {($match == "") ||
                ([string match -nocase $match $bt]) ||
                ([string match -nocase $match $bm]) ||
                ([string match -nocase $match $bc])} {
                # check if we should also show internal binds
                if {($all) || (![string match -nocase {\**} $bc])} {
                    lappend binds [list $bt $bf $bm $bh $bc]
                    if {[set bl [string length $bt]] > $btl} { set btl $bl }
                    if {[set bl [string length $bf]] > $bfl} { set bfl $bl }
                    if {[set bl [string length $bm]] > $bml} { set bml $bl }
                    if {[set bl [string length $bh]] > $bhl} { set bhl $bl }
                }
            }
        }
    }
    putdcc $i [format "  %-${btl}s %-${bfl}s %-${bml}s %${bhl}s BINDING (TCL)" "TYPE" "FLGS" "COMMAND" "HITS"]
    foreach bind $binds {
        foreach {bt bf bm bh bc} $bind {
            putdcc $i [format "  %-${btl}s %-${bfl}s %-${bml}s %${bhl}s $bc" $bt $bf $bm $bh]
        }
    }
    if {[llength $binds] == 0} {
        if {$match != ""} {
            putdcc $i "No command bindings found that match $match"
        } else {
            putdcc $i "No command bindings found."
        }
    }
}
bind dcc n mcbinds dcc_mcbinds
#######################################################







# Heidel 7/18/05 - nice new partyline esay and emsg, encrypted verion of say and msg
#######################################################
proc dcc_esay {handle idx text} {
    # we set CHANMETA as in chan.h, line 31
    set CHANMETA "#&!+"
    set channel [lindex [split $text] 0]
    if {[string match "\[$CHANMETA\]" [string index $channel 0]]} {
        # user gave a channel
        set msgtext [join [lrange [split $text] 1 end]]
        if {$msgtext != ""} {
            set text "$channel [mcpsencrypt $channel $msgtext]"
        }
        # else text is empty and the msg won't be accepted by the server
        # anyway, so no need to encrypt
    } else {
        # find out user console channel
        set channel [lindex [split [console $idx]] 0]
        if {[string match "\[$CHANMETA\]" [string index $channel 0]] && $text != ""} {
            set text "$channel [mcpsencrypt $channel $text]"
        }
        # else something went wrong and we pass the text on unencrypted,
        # because the say proc probably throws an error anyway.
    }
    if {[info commands {::\*dcc:say}] != [list]} {
        *dcc:say $handle $idx $text
    } else {
        putdcc $idx "Error: Unable to find the eggdrop proc *dcc:say!"
    }
}

proc dcc_emsg {handle idx text} {
    set nick [lindex [split $text] 0]
    set text [join [lrange [split $text] 1 end]]
    if {[info commands {::\*dcc:msg}] != [list]} {
        if {$text != ""} {
            # encrypt the text only if its not empty
            set text [mcpsencrypt $nick $text]
        }
        *dcc:msg $handle $idx "$nick $text"
    } else {
        putdcc $idx "Error: Unable to find the eggdrop proc *dcc:msg!"
    }
}

# BINDS - call with esay .... or emsg....
bind dcc o|o esay dcc_esay
bind dcc o|- emsg dcc_emsg
#######################################################











#######################################################
# Announce successful loading of this script in log
set mcinfostring [ getmcinfostring "verbose"]
putlog "McEggdrop TCL Helper Functions v$mceggdropversion loaded ($mcinfostring)."
#######################################################
