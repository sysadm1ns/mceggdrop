# ---------------------------------------------------------------------------
# PlainTextBlock.tcl
# ---------------------------------------------------------------------------
# this script is used to block a bot from responding to plaintext commands
#  it can be used to block plaintext notices, pms(msg), channel text (pub), dcc, etc
# it is mean to be used with mircryption, so that a bot only responds to encryped commands.
# in the near future, this code may be merged into tcleggdrop_mcpsfuncs.tcl
# -mouser
#
# v 1.00.01 - 02/12/05 - first beta
# v 1.00.02 - 02/14/05 - now supports using wildcard ! or * for blocking all plaintext
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# INSTALLATION:
# 1a) Put this script at the bottom of all your other scripts that you want
#     it to be able to block in the .conf file of the eggdrop.
# 1b) It has to be below tcleggdrop_mcpsfuncs (put tcleggdrop_mcpsfuncs at top)
# 1c) You can place other scripts below PlaintextBlock.tcl to prevent their
#     plaintext from being blocked.
# 2)  Add lines to PlaintextBlock_sitesettings.ini to specify which commands
#     to block plaintext access to.
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# TODO
#  we currently not blocking dcc/chat binds - not sure if we should, count be easy
#  need to support better wildcard patterns on blocking
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
putlog "PlaintextBlock Script 1.00.02 loaded and blocking plaintext commands."
# ---------------------------------------------------------------------------






#  --------------------------------------------------------------------------
proc mcreplacebind {tablecommand} {
  # from mceggdrop
  global mcbinds

  # debugging
  # putlog "DEBUG trying to replace handler for $tablecommand"
  set bindfilter "*"
  set bindindex 0

  # walk through all binds and look for matches
  set triggercount 0
  foreach abind [binds $bindfilter] { 
    # grab the the elements from current bind table entry
    foreach {table flags mask hits callback} $abind {
      # putlog "DEBUG checking against $table and $mask"
      set replaceflag 0

      # first check the types we handle
      if { $table == "pub" } { set replaceflag 1 }
      if { $table == "pubm" } { set replaceflag 1 }
      if { $table == "msg" } { set replaceflag 1 }
      if { $table == "msgm" } { set replaceflag 1 }
      if { $table == "notc" } { set replaceflag 1 }
#      if { $table == "topc" } { set replaceflag 1 }
#      if { $table == "dcc" } { set replaceflag 1 }
#      if { $table == "chat" } { set replaceflag 1 }

      # disable catching +OK and mcps
      if { $mask == "+OK" } { set replaceflag 0 }
      if { $mask == "mcps" } { set replaceflag 0 }

      # disable already replaced
      if {$callback == "mcpub_blocker"} { set replaceflag 0 }
      if {$callback == "mcdcc_blocker"} { set replaceflag 0 }
      if {$callback == "mcmsg_blocker"} { set replaceflag 0 }
      if {$callback == "mcnotc_blocker"} { set replaceflag 0 }
      if {$callback == "mctopc_blocker"} { set replaceflag 0 }
      if {$callback == "mcctcp_blocker"} { set replaceflag 0 }
      if {$callback == "mcchat_blocker"} { set replaceflag 0 }

      # if its a matching type, check command string
      #ATTN maybe the best solution is a regex check on the block string
      if { $replaceflag == 1 } {
        # ATTN: a smarter mask check which avoids channel name part would be better
        if {$mask == $tablecommand} { set replaceflag 2 }
        if { [string first $tablecommand $mask] != -1 } { set replaceflag 2 }
        if { $tablecommand == "*" } { set replaceflag 2 }
        }

      if { $replaceflag == 2 } {
        # putlog "DEBUG matched, now trying to add overwrite for $tablecommand -> $table $mask $callback"
        # add a 5 tuple containing [tablecommand flags mask proccallback]
        #ATTN: should 0 be $hits ??
        set mcbindentry "$table $flags \"$mask\" 0 $callback"
        lappend mcbinds "$mcbindentry"

        if { $tablecommand == "*" } {
           # in this case, if we want the plaintext to not be able to trigger, then we need to actually
           # modify the existing bind table entry, or bind our own new command that masks this one.
           # the only tricky part is the types pubm and msgm which include channel name in mask
           }

        # what might be nice now is if we REMOVED this entry from the table, so that it cant be caught in plaintext
		# ATTN: EXPERIMENTAL

        #putlog "DEBUG unbinding $table $mask $callback"
        unbind $table $flags $mask $callback 

        # should we try to rebind to our warnings?
        if {$table == "pub"} { set callback mcpub_blocker }
        if {$table == "pubm"} { set callback mcpub_blocker }
        if {$table == "msg"} { set callback mcmsg_blocker }
        if {$table == "msgm"} { set callback mcmsg_blocker }
        if {$table == "notc"} { set callback mcnotc_blocker }
        bind $table $flags $mask $callback

#        if {$table == "topc"} { set callback mctopc_blocker }
#        if {$table == "dcc"} { set callback mcdcc_blocker }
#        if {$table == "ctcp"} { set callback mcctcp_blocker }
#        if {$table == "chat"} { set callback mcchat_blocker }
#        set abind [lreplace $abind 0 4 $table $flags $mask $hits $callback]
#		set binds [lreplace $binds $bindindex $bindindex $abind]

        }
      }
    # increment bind index
    set bindindex [expr $bindindex + 1 ]
    }
  }

# --------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Helper function to set up binds to block all use of the command from msg, pub, etc
proc mcblockall {comstring} {
  #add replacement entries so we can route to ma
  # putlog "DEBUG: setting up plaintext block for '$comstring'"
  mcreplacebind $comstring

  if {$comstring == "*"} { 
    putlog "PlaintextBlock Script - Warning: configured to block *ALL* plaintext commands."
    return
    }

  #now take them over
  bind pub - "$comstring" mcpub_blocker
  bind dcc - "$comstring" mcdcc_blocker
  bind msg - "$comstring" mcmsg_blocker
  bind notc - "$comstring" mcnotc_blocker
# ATTN: these may not be useful, and ctcp triggers on actions for some reasom
#  bind topc - "$comstring" mctopc_blocker
#  bind ctcp - "$comstring" mcctcp_blocker
#  bind chat - "$comstring" mcchat_blocker
}
# ---------------------------------------------------------------------------









# ---------------------------------------------------------------------------
# OKAY, now load the user's block settings - we keep these in a separate
#  file so that this script can be updated without effecting user's
#  specific settings
source scripts/PlaintextBlock_sitesettings.ini
# ---------------------------------------------------------------------------

























# ---------------------------------------------------------------------------
proc mcpub_blocker {nick uhost hand chan arg} {
  global mcblocklog
  global mcblockinform
  if {$mcblocklog == "verbose"} { putlog "PlainTextBock.tcl blocked: pub '$nick|$uhost|$hand|$chan|$arg'." } elseif {
    $mcblocklog != "silent"} { putlog "PlainTextBock.tcl blocked: pub." }
  if {$mcblockinform != ""} {putserv "PRIVMSG $nick :$mcblockinform"}
}

proc mcmsg_blocker {nick uhost hand arg} {
  global mcblocklog
  global mcblockinform
  if {$mcblocklog == "verbose"} { putlog "PlainTextBock.tcl blocked: msg '$nick|$uhost|$hand|$arg'." } elseif {
    $mcblocklog != "silent"} { putlog "PlainTextBock.tcl blocked: msg." }
  if {$mcblockinform != ""} {putserv "PRIVMSG $nick :$mcblockinform"}
}

proc mcdcc_blocker {hand idx arg} {
  global mcblocklog
  global mcblockinform
  if {$mcblocklog == "verbose"} { putlog "PlainTextBock.tcl blocked: dcc '$hand|$idx|$arg'." } elseif {
    $mcblocklog != "silent"} { putlog "PlainTextBock.tcl blocked: dcc." }
}

proc mcnotc_blocker {n uh h t {c ""} } {
  global mcblocklog
  global mcblockinform
  if {$mcblocklog == "verbose"} { putlog "PlainTextBock.tcl blocked: notc '$n|$uh|$h|$t|$c'." } elseif {
    $mcblocklog != "silent"} { putlog "PlainTextBock.tcl blocked: notc." }
  if {$mcblockinform != ""} {putserv "PRIVMSG $n :$mcblockinform"}
}

proc mctopc_blocker {n uh h c t} {
  global mcblocklog
  global mcblockinform
  if {$mcblocklog == "verbose"} { putlog "PlainTextBock.tcl blocked: topc '$n|$uh|$h|$c|$t'." } elseif {
    $mcblocklog != "silent"} { putlog "PlainTextBock.tcl blocked: topc." }
  #if {$mcblockinform != ""} {putserv "PRIVMSG $n :$mcblockinform"}
}

proc mcctcp_blocker {n uh h c k t} {
  global mcblocklog
  global mcblockinform
  if {$mcblocklog == "verbose"} { putlog "PlainTextBock.tcl blocked: ctcp '$n|$uh|$h|$c|$k|$t'." } elseif {
    $mcblocklog != "silent"} { putlog "PlainTextBock.tcl blocked: ctcp." }
  if {$mcblockinform != ""} {putserv "PRIVMSG $n :$mcblockinform"}
}

proc mcchat_blocker {h c t} {
  global mcblocklog
  global mcblockinform
  if {$mcblocklog == "verbose"} { putlog "PlainTextBock.tcl blocked: chat '$n|$c|$t'." } elseif {
    $mcblocklog != "silent"} { putlog "PlainTextBock.tcl blocked: chat." }
}
# ---------------------------------------------------------------------------

