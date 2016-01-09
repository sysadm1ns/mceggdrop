#-+----------------------------------------------------------------
# mckey v1.1 - 08/27/06
# Keymanager for mceggdrop by SlaSk and heidel.
#
# NOTE: 99.999% of people should NOT install this - you do NOT NEED IT!!!
#       It is a purely optional thing for those people who want to do some
#       unusual stuff with botnets.
#
#       If you experience any bugs or have any questions, please help by
#       sharing e.g. in #mircryption @ EFnet!
#       
# This script lets you avoid storing the channel/nick key in the config file
# of each bot in your botnet.
#
# A designated "master" bot keeps the key and the remaining bots query the
# master for the key. These bots keep the key in memory at all times, this
# makes it harder (but not impossible) to steal the key from a bot.
#
# Just remember - this means that the bots are sending the key to each other
# in plaintext over the network - so you better be sure these bots are not
# communicating over a snoopable network.
#
# If you don't want to take any chances there, you can use the
# transmission_key setting, all key exchanges will then become encrypted.
# This requires each bot to use the same transmission key though.
#
# This script should be included (source'd) AFTER the McEggdropTcl script!
#
# Requirements:
#
#   eggdrop version (tested): 1.6.[17-18]
#                   (probably): unknown
#   TCL version (tested): 8.4
#               (probably): 8.2+
#
#   If you test this on earlier versions of eggdrop or TCL please inform
#   us wether or not it is fully working.
#
# Partyline commands (for owners only):
#
#   .mckey
#     Show all designated master bots for channels and nicks on that bot
#
#   .chanset #channel blowkey secretkey
#     This will set the blowkey for #channel to "secretkey".
#
#     BEWARE! Eggdrop logs all commands by default to the specified logfile,
#             so unless this is disabled, your secret key will become logged
#             into the master bot's logfile!
#             So make sure your logfiles as well as the channel file are
#             ONLY accessible by your user (file permissions)!
#
#   .chanset #channel blowkeymaster masterbotforchankey
#     Sets the "master bot" for this channel to "masterbotforchankey".
#     Whenever the bot loads or rehashes it will query that master bot for
#     the key for #channel.
#     You also have to add the actual bot keeping the key to itself as master
#     bot, so it will try and push the key to other bots.
#
#   .mckeypush [#channel|nick]
#     Push key for that channel/nick to all linked bots. you should not
#     need this command, but i've added it just in case.
#
# Example:
#
#   Presume you have 3 bots A, B and C all sitting in channel #test1 and
#   #test2. You decide to let bot A keep the channel key for #test1 and
#   bot B the channel key for #test2. Bot C will in this scenario not store
#   any key permanently.
#
#   First, lets set up the blowkey for #test1:
#     On bot A you would do:
#       .chanset #test1 blowkey thisismysecretkey
#       .chanset #test1 blowkeymaster A
#     On bots B and C you would do:
#       .chanset #test1 blowkeymaster A
#
#   Now to set up the blowkey for #test2:
#     On bot B you would do:
#       .chanset #test2 blowkey thisisanothersecretkey
#       .chanset #test2 blowkeymaster B
#     On bots A and C you would do:
#       .chanset #test2 blowkeymaster B
#
#   What will happen: Bot A has the key for #test1, bots B and C will know
#   that and ask bot A for the key when they join the botnet or after they
#   experience a rehash.
#   Whenever you decide to change the key on bot A, the bot will broadcast
#   the new key over the botnet to all the other bots, and since bot B and C
#   consider A the "master bot", they would accept this new key.
#
#   The scenario for #test2 is very similar, only in this case bot B will
#   be the master and accept key requests or push the key out.
#
# And if you really want to know what is happening internally, read up on the
# debug setting below!
#
# Info for TCL scripters:
#   mckey can recognize blowkey/blowkeymaster changes through the following
#   tcl commands:
#     - channel [add|set|remove]
#     - loadchannels (internally it uses the "channel add" command)
#     - *dcc:chanset (the internal proc bound to .chanset)
#
# License:
#   This addon is released under the zlib license.
#     ( http://www.gzip.org/zlib/zlib_license.html )
#
# 2004-06-14 slask  - Initial release.
# 2005-07-16 heidel - worked entire script over, fixed numerous bugs
#                   - added the more secure transmission key feature
#                   - added blowkey features with dynamic channel setting
#                     (blowkey & blowkeymaster)
#                   - added hook procs to notice dynamic changes
#                   - added more help text and example
# 2005-07-19 slask  - added logging of request failures
#            heidel - added logging of send failures (dev log only)
# 2005-08-13 heidel - fixed invalid command error with disabled dyn settings
# 2006-08-27 heidel - fixed script to work on eggdrop 1.6.18
#                   - fixed chanset hook bug when using console channel
#
#-+----------------------------------------------------------------

namespace eval mckey {

    # Specify the bot holding the key for each channel/nick.
    #
    # You can also/instead use the dcc partyline command for channels:
    #   .chanset #channel blowkeymaster KeyBot
    # This will store the master bot for the channel dynamically inside
    # the eggdrop.chan file. Chanfile settings overwrite static master
    # entries here.
    #
    # If you want to share this tcl script among various bots, you can
    # also set any of these settings in your config file after the
    # include (source) line, e.g. by using:
    #   set ::mckey::master(#channel) KeyBot

    variable master
    #set master(#channel1) KeyBot1
    #set master(#channel2) KeyBot2
    #set master(#channel3) KeyBot3
    #set master(#channelN) KetBotN


    # Define a key for secure transmission of channel keys between the
    # bot and the channel key master bot. You can disable it by setting "".
    variable transmission_key "D3F4Ul7K3Y"

    # Masterbot ONLY setting! If this setting is enabled, this master
    # bot will only send channel keys to bots with this user flag.
    # This allows to only send keys to a few selected linked bots.
    # It can get quite confusing, so unless absolutely required, leave
    # it disabled!
    #
    # Most users will never need this and if you really do, you should
    # probably also rethink your linking policy. ;-)
    #
    variable slaveflag ""

    # Enable, if you want to use the DYNAMIC CHANNEL SETTINGS "blowkey" and
    # "blowkeymaster". If you disabled both hooks (read below), you can also
    # safely disable this setting.
    #
    # BEWARE: If you disable this, all dynamic blowkey(master) channel
    #         settings will get lost!
    variable use-dynamic-settings 1

    # This setting makes the script hook itself into the "chanset" partyline
    # command, so it notices all changes made through there!
    #
    # If you use dynamic channel settings, you would probably want to ENABLE
    # this.
    variable use-chanset-hook 1

    # Setting to make the script hook itself into the "channel" tcl command,
    # this is useful if any of your scripts change the blowkey/blowkeymaster
    # dynamic channel setting.
    #
    # Enable ONLY if you use the dynamic channel settings AND have 3rd party
    # scripts that update it (e.g. if you want to use .netchanset from
    # netbots to update all blowkeys at once).
    #
    # Upsides:
    #   - makes the addon notice ALL dynamic blowkey(master) changes through
    #     scripts on-the-fly (without rehash!), that means it kind of
    #     gurantees 100% sync'ed settings
    #
    # Downsides to hooking this VERY frequently used command:
    #   - slows down performance (uses more CPU)
    #   - if there is a bug you could lose all your dynamic channel settings
    #     (absolute worst case scenario, should not happen, but i wanted to
    #     mention it for completeness sake)
    #
    # The downsides using this hook often outweigh its usefulness, so unless
    # you have that very special reason to use it, KEEP IT DISABLED!
    variable use-channel-hook 0

    # Enable/Disable debug output, you need to set .console +d to see it!
    # log levels:
    #   0   no logging (disabled)
    #   1   log key exchanges (default)
    #   2   log hook information and all exchange attempts (developers log)
    variable debug 1
    # Most people use "o" (misc info) already on their console, so if you
    # are interested in MCKEY logging but don't want to set .console +d
    # change this setting to any other console flag you like, e.g. "o".
    variable logconsoleflag "d"

    # Comment the next line (insert a # in front of it) so the script
    # will be loaded. This hopefully ensures you read the scripts help and
    # configuration section COMPLETELY.
    putlog "Error: Unable to load mckey. Please read the configuration help completely."; return

    # END OF CONFIGURATION

    #-+----------------------------------------------------------------

    # Call ::mckey::push from any script or .mckeypush from the partyline
    # to send the new key to all bots if you change it while the bots are
    # running.

    proc push {keyname} {
        foreach bot [bots] {
            send $bot $keyname
        }
    }

    proc dcc_mckeypush {handle idx text} {
        if {[llength [split $text]] != 1} {
            putdcc $idx {Usage: mckeypush [#channel|nick]}
        } else {
            variable master
            if {[info exists master($text)]} {
                putdebug "Sending key for $text to all bots."
                push $text
            } else {
                putdcc $idx "No blowkey master set for that nick/channel."
            }
        }
    }
    bind dcc n mckeypush [namespace current]::dcc_mckeypush

    proc dcc_mckey {handle idx text} {
        variable master
        putdcc $idx "Blowkey master bots:"
        set bkl [string length "KEYNAME"]
        set bml [string length "MASTERBOT"]
        foreach {kn mb} [array get master] {
            if {[set bl [string length $kn]] > $bkl} { set bkl $bl }
            if {[set bl [string length $mb]] > $bml} { set bml $bl }
        }
        putdcc $idx [format "  %-${bkl}s %-${bml}s" "KEYNAME" "MASTERBOT"]
        foreach kn [lsort [array names master]] {
            if {[string compare -nocase ${::botnet-nick} $master($kn)] == 0} {
                putdcc $idx [format "  %-${bkl}s %-${bml}s <- it's me!" $kn $master($kn)]
            } else {
                putdcc $idx [format "  %-${bkl}s %-${bml}s" $kn $master($kn)]
            }
        }
        if {[array size master] == 0} {
            putdcc $idx "No blowkey master definitions found."
        }
    }
    bind dcc n mckey [namespace current]::dcc_mckey

    #-+----------------------------------------------------------------

    # Logging proc.

    proc putdebug {text {level 1}} {
        variable debug
        variable logconsoleflag
        if {$debug >= $level} {
            putloglev $logconsoleflag * "MCKEY: $text"
        }
    }

    if {![regexp -- {^[jkmpsbdcow1-8]$} $logconsoleflag]} {
        # set d as default logging console flag, if none or bad flag given
        variable logconsoleflag "d"
    }

    #-+----------------------------------------------------------------

    # We need to notice any blowkey/blowkeymaster changes made by .chanset!
    # To achieve this, we rename the original dcc chanset proc and route the
    # calls through our own proc here (this way we are also safe in case the
    # user renamed his actual partyline "chanset" command to something else!)
    #
    # to have full script support, we also hook the "channel" tcl command, so
    # changes through scripts wont go unnoticed!

    # Due to the sensitive nature of these hooks, we must not allow the script
    # to continue loading if we find any of our hook names already in use!
    # (this can only result from source'ing more than once!)
    #
    # All our hooks rename the original proc by appending "_mckey_hook" to it.
    if {[info commands {::*_mckey_hook}] != [list]} {
        putlog "Warning: Unable to load mckey (already loaded). Use rehash to reload the script."
        return
    }

    # Chanset hook
    if {${use-dynamic-settings} && ${use-chanset-hook} && [info commands {::\*dcc:chanset}] != [list]} {
        # rename the currently defined original proc
        putdebug "Hooking ::*dcc:chanset chain (next in chain: ::*dcc:chanset_mckey_hook)" 2
        rename ::*dcc:chanset ::*dcc:chanset_mckey_hook
        # hook ourself into the calling chain for this proc
        proc ::*dcc:chanset {handle idx text} {
            # chanset is a very complicated command with difficult input
            # parsing, so we avoid doing this and just make a before and after
            # snapshot of the settings that matter and then compare. :-)
            set CHANMETA "#&!+"
            set channel [lindex [split $text] 0]
            if {![string match "\[$CHANMETA\]" [string index $channel 0]]} {
                # user didn't give a channel, find out user console channel
                set channel [lindex [split [console $idx]] 0]
            }
            return [::mckey::wrap_original_proc $channel [list uplevel #0 [list *dcc:chanset_mckey_hook $handle $idx $text]]]
        }
    }

    # Channel hook
    # (Hooking works exactly the same way as for chanset.)
    #
    # In this particular case we also need to set a variable channel_mckey_hook
    # so we always know the correct name of the next proc in the chain, if we
    # hook, it will be "channel_mckey_hook" and if for some reason we cannot
    # hook it will be "channel". It is important because this proc is always
    # referred inside the "wrap_original_proc" code and we must NEVER call the
    # currently hooked procname or we will get into an infinite loop!
    variable channel_mckey_hook "channel"
    if {${use-dynamic-settings} && ${use-channel-hook} && [info commands {::channel}] != [list]} {
        putdebug "Hooking ::channel chain (next in chain: ::channel_mckey_hook)" 2
        rename ::channel ::channel_mckey_hook
        set channel_mckey_hook "channel_mckey_hook"
        proc ::channel {args} {
            # format is: channel [add|set|get|info|remove] #channel [..]
            return [::mckey::wrap_original_proc [lindex $args 1] [concat ::channel_mckey_hook $args]]
        }
    }

    # This proc does the wrapping of the original proc and also makes the
    # before and after settings snapshots and then triggers possible reactions
    # to the changes.
    proc wrap_original_proc {channel script} {
        variable channel_mckey_hook
        if {[validchan $channel]} {
            # save the current blowkey and blowkeymaster setting
            set blowkey [$channel_mckey_hook get $channel blowkey]
            set blowkeymaster [$channel_mckey_hook get $channel blowkeymaster]
        } else {
            # in case this is "channel add" executing, we will have a channel
            # after execution!
            set blowkey ""
            set blowkeymaster ""
        }
        # first we call the original proc, let it do its magic
        putdebug "Routing call to next proc in hook chain" 2
        putdebug "  ($channel) command: $script" 2
        set ret [eval $script]
        if {[validchan $channel]} {
            # now we can do our thing
            set new_blowkey [$channel_mckey_hook get $channel blowkey]
            set new_blowkeymaster [$channel_mckey_hook get $channel blowkeymaster]
            if {[string compare $blowkey $new_blowkey] != 0} {
                # new blowkey, try to push to all bots
                if {$new_blowkey != ""} {
                    # new blowkey
                    set ::mcpskey([string tolower $channel]) $new_blowkey
                } else {
                    # remove blowkey
                    unset -nocomplain -- ::mcpskey([string tolower $channel])
                }
                push $channel
            } elseif {[string compare $blowkeymaster $new_blowkeymaster] != 0} {
                # first lets set the master to the new botname in the tcl array
                variable master
                if {$new_blowkeymaster != ""} {
                    # new masterbot
                    set master([string tolower $channel]) $new_blowkeymaster
                } else {
                    # remove masterbot
                    unset -nocomplain -- master([string tolower $channel])
                }
                if {[string compare -nocase $new_blowkeymaster ${::botnet-nick}] == 0} {
                    # new blowkeymaster and its us! now lets push the key out
                    push $channel
                } else {
                    # new blowkeymaster, lets ask for the key
                    request $channel
                }
            }
        }
        # return the values given by the evaluated original proc
        return $ret
    }

    # Remove all hooks before a rehash, so the script doesn't use our hooks
    # recursively (especially the channel command hook!)
    proc evnt_prerehash {type} {
        foreach command [info commands {::*_mckey_hook}] {
            regexp -- {^(::.+)_mckey_hook$} $command - originalcommand
            putdebug "Unhooking $originalcommand chain" 2
            rename $originalcommand ""
            rename $command $originalcommand
        }
    }
    bind evnt - prerehash [namespace current]::evnt_prerehash
    
    #-+----------------------------------------------------------------

    # blowkey/blowkeymaster dynamic channel setting

    if {${use-dynamic-settings}} {

        proc read_chanset_blowkeymaster {channel} {
            variable master
            if {[validchan $channel]} {
                if {[set key [channel get $channel blowkey]] != ""} {
                    set ::mcpskey([string tolower $channel]) $key
                }
                if {[set bot [channel get $channel blowkeymaster]] != ""} {
                    set master([string tolower $channel]) $bot
                }
            }
        }
        proc read_master_from_channels {} {
            foreach channel [channels] {
                read_chanset_blowkeymaster $channel
            }
        }
        # enable custom blowkey/blowkeymaster settings
        setudef str blowkey
        setudef str blowkeymaster

    }

    # bind events loaded and rehash to read the blowkeymasters into the array
    # and send/request keys.
    proc evnt_loaded_read_chanset_blowkeymaster {type} {
        variable use-dynamic-settings
        if {${use-dynamic-settings}} {
            read_master_from_channels
        }
        request_keys
        send_keys
    }
    bind evnt - loaded [namespace current]::evnt_loaded_read_chanset_blowkeymaster
    bind evnt - rehash [namespace current]::evnt_loaded_read_chanset_blowkeymaster

    #-+----------------------------------------------------------------

    # Intrabot communication.

    proc bot_trigger {from cmd text} {
        global mcpskey
        variable master
        switch -- $cmd {
            MCKEY_QUERY {
                putdebug "$from requested the key for ${text}."
                send $from $text
            }
            MCKEY_RESP {
                set keyname [lindex [split $text] 0]
                if {$keyname != ""} {
                    if {[info exists master($keyname)]} {
                        if {[string compare -nocase $from $master($keyname)] == 0} {
                            set key [lindex [split $text] 1]
                            if {$key != ""} {
                                putdebug "Received the key for $keyname from ${from}."
                                set mcpskey([string tolower $keyname]) [decrypt $key]
                            } else {
                                putdebug "Received empty key for $keyname from ${from}. Removing key."
                                unset -nocomplain -- mcpskey([string tolower $keyname])
                            }
                        } else {
                            putdebug "Got $cmd from unrecognized master $from for $keyname (registered master: $master($keyname))."
                        }
                    } else {
                        putdebug "Got $cmd for unregistered key name ${keyname}." 2
                    }
                } else {
                    putdebug "Got erroneous $cmd (missing key name)."
                }
            }
        }
    }
    bind bot - MCKEY_QUERY [namespace current]::bot_trigger
    bind bot - MCKEY_RESP [namespace current]::bot_trigger

    #-+----------------------------------------------------------------

    # Watch for links with a master bot.

    proc link_trigger {bot via} {
        variable master
        putdebug "Linked with $bot via $via"
        foreach {keyname masterbot} [array get master] {
            if {[string compare -nocase $bot $masterbot] == 0} {
                request $keyname
            }
        }
    }
    bind link - * [namespace current]::link_trigger

    #-+----------------------------------------------------------------

    # Request and send keys.

    proc send {bot keyname} {
        # failures are logged into the developers log only (log level 2)
        global mcpskey
        variable master
        variable slaveflag
        if {[info exists mcpskey($keyname)]} {
            if {[info exists master($keyname)]} {
                if {[string compare -nocase ${::botnet-nick} $master($keyname)] == 0} {
                    if {($slaveflag == "" || [matchattr $bot $slaveflag])} {
                        if {[islinked $bot]} {
                            putdebug "Sending key for $keyname to ${bot}."
                            putbot $bot "MCKEY_RESP $keyname [encrypt $mcpskey($keyname)]"
                        } else {
                            putdebug "Can't send key for $keyname to ${bot}, bot not linked." 2
                        }
                    } else {
                        putdebug "Can't send key for $keyname to ${bot}, unrecognized slave." 2
                    }
                } else {
                    putdebug "Can't send key for $keyname to ${bot}, I'm not the master bot (current master: $master($keyname))." 2
                }
            } else {
                putdebug "Can't send key for $keyname to ${bot}, no master bot configured." 2
            }
        } else {
            putdebug "Can't send key for $keyname to ${bot}, no key configured." 2
        }
    }

    proc send_keys {} {
        variable master
        foreach keyname [array names master] {
            foreach bot [bots] {
                send $bot $keyname
            }
        }
    }

    proc request {keyname} {
        # failures are partly logged into the developers log (log level 2)
        variable master
        if {[info exists master($keyname)]} {
            set masterbot $master($keyname)
            if {[string compare -nocase ${::botnet-nick} $masterbot] != 0} {
                if {[islinked $masterbot]} {
                    putdebug "Requesting key for $keyname from ${masterbot}."
                    putbot $masterbot "MCKEY_QUERY $keyname"
                } else {
                    putdebug "Can't request key for ${keyname}, not linked to ${masterbot}."
                }
            } else {
                putdebug "Ignoring my own key request for ${keyname}, I'm the master bot." 2
            }
        } else {
            putdebug "Can't request key for ${keyname}, no master bot configured."
        }
    }

    proc request_keys {} {
        variable master
        foreach {keyname masterbot} [array get master] {
            request $keyname
        }
    }

    # Functions to encrypt/decrypt the transmitted blowkeys with the
    # transmission_key

    proc encrypt {text} {
        variable transmission_key
        if {$transmission_key != ""} {
            set text [::encrypt $transmission_key $text]
        }
        return $text
    }

    proc decrypt {text} {
        variable transmission_key
        if {$transmission_key != ""} {
            set text [::decrypt $transmission_key $text]
        }
        return $text
    }

    #-+----------------------------------------------------------------

    variable version "1.1"

    putlog "mckey v$version loaded (running on eggdrop ${::version}, TCL [info patchlevel])"
}

#-+----------------------------------------------------------------
